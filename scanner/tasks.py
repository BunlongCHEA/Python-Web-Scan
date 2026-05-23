import os
import json
import subprocess

from celery import shared_task
from django.conf import settings

from .models import ScanJob, Vulnerability
from .utils import WAPITI_MODULES


def _safe_str(value, fallback='') -> str:
    """Safely convert any value to string, replacing None with fallback."""
    if value is None:
        return fallback
    return str(value).strip() or fallback

# ── Synchronous runner (used by threading in views.py) ───────────────────
def run_scan_sync(scan_id: str):
    """
    Runs wapiti3 synchronously.
    All cmd parameters read from the ScanJob model — no hardcoded values.
    """
    # from .models import ScanJob, Vulnerability

    job = ScanJob.objects.get(id=scan_id)
    
    # Guard: skip if already manually failed/reset
    if job.status == 'failed':
        return
    
    job.status = 'running'
    job.save()

    report_path = os.path.join(settings.SCAN_REPORTS_DIR, f"{scan_id}.json")
    modules = ','.join(job.modules) if job.modules else 'all'

    # ── Build cmd from model config fields ────────────────────────────
    cmd = ['wapiti', '-u', job.target_url]

    # Modules
    cmd += ['-m', modules]

    # Scope
    cmd += ['--scope', job.scope]

    # Crawl depth
    cmd += ['-d', str(job.scan_depth)]

    # Max links per page
    cmd += ['--max-links-per-page', str(job.max_links)]

    # Attack level
    cmd += ['-l', str(job.level)]

    # Parallel tasks (speeds up crawling significantly)
    cmd += ['--tasks', str(job.tasks)]

    # Max scan time (0 = no limit)
    if job.max_scan_time > 0:
        cmd += ['--max-scan-time', str(job.max_scan_time)]

    # Max attack time per module (0 = no limit)
    if job.max_attack_time > 0:
        cmd += ['--max-attack-time', str(job.max_attack_time)]
        
    # Anti-hang / Anti-SSL-fail flags
    cmd += ['-t', '10']          # 10s per-request timeout — prevents hanging on slow sites
    cmd += ['--verify-ssl', '0'] # skip SSL verification — fixes cert issues (e.g. web.nika2u.com)

    # Output format
    cmd += ['-f', 'json', '-o', report_path]

    # Always flush session so re-runs start fresh
    cmd += ['--flush-session']

    # ──────────────────────────────────────────────────────────────────

    # Timeout = max_scan_time + 60s grace, or 600s fallback
    timeout = (job.max_scan_time + 60) if job.max_scan_time > 0 else 660
    
    # ── Fix Windows cp1252 UnicodeEncodeError in wapiti banner ───────
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    env['PYTHONUTF8']       = '1'   # Python 3.7+ UTF-8 mode

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,                # ← pass the UTF-8 env
            encoding='utf-8',       # ← decode stdout/stderr as UTF-8
            errors='replace', 
        )

        if result.returncode != 0:
            job.status = 'failed'
            job.error_msg = (result.stderr or result.stdout or 'Unknown wapiti error')[:2000]
            job.save()
            return
        
        # Report file may not exist if wapiti found nothing at all
        if not os.path.exists(report_path):
            job.status = 'done'
            job.report_json = {'vulnerabilities': {}, 'anomalies': {}}
            job.save()
            return

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        job.report_json = report_data
        job.status = 'done'
        job.save()

        _save_vulnerabilities(job, report_data)

    except subprocess.TimeoutExpired:
        job.status = 'failed'
        job.error_msg = f'Scan hard-timed out after {timeout}s. Try reducing depth or scan time.'
        job.save()
    except json.JSONDecodeError as exc:
        job.status = 'failed'
        job.error_msg = f'Failed to parse wapiti JSON report: {exc}'
        job.save()
    except Exception as exc:
        job.status = 'failed'
        job.error_msg = str(exc)
        job.save()


# ── Celery task (kept for when Redis is available) ───────────────────────
@shared_task(bind=True)
def run_wapiti_scan(self, scan_id: str):
    run_scan_sync(scan_id)


def _save_vulnerabilities(job, report: dict):
    from .models import Vulnerability

    # ── Vulnerabilities ───────────────────────────────────────────────
    for vuln_name, entries in report.get('vulnerabilities', {}).items():
        if not isinstance(entries, list):
            continue
        severity = _guess_severity(vuln_name)
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            Vulnerability.objects.create(
                scan        = job,
                name        = _safe_str(vuln_name),
                severity    = severity,
                url         = _safe_str(entry.get('path')),
                method      = _safe_str(entry.get('method'), 'GET'),
                parameter   = _safe_str(entry.get('parameter')),   # ← None → ''
                description = _safe_str(entry.get('info')),
                wstg        = _safe_str(
                    entry.get('wstg', [None])[0]
                    if isinstance(entry.get('wstg'), list) and entry.get('wstg')
                    else entry.get('wstg')
                ),
            )

    # ── Anomalies ─────────────────────────────────────────────────────
    for anom_name, entries in report.get('anomalies', {}).items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            Vulnerability.objects.create(
                scan        = job,
                name        = f"[Anomaly] {_safe_str(anom_name)}",
                severity    = 'low',
                url         = _safe_str(entry.get('path')),
                method      = _safe_str(entry.get('method'), 'GET'),
                parameter   = _safe_str(entry.get('parameter')),   # ← None → ''
                description = _safe_str(entry.get('info')),
                wstg        = '',
            )


def _guess_severity(vuln_name: str) -> str:
    name_lower = vuln_name.lower()
    for mod_key, meta in WAPITI_MODULES.items():
        if mod_key in name_lower:
            return meta['severity']
    return 'medium'