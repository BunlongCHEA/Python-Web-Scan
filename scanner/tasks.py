import os
import json
import subprocess

from celery import shared_task
from django.conf import settings

from .models import ScanJob, Vulnerability
from .utils import WAPITI_MODULES


# ── Synchronous runner (used by threading in views.py) ───────────────────
def run_scan_sync(scan_id: str):
    """
    Runs wapiti3 synchronously.
    All cmd parameters read from the ScanJob model — no hardcoded values.
    """
    # from .models import ScanJob, Vulnerability

    job = ScanJob.objects.get(id=scan_id)
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

    # Output format
    cmd += ['-f', 'json', '-o', report_path]

    # Always flush session so re-runs start fresh
    cmd += ['--flush-session']

    # ──────────────────────────────────────────────────────────────────

    # Timeout = max_scan_time + 60s grace, or 600s fallback
    timeout = (job.max_scan_time + 60) if job.max_scan_time > 0 else 600

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            job.status = 'failed'
            job.error_msg = result.stderr[:2000]
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
        job.error_msg = f'Scan timed out after {timeout}s.'
        job.save()
    except Exception as exc:
        job.status = 'failed'
        job.error_msg = str(exc)
        job.save()


# ── Celery task (kept for when Redis is available) ───────────────────────
@shared_task(bind=True)
def run_wapiti_scan(self, scan_id: str):
    run_scan_sync(scan_id)


def _save_vulnerabilities(job: ScanJob, report: dict):
    """Parse wapiti JSON report structure and create Vulnerability rows."""
    vulnerabilities = report.get('vulnerabilities', {})
    for vuln_name, entries in vulnerabilities.items():
        severity = _guess_severity(vuln_name)
        for entry in entries:
            Vulnerability.objects.create(
                scan=job,
                name=vuln_name,
                severity=severity,
                url=entry.get('path', ''),
                method=entry.get('method', 'GET'),
                parameter=entry.get('parameter', ''),
                description=entry.get('info', ''),
                wstg=entry.get('wstg', [''])[0] if entry.get('wstg') else '',
            )

    # Anomalies section
    anomalies = report.get('anomalies', {})
    for anom_name, entries in anomalies.items():
        for entry in entries:
            Vulnerability.objects.create(
                scan=job,
                name=f"[Anomaly] {anom_name}",
                severity='low',
                url=entry.get('path', ''),
                method=entry.get('method', 'GET'),
                parameter=entry.get('parameter', ''),
                description=entry.get('info', ''),
            )


def _guess_severity(vuln_name: str) -> str:
    name_lower = vuln_name.lower()
    for mod_key, meta in WAPITI_MODULES.items():
        if mod_key in name_lower:
            return meta['severity']
    return 'medium'