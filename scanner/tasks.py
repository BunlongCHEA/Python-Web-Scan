import os
import json
import subprocess
import tempfile

from celery import shared_task
from django.conf import settings

from .models import ScanJob, Vulnerability
from .utils import WAPITI_MODULES


@shared_task(bind=True)
def run_wapiti_scan(self, scan_id: str):
    """Run wapiti3 as subprocess, parse JSON report, save results."""
    from .models import ScanJob  # local import avoids circular

    job = ScanJob.objects.get(id=scan_id)
    job.status = 'running'
    job.save()

    report_path = os.path.join(settings.SCAN_REPORTS_DIR, f"{scan_id}.json")

    # Build wapiti command
    modules = ','.join(job.modules) if job.modules else 'all'
    cmd = [
        'wapiti',
        '-u', job.target_url,
        '-m', modules,
        '-f', 'json',
        '-o', report_path,
        '--flush-session',
        '--max-depth', '3',
        '--max-links-per-page', '50',
        '--max-scan-time', '300',   # 5 min safety cap
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=360,
        )

        if result.returncode != 0:
            job.status = 'failed'
            job.error_msg = result.stderr[:2000]
            job.save()
            return

        # Parse JSON report
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        job.report_json = report_data
        job.status = 'done'
        job.save()

        # Persist individual vulnerabilities
        _save_vulnerabilities(job, report_data)

    except subprocess.TimeoutExpired:
        job.status = 'failed'
        job.error_msg = 'Scan timed out after 6 minutes.'
        job.save()
    except Exception as exc:
        job.status = 'failed'
        job.error_msg = str(exc)
        job.save()


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