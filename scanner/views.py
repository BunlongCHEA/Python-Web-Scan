import csv
import json
import io
import threading

from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_POST

from scanner.tasks import run_wapiti_scan

from .models import ScanJob, Vulnerability
from .utils import WAPITI_MODULES, suggest_modules, severity_badge_color


def index(request):
    recent_scans = ScanJob.objects.all()[:20]
    context = {
        'recent_scans': recent_scans,
        'all_modules': WAPITI_MODULES,
        'suggested_modules': [],
        'scope_choices': ScanJob.SCOPE_CHOICES,
    }
    return render(request, 'scanner/index.html', context)


@require_POST
def start_scan(request):
    target_url = request.POST.get('target_url', '').strip()
    if not target_url:
        return redirect('index')

    def _int(key, default, min_val=0, max_val=9999):
        try:
            return max(min_val, min(max_val, int(request.POST.get(key, default))))
        except (ValueError, TypeError):
            return default

    job = ScanJob.objects.create(
        target_url    = target_url,
        modules       = request.POST.getlist('modules'),
        scan_depth    = _int('scan_depth',    2, 1, 10),
        max_links     = _int('max_links',    20, 1, 500),
        max_scan_time = _int('max_scan_time', 180, 0, 86400),
        max_attack_time = _int('max_attack_time', 60, 0, 3600),
        tasks         = _int('tasks',         8, 1, 32),
        scope         = request.POST.get('scope', 'folder'),
        level         = _int('level',          1, 1, 2),
    )

    run_wapiti_scan.delay(str(job.id))
    return redirect('scan_running', scan_id=job.id)


def scan_running(request, scan_id):
    job = get_object_or_404(ScanJob, id=scan_id)
    return render(request, 'scanner/scan_running.html', {'job': job})


def scan_status_api(request, scan_id):
    job = get_object_or_404(ScanJob, id=scan_id)
    return JsonResponse({'status': job.status, 'scan_id': str(job.id)})


def scan_detail(request, scan_id):
    job = get_object_or_404(ScanJob, id=scan_id)
    vulns = job.vulnerabilities.all().order_by('severity')

    severity_counts = {
        'critical': vulns.filter(severity='critical').count(),
        'high':     vulns.filter(severity='high').count(),
        'medium':   vulns.filter(severity='medium').count(),
        'low':      vulns.filter(severity='low').count(),
        'info':     vulns.filter(severity='info').count(),
    }

    for v in vulns:
        v.badge_color = severity_badge_color(v.severity)

    return render(request, 'scanner/scan_detail.html', {
        'job': job,
        'vulns': vulns,
        'severity_counts': severity_counts,
    })


def suggest_modules_api(request):
    url = request.GET.get('url', '')
    suggested = suggest_modules(url)
    return JsonResponse({'suggested': suggested})


# ── Cancel a single job ───────────────────────────────────────────────────

@require_POST
def cancel_scan(request, scan_id):
    """Mark a single pending/running job as failed immediately."""
    job = get_object_or_404(ScanJob, id=scan_id)
    if job.status in ('pending', 'running'):
        job.status = 'failed'
        job.error_msg = 'Cancelled by user.'
        job.save()
        # Attempt to revoke Celery task (best-effort)
        try:
            from celery import current_app
            current_app.control.revoke(str(job.id), terminate=True)
        except Exception:
            pass
    return JsonResponse({'status': job.status, 'scan_id': str(job.id)})


# ── Clear ALL stale (pending/running) jobs ───────────────────────────────

@require_POST
def clear_stale_scans(request):
    """Reset all pending/running jobs to failed + purge Celery queue."""
    qs = ScanJob.objects.filter(status__in=['pending', 'running'])
    count = qs.count()
    qs.update(status='failed', error_msg='Cleared by user via UI.')

    # Purge Celery queue (best-effort)
    purged = False
    try:
        from celery import current_app
        current_app.control.purge()
        purged = True
    except Exception:
        pass

    return JsonResponse({
        'cleared': count,
        'queue_purged': purged,
        'message': f'{count} stale job(s) cleared. Queue purged: {purged}',
    })


# ── Report Downloads ─────────────────────────────────────────────────────

def download_json(request, scan_id):
    job = get_object_or_404(ScanJob, id=scan_id)
    response = HttpResponse(
        json.dumps(job.report_json or {}, indent=2),
        content_type='application/json',
    )
    response['Content-Disposition'] = f'attachment; filename="scan_{scan_id}.json"'
    return response


def download_txt(request, scan_id):
    job = get_object_or_404(ScanJob, id=scan_id)
    vulns = job.vulnerabilities.all()
    lines = [
        "Wapiti Scan Report",
        f"Target : {job.target_url}",
        f"Status : {job.status}",
        f"Date   : {job.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60, "",
    ]
    for v in vulns:
        lines += [
            f"[{v.severity.upper()}] {v.name}",
            f"  URL       : {v.url}",
            f"  Method    : {v.method}",
            f"  Parameter : {v.parameter}",
            f"  Info      : {v.description}",
            f"  WSTG      : {v.wstg}",
            "",
        ]
    response = HttpResponse('\n'.join(lines), content_type='text/plain')
    response['Content-Disposition'] = f'attachment; filename="scan_{scan_id}.txt"'
    return response


def download_csv(request, scan_id):
    job = get_object_or_404(ScanJob, id=scan_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Severity', 'Name', 'URL', 'Method', 'Parameter', 'Description', 'WSTG'])
    for v in job.vulnerabilities.all():
        writer.writerow([v.severity, v.name, v.url, v.method,
                         v.parameter, v.description, v.wstg])
    response = HttpResponse(output.getvalue(), content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="scan_{scan_id}.csv"'
    return response