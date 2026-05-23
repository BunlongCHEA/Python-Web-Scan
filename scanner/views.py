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
    }
    return render(request, 'scanner/index.html', context)


@require_POST
def start_scan(request):
    target_url = request.POST.get('target_url', '').strip()
    if not target_url:
        return redirect('index')

    selected_modules = request.POST.getlist('modules')

    job = ScanJob.objects.create(
        target_url=target_url,
        modules=selected_modules,
    )
    
    # Use Celery for real async processing (requires Redis broker)
    run_wapiti_scan.delay(str(job.id))

    # Use threading for no broker connection needed
    # from .tasks import run_scan_sync
    # thread = threading.Thread(
    #     target=run_scan_sync,
    #     args=(str(job.id),),
    #     daemon=True,
    # )
    # thread.start()

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