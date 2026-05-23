from django.db import models
import uuid


class ScanJob(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('done',    'Done'),
        ('failed',  'Failed'),
    ]

    SCOPE_CHOICES = [
        ('url',       'URL only'),
        ('page',      'Page'),
        ('folder',    'Folder (recommended)'),
        ('subdomain', 'Subdomain'),
        ('domain',    'Full Domain (slow)'),
    ]

    # ── Core ──────────────────────────────────────────────────────────
    id         = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_url = models.URLField(max_length=500)
    status     = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    modules    = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    report_json = models.JSONField(null=True, blank=True)
    error_msg  = models.TextField(blank=True)

    # ── Scan config (user-configurable) ───────────────────────────────
    scan_depth       = models.PositiveSmallIntegerField(
        default=2,
        help_text="Crawl depth (-d). Lower = faster. Recommended: 1-3."
    )
    max_links        = models.PositiveSmallIntegerField(
        default=20,
        help_text="Max links crawled per page. Lower = faster."
    )
    max_scan_time    = models.PositiveIntegerField(
        default=180,
        help_text="Max total scan time in seconds. 0 = unlimited."
    )
    max_attack_time  = models.PositiveIntegerField(
        default=60,
        help_text="Max attack time per module in seconds. 0 = unlimited."
    )
    tasks            = models.PositiveSmallIntegerField(
        default=8,
        help_text="Parallel async tasks wapiti uses internally (--tasks)."
    )
    scope            = models.CharField(
        max_length=20, choices=SCOPE_CHOICES, default='folder',
        help_text="Crawl scope. 'folder' is the best balance of speed vs coverage."
    )
    level            = models.PositiveSmallIntegerField(
        default=1,
        help_text="Attack level (-l). 1=normal, 2=aggressive. Higher = slower."
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.target_url} [{self.status}]"


class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high',     'High'),
        ('medium',   'Medium'),
        ('low',      'Low'),
        ('info',     'Info'),
    ]

    scan        = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name='vulnerabilities')
    name        = models.CharField(max_length=200)
    severity    = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='info')
    url         = models.URLField(max_length=1000)
    method      = models.CharField(max_length=10, default='GET')
    parameter   = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)
    wstg        = models.CharField(max_length=50, blank=True)

    def __str__(self):
        return f"[{self.severity.upper()}] {self.name} @ {self.url}"