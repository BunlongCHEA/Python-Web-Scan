from django.db import models
import uuid

class ScanJob(models.Model):
    STATUS_CHOICES = [
        ('pending',  'Pending'),
        ('running',  'Running'),
        ('done',     'Done'),
        ('failed',   'Failed'),
    ]

    id          = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_url  = models.URLField(max_length=500)
    status      = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    modules     = models.JSONField(default=list)       # selected wapiti modules
    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)
    report_json = models.JSONField(null=True, blank=True)
    error_msg   = models.TextField(blank=True)

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
    wstg        = models.CharField(max_length=50, blank=True)   # OWASP WSTG reference

    def __str__(self):
        return f"[{self.severity.upper()}] {self.name} @ {self.url}"