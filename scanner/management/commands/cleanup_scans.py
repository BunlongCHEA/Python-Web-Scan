"""
python manage.py cleanup_scans

Resets all stuck pending/running jobs to 'failed'.
Also purges the Celery queue so no ghost tasks remain.
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from scanner.models import ScanJob


class Command(BaseCommand):
    help = 'Reset all stuck pending/running scan jobs to failed'

    def add_arguments(self, parser):
        parser.add_argument(
            '--older-than',
            type=int,
            default=0,
            help='Only reset jobs older than N minutes (0 = all stuck jobs)',
        )
        parser.add_argument(
            '--purge-queue',
            action='store_true',
            help='Also purge the Celery Redis queue',
        )

    def handle(self, *args, **options):
        qs = ScanJob.objects.filter(status__in=['pending', 'running'])

        minutes = options['older_than']
        if minutes > 0:
            cutoff = timezone.now() - timezone.timedelta(minutes=minutes)
            qs = qs.filter(created_at__lte=cutoff)
            self.stdout.write(f'Filtering jobs older than {minutes} minutes…')

        count = qs.count()
        if count == 0:
            self.stdout.write(self.style.SUCCESS('No stuck jobs found.'))
        else:
            qs.update(
                status='failed',
                error_msg='Manually reset by cleanup_scans command.',
            )
            self.stdout.write(
                self.style.SUCCESS(f'✅ Reset {count} stuck job(s) to failed.')
            )

        # Purge Celery queue
        if options['purge_queue']:
            try:
                from django.conf import settings
                from celery import current_app
                current_app.control.purge()
                self.stdout.write(self.style.SUCCESS('✅ Celery queue purged.'))
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'⚠️  Could not purge queue: {e}'))