from django.urls import path
from . import views

urlpatterns = [
    path('',                                    views.index,               name='index'),
    path('scan/start/',                         views.start_scan,          name='start_scan'),
    path('scan/<uuid:scan_id>/running/',        views.scan_running,        name='scan_running'),
    path('scan/<uuid:scan_id>/status/',         views.scan_status_api,     name='scan_status_api'),
    path('scan/<uuid:scan_id>/',                views.scan_detail,         name='scan_detail'),
    path('scan/<uuid:scan_id>/download/json/',  views.download_json,       name='download_json'),
    path('scan/<uuid:scan_id>/download/txt/',   views.download_txt,        name='download_txt'),
    path('scan/<uuid:scan_id>/download/csv/',   views.download_csv,        name='download_csv'),
    path('api/suggest-modules/',                views.suggest_modules_api, name='suggest_modules_api'),
    path('api/clear-stale/',                    views.clear_stale_scans,   name='clear_stale_scans'),
    path('scan/<uuid:scan_id>/cancel/',         views.cancel_scan,         name='cancel_scan'),
]