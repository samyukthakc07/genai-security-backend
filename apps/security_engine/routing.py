"""WebSocket URL routing for the Security Engine app.

Routes are included from config/routing.py and config/asgi.py.
"""
from django.urls import re_path

from apps.security_engine.consumers import ScanProgressConsumer

websocket_urlpatterns = [
    # Scan progress updates
    #   ws://host:port/ws/scan/<scan_id>/
    re_path(
        r'^ws/scan/(?P<scan_id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/$',
        ScanProgressConsumer.as_asgi(),
        name='scan_progress',
    ),
]
