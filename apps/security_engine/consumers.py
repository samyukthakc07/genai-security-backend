"""WebSocket consumers for real-time security scan progress.

Clients connect to:
    ws://host:port/ws/scan/<scan_id>/

They receive JSON messages with scan progress, completion, and failure events.

Example client (JavaScript):
    const socket = new WebSocket('ws://localhost:8000/ws/scan/abc-123/');
    socket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log(data.event, data.data);
    };
"""
import json
import logging
from uuid import UUID

from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger('security_engine.consumers')


class ScanProgressConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer that streams scan progress to clients.

    Clients connect to: ws://<host>/ws/scan/<scan_id>/
    The Celery task sends progress updates via the channel layer,
    and this consumer forwards them to the connected WebSocket client.
    """

    async def connect(self):
        """Accept connection and join the scan progress group."""
        self.scan_id = self.scope['url_route']['kwargs'].get('scan_id')
        if not self.scan_id:
            await self.close(code=4000)
            return

        # Validate UUID format
        try:
            UUID(self.scan_id)
        except (ValueError, AttributeError):
            await self.close(code=4000)
            return

        self.group_name = f'scan_{self.scan_id}'

        # Join the scan progress group
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        logger.info('WebSocket connected: scan_id=%s', self.scan_id)

        # Send initial connection confirmation
        await self.send(text_data=json.dumps({
            'event': 'scan.connected',
            'data': {
                'scan_id': self.scan_id,
                'message': 'Connected to scan progress stream.',
            },
        }))

    async def disconnect(self, close_code):
        """Leave the scan progress group on disconnect."""
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
            logger.info(
                'WebSocket disconnected: scan_id=%s, code=%s',
                getattr(self, 'scan_id', 'unknown'),
                close_code,
            )

    async def scan_message(self, event):
        """Receive a scan progress message from the channel layer.

        The Celery task calls:
            channel_layer.group_send('scan_<id>', {
                'type': 'scan_message',
                'event': 'scan.progress',
                'data': { ... },
            })

        This method forwards it to the WebSocket client.
        """
        await self.send(text_data=json.dumps({
            'event': event.get('event', 'scan.progress'),
            'data': event.get('data', {}),
        }))
