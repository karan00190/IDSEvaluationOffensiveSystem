# scanner/consumers.py — FINAL VERSION
# Handles both AgentConsumer (agent ↔ server) and DashboardConsumer (browser ↔ server)

import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db                 import database_sync_to_async
from django.utils                import timezone

logger = logging.getLogger(__name__)


class AgentConsumer(AsyncWebsocketConsumer):
    """
    WebSocket connection for MIAT agents.
    URL: ws(s)://server/ws/agent/<agent_id>/?token=<auth_token>
    """

    async def connect(self):
        self.agent_id   = self.scope['url_route']['kwargs']['agent_id']
        self.group_name = f"agent_{self.agent_id}"

        # Extract token from query string: ?token=abc123
        query_string = self.scope.get('query_string', b'').decode()
        token        = self._extract_token(query_string)

        if not token:
            await self.close(code=4001)
            return

        self.agent = await self._get_agent(token)
        if not self.agent:
            logger.warning(f'WS rejected: bad token for {self.agent_id}')
            await self.close(code=4001)
            return

        # Add to group so server can push commands to this agent
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        await self._mark_seen()

        logger.info(f'Agent {self.agent_id} WebSocket connected')

        await self.send(text_data=json.dumps({
            'type':        'connected',
            'message':     f'Agent {self.agent_id} ready.',
            'server_time': timezone.now().isoformat(),
        }))

    async def disconnect(self, close_code):
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(
                self.group_name, self.channel_name
            )
        logger.info(f'Agent {getattr(self, "agent_id", "?")} disconnected')

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({'type': 'error', 'message': 'Invalid JSON'}))
            return

        msg_type = data.get('type', '')

        if msg_type == 'heartbeat':
            await self._mark_seen()
            await self.send(text_data=json.dumps({
                'type':        'heartbeat_ack',
                'server_time': timezone.now().isoformat(),
            }))

        elif msg_type == 'scan_result':
            scan_id = data.get('scan_id')
            logger.info(f'Agent {self.agent_id} streamed result for scan #{scan_id}')
            await self.send(text_data=json.dumps({
                'type': 'result_ack', 'scan_id': scan_id
            }))

        elif msg_type == 'module_output':
            # Forward live module output to the browser dashboard
            await self.channel_layer.group_send(
                'dashboard',
                {
                    'type':     'dashboard.update',
                    'agent_id': self.agent_id,
                    'module':   data.get('module', 'unknown'),
                    'output':   data.get('output', ''),
                }
            )

        elif msg_type == 'ids_alert':
            logger.warning(f'IDS ALERT from {self.agent_id}: {data.get("message")}')
            await self.send(text_data=json.dumps({'type': 'alert_ack'}))

        elif msg_type == 'scan_submitted':
            # Agent confirmed it submitted a scan — forward to dashboard
            await self.channel_layer.group_send(
                'dashboard',
                {
                    'type':    'dashboard.update',
                    'message': f'Agent {self.agent_id} submitted scan #{data.get("scan_id")} for {data.get("target")}',
                    'level':   'info',
                }
            )

    # ── Server → Agent: push a command ───────────────────────────────────────
    # Called when channel_layer.group_send("agent_<id>", {"type": "agent.command", ...})

    async def agent_command(self, event):
        """Push a command from server to agent instantly."""
        await self.send(text_data=json.dumps({
            'type':    'command',
            'command': event['command'],
            'args':    event.get('args', {}),
        }))
        logger.info(f'Command sent to {self.agent_id}: {event["command"]}')

    # ── DB helpers ────────────────────────────────────────────────────────────

    @database_sync_to_async
    def _get_agent(self, token: str):
        from .models import Agent
        try:
            return Agent.objects.get(auth_token=token, is_active=True)
        except Agent.DoesNotExist:
            return None

    @database_sync_to_async
    def _mark_seen(self):
        if hasattr(self, 'agent') and self.agent:
            self.agent.last_seen_at = timezone.now()
            self.agent.save(update_fields=['last_seen_at'])

    @staticmethod
    def _extract_token(query_string: str) -> str:
        for part in query_string.split('&'):
            if part.startswith('token='):
                return part[6:].strip()
        return ''


class DashboardConsumer(AsyncWebsocketConsumer):
    """
    WebSocket connection for browser dashboards.
    URL: ws(s)://server/ws/dashboard/

    Receives push notifications from:
      - tasks.py (notify_scan_complete → scan.complete event)
      - AgentConsumer (module_output → dashboard.update event)
    """

    GROUP_NAME = 'dashboard'

    async def connect(self):
        await self.channel_layer.group_add(self.GROUP_NAME, self.channel_name)
        await self.accept()
        logger.info('Browser dashboard WebSocket connected')

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.GROUP_NAME, self.channel_name)

    async def receive(self, text_data):
        pass   # browser only receives — never sends to this consumer

    # ── Event handlers — called by channel_layer.group_send ──────────────────
    # Method name = event 'type' with dots replaced by underscores

    async def scan_complete(self, event):
        """
        Called by tasks.py → notify_scan_complete() when nmap finishes.
        Tells the browser to redirect to the report page.
        'type': 'scan.complete' → this method name (dot → underscore).
        """
        await self.send(text_data=json.dumps({
            'type':       'scan_complete',
            'scan_id':    event.get('scan_id'),
            'risk':       event.get('risk'),
            'report_url': event.get('report_url'),
        }))

    async def dashboard_update(self, event):
        """
        Called for general live updates:
          - module output streamed from agent
          - scan started / failed messages
        """
        await self.send(text_data=json.dumps({
            'type':     'live_update',
            'agent_id': event.get('agent_id', ''),
            'module':   event.get('module', ''),
            'output':   event.get('output', ''),
            'message':  event.get('message', ''),
            'level':    event.get('level', 'info'),
        }))