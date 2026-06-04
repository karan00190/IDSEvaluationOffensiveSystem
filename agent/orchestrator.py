#!/usr/bin/env python3
# agent/orchestrator.py
# =============================================================================
#  MIAT — Async Orchestrator
#
#  This is the ONLY entry point for the agent. It does exactly three things:
#    1. Maintains authentication (JWT refresh, heartbeat)
#    2. Maintains the WebSocket connection
#    3. Dispatches incoming commands to the correct plugin
#
#  It knows NOTHING about nmap, DGA, or exfiltration.
#  All attack logic lives in plugins/. The orchestrator just routes.
#
#  Architecture:
#    asyncio event loop runs everything
#    ┌─────────────────────────────────────────────┐
#    │  Orchestrator (asyncio)                      │
#    │  ├── heartbeat_loop()    every 30s           │
#    │  ├── TelemetryEngine()   drains result queue │
#    │  └── dispatch_command()  routes → plugin     │
#    │                                              │
#    │  WebSocketThread (daemon thread)             │
#    │  └── on_message → calls dispatch_command()   │
#    └─────────────────────────────────────────────┘
# =============================================================================

import asyncio
import json
import logging
import signal
import sys
import argparse
from pathlib import Path

from config        import AgentConfig
from transport     import SecureTransport, WebSocketThread, build_ssl_context
from plugin_loader import PluginLoader
from telemetry     import TelemetryEngine

logging.basicConfig(
    level   = logging.INFO,
    format  = '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt = '%H:%M:%S',
)
logger = logging.getLogger('MIAT.Orchestrator')

HEARTBEAT_INTERVAL = 30   # seconds


class Orchestrator:
    """
    Async orchestrator — the brain of the agent.
    Knows about transport and plugins, nothing else.
    """

    def __init__(self, config: AgentConfig):
        self.config    = config
        self._running  = False

        # Build SSL context once — shared by HTTP and WebSocket
        self.ssl_ctx = build_ssl_context(
            config.ca_cert, config.agent_cert, config.agent_key
        )

        # Secure HTTP transport
        self.transport = SecureTransport(
            server_url = config.server_url,
            config     = config.as_dict(),
            ssl_ctx    = self.ssl_ctx,
        )

        # Telemetry engine — owns the result queue
        self.telemetry = TelemetryEngine(
            transport  = self.transport,
            ws_thread  = None,   # set after WS connects
        )

        # Plugin loader — discovers plugins/ directory
        self.plugins = PluginLoader(telemetry_queue=self.telemetry.queue)

        # WebSocket thread (daemon) — set in start()
        self.ws_thread = None

        # Track running plugin tasks
        self._active_tasks: dict[str, asyncio.Task] = {}

    # =========================================================================
    # STARTUP
    # =========================================================================

    async def start(self) -> None:
        """
        Full startup sequence:
          1. Authenticate (get JWT)
          2. Load plugins
          3. Start WebSocket thread
          4. Start telemetry engine
          5. Register capabilities with server
          6. Run heartbeat loop
        """
        self._running = True
        logger.info("=" * 56)
        logger.info("  MIAT Orchestrator starting")
        logger.info(f"  Agent ID : {self.config.agent_id}")
        logger.info(f"  Server   : {self.config.server_url}")
        logger.info(f"  Security : mTLS + JWT + HMAC")
        logger.info("=" * 56)

        # Step 1: Authenticate
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.transport.authenticate)

        # Step 2: Load plugins
        count = self.plugins.load_all()
        if count == 0:
            logger.warning("No plugins loaded — agent will accept no attack commands")

        # Step 3: Start WebSocket thread
        self.ws_thread = WebSocketThread(
            server_url = self.config.server_url,
            agent_id   = self.config.agent_id,
            auth_token = self.config.auth_token,
            ssl_ctx    = self.ssl_ctx,
            on_command = self._on_ws_command,
        )
        self.telemetry.ws_thread = self.ws_thread
        self.ws_thread.start()

        # Step 4: Start telemetry engine
        asyncio.create_task(self.telemetry.run(), name='telemetry')

        # Step 5: Register loaded plugins with server
        await self._register_capabilities()

        # Step 6: Heartbeat + main loop
        logger.info("Orchestrator running. Ctrl+C to stop.")
        await self._heartbeat_loop()

    # =========================================================================
    # HEARTBEAT
    # =========================================================================

    async def _heartbeat_loop(self) -> None:
        """Send heartbeat to server every 30s via WebSocket."""
        while self._running:
            if self.ws_thread and self.ws_thread.connected:
                self.ws_thread.send_heartbeat(self.plugins.all_names())
                logger.debug(
                    f"Heartbeat sent — "
                    f"plugins={self.plugins.all_names()}, "
                    f"queue={self.telemetry.queue_size}"
                )
            await asyncio.sleep(HEARTBEAT_INTERVAL)

    # =========================================================================
    # CAPABILITY REGISTRATION
    # =========================================================================

    async def _register_capabilities(self) -> None:
        """
        Tell the server which plugins this agent has loaded.
        The server stores this so the dashboard can show what
        commands each agent supports.
        """
        capabilities = self.plugins.get_all_info()
        loop         = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: self.transport.post('/api/agent/capabilities/', {
                    'agent_id':     self.config.agent_id,
                    'capabilities': capabilities,
                })
            )
            logger.info(
                f"Capabilities registered with server: "
                f"{[c['name'] for c in capabilities]}"
            )
        except Exception as exc:
            logger.warning(f"Could not register capabilities: {exc}")

    # =========================================================================
    # COMMAND DISPATCH
    # =========================================================================

    def _on_ws_command(self, data: dict) -> None:
        """
        Called by WebSocketThread when a command arrives.
        Runs in WS thread — schedules coroutine on the event loop.
        This is the bridge between the WS thread and asyncio.
        """
        loop = asyncio.get_event_loop()
        asyncio.run_coroutine_threadsafe(
            self.dispatch_command(data), loop
        )

    async def dispatch_command(self, data: dict) -> None:
        """
        Route a server command to the correct plugin.

        Command format from server:
        {
            "type":    "command",
            "command": "nmap",
            "args":    { "target": "192.168.1.1", "profile": "fast" }
        }

        Special built-in commands handled by orchestrator directly:
          stop        — stop a running plugin or all plugins
          status      — return current status of all plugins
        """
        command = data.get('command', '').strip()
        args    = data.get('args', {})

        logger.info(f"Command received: '{command}' args={args}")

        # ── Built-in: stop ────────────────────────────────────────────────────
        if command == 'stop':
            target = args.get('plugin', None)
            if target:
                await self._stop_plugin(target)
            else:
                await self._stop_all_plugins()
            return

        # ── Built-in: status ──────────────────────────────────────────────────
        if command == 'status':
            await self._send_status()
            return

        # ── Plugin dispatch ───────────────────────────────────────────────────
        plugin = self.plugins.get(command)
        if plugin is None:
            logger.warning(
                f"Unknown command '{command}'. "
                f"Loaded plugins: {self.plugins.all_names()}"
            )
            if self.ws_thread and self.ws_thread.connected:
                self.ws_thread.send({
                    'type':    'error',
                    'message': f"Unknown command '{command}'. "
                               f"Available: {self.plugins.all_names()}"
                })
            return

        # Cancel any existing task for this plugin
        if command in self._active_tasks:
            existing = self._active_tasks[command]
            if not existing.done():
                logger.info(f"Cancelling existing '{command}' task")
                existing.cancel()

        # Launch plugin as asyncio task
        task = asyncio.create_task(
            self._run_plugin(plugin, args),
            name=f'plugin-{command}'
        )
        self._active_tasks[command] = task

    async def _run_plugin(self, plugin, args: dict) -> None:
        """
        Execute one plugin safely.
        Catches all exceptions so a bad plugin never crashes the orchestrator.
        """
        from plugin_base import PluginStatus

        plugin._stop_event.clear()
        plugin.status = PluginStatus.RUNNING
        plugin.config = args

        logger.info(f"Plugin [{plugin.name}] executing with args={args}")

        try:
            await plugin.execute(args)
            plugin.status = PluginStatus.COMPLETE
            logger.info(f"Plugin [{plugin.name}] completed successfully")

        except asyncio.CancelledError:
            plugin.status = PluginStatus.STOPPED
            logger.info(f"Plugin [{plugin.name}] was cancelled")

        except Exception as exc:
            plugin.status = PluginStatus.FAILED
            logger.error(f"Plugin [{plugin.name}] raised exception: {exc}", exc_info=True)
            # Emit failure to telemetry so server knows
            await plugin._emit(
                data    = {'error': str(exc), 'plugin': plugin.name},
                success = False,
                endpoint= f'/api/agent/{plugin.name}/results/',
            )

    # =========================================================================
    # BUILT-IN COMMAND HANDLERS
    # =========================================================================

    async def _stop_plugin(self, name: str) -> None:
        plugin = self.plugins.get(name)
        if plugin:
            plugin.stop()
            task = self._active_tasks.get(name)
            if task and not task.done():
                task.cancel()
            logger.info(f"Plugin [{name}] stopped")
        else:
            logger.warning(f"Cannot stop unknown plugin: {name}")

    async def _stop_all_plugins(self) -> None:
        self.plugins.stop_all()
        for name, task in self._active_tasks.items():
            if not task.done():
                task.cancel()
        logger.info("All plugins stopped")

    async def _send_status(self) -> None:
        """Push current agent status to server via telemetry queue."""
        from plugin_base import PluginResult
        status_data = {
            'agent_id':     self.config.agent_id,
            'plugins':      self.plugins.get_all_info(),
            'queue_size':   self.telemetry.queue_size,
            'ws_connected': self.ws_thread.connected if self.ws_thread else False,
        }
        result = PluginResult(
            plugin_name = 'orchestrator',
            success     = True,
            data        = status_data,
            endpoint    = '/api/agent/status/report/',
            live_output = f"Status: {len(self.plugins.all_names())} plugins, "
                          f"queue={self.telemetry.queue_size}",
        )
        await self.telemetry.queue.put(result)

    # =========================================================================
    # SHUTDOWN
    # =========================================================================

    async def stop(self) -> None:
        """Graceful shutdown — stop all plugins, close connections."""
        logger.info("Orchestrator shutting down...")
        self._running = False

        # Stop all plugins
        await self._stop_all_plugins()

        # Stop telemetry
        self.telemetry.stop()

        # Stop WebSocket
        if self.ws_thread:
            self.ws_thread.stop()

        logger.info("Orchestrator stopped cleanly.")


# =============================================================================
# REGISTRATION HELPER
# =============================================================================

def register_agent(server_url: str, agent_id: str,
                   name: str, reg_key: str) -> None:
    """
    Register a new agent with the server.
    Creates agent_config.json with credentials.
    Run this ONCE before starting the orchestrator.

    WHY REGISTRATION EXISTS:
      The server needs to know which machines are authorised to submit
      scan results. Registration creates a unique identity (agent_id),
      an auth_token for HMAC signing, and a secret_key for JWT auth.
      Without registration any script could post fake results.
    """
    import ssl
    import urllib.request
    import urllib.error

    cert_dir   = Path(__file__).parent / 'certs'
    ca_cert    = cert_dir / 'ca.crt'
    agent_cert = cert_dir / 'agent.crt'
    agent_key  = cert_dir / 'agent.key'

    ssl_ctx = build_ssl_context(ca_cert, agent_cert, agent_key)
    body    = json.dumps({
        'agent_id':         agent_id,
        'name':             name or agent_id,
        'registration_key': reg_key,
    }).encode('utf-8')

    req = urllib.request.Request(
        f"{server_url.rstrip('/')}/api/agent/register/",
        data=body, headers={'Content-Type': 'application/json'}, method='POST',
    )

    logger.info(f"Registering agent '{agent_id}' with server...")
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as exc:
        logger.error(f"Registration failed: {exc.code} {exc.read().decode()}")
        sys.exit(1)
    except urllib.error.URLError as exc:
        logger.error(f"Cannot reach server: {exc.reason}")
        sys.exit(1)

    config = AgentConfig.__new__(AgentConfig)
    config._path = Path(__file__).parent / 'agent_config.json'
    config.save({
        'server_url':       server_url,
        'agent_id':         data['agent_id'],
        'auth_token':       data['auth_token'],
        'secret_key':       data['secret_key'],
        'registration_key': reg_key,
    })

    logger.info(f"Registration complete!")
    logger.info(f"  Agent ID  : {data['agent_id']}")
    logger.info(f"  Auth Token: {data['auth_token'][:16]}...")
    logger.info(f"  Config    : agent_config.json")
    logger.info("  Next: python orchestrator.py --run")


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description='MIAT Agent Orchestrator — mTLS + JWT + HMAC + Plugins',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  Register agent (run once):
    python orchestrator.py --register --agent-id barc-lab-01 --reg-key KEY

  Start agent (persistent):
    python orchestrator.py --run

  Start against specific server:
    python orchestrator.py --run --server https://10.0.0.1:8443

  Development (no SSL):
    python orchestrator.py --run --server http://127.0.0.1:8000 --no-tls
        """
    )

    parser.add_argument('--register',   action='store_true',
                        help='Register this agent with the server')
    parser.add_argument('--run',        action='store_true',
                        help='Start the orchestrator (persistent mode)')
    parser.add_argument('--agent-id',   help='Agent ID for registration')
    parser.add_argument('--agent-name', help='Display name')
    parser.add_argument('--reg-key',    help='Registration key from settings.py')
    parser.add_argument('--server',     default='https://127.0.0.1:8443')
    parser.add_argument('--no-tls',     action='store_true',
                        help='Skip mTLS (development only)')

    args = parser.parse_args()

    # ── Registration ──────────────────────────────────────────────────────────
    if args.register:
        if not args.agent_id or not args.reg_key:
            parser.error('--register requires --agent-id and --reg-key')
        register_agent(
            server_url = args.server,
            agent_id   = args.agent_id,
            name       = args.agent_name or args.agent_id,
            reg_key    = args.reg_key,
        )
        return

    # ── Run ───────────────────────────────────────────────────────────────────
    if args.run:
        config = AgentConfig()
        if args.server:
            config._data['server_url'] = args.server

        orchestrator = Orchestrator(config)

        # Handle Ctrl+C gracefully
        loop = asyncio.get_event_loop()

        def _shutdown():
            logger.info("Shutdown signal received")
            loop.create_task(orchestrator.stop())

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _shutdown)
            except NotImplementedError:
                pass   # Windows doesn't support add_signal_handler

        try:
            loop.run_until_complete(orchestrator.start())
        except KeyboardInterrupt:
            loop.run_until_complete(orchestrator.stop())
        finally:
            loop.close()
        return

    parser.print_help()


if __name__ == '__main__':
    main()