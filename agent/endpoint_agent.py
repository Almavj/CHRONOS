"""
CHRONOS Lightweight Endpoint Agent
A lightweight agent for endpoint log collection and threat detection
"""

import os
import sys
import json
import time
import socket
import logging
import hashlib
import platform
import signal
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
import argparse

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class EndpointAgent:
    """Lightweight endpoint security agent."""

    def __init__(
        self,
        server_url: str,
        api_key: str = "chronos-secret-key-2024",
        hostname: str = None,
        tags: List[str] = None,
    ):
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.hostname = hostname or socket.gethostname()
        self.tags = tags or []

        self.agent_id = self._generate_agent_id()
        self.running = False
        self.buffer_size = 100
        self.event_buffer: List[Dict[str, Any]] = []
        self.buffer_lock = threading.Lock()

        self.collection_config = {
            "process_creation": True,
            "network_connections": True,
            "file_operations": True,
            "registry_operations": True,
            "authentication": True,
        }

        self._setup_platform()

    def _generate_agent_id(self) -> str:
        """Generate unique agent ID."""
        unique_str = f"{socket.gethostname()}{platform.node()}{time.time()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()[:16]

    def _setup_platform(self) -> None:
        """Setup platform-specific collection."""
        self.platform = platform.system().lower()
        logger.info(f"Running on platform: {self.platform}")

    def collect_process_events(self) -> None:
        """Collect process creation events."""
        if self.platform == "windows":
            self._collect_windows_process()
        else:
            self._collect_linux_process()

    def _collect_windows_process(self) -> None:
        """Collect Windows process events using PowerShell."""
        try:
            import subprocess

            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 5 2>$null | Select-Object TimeCreated,Message | ConvertTo-Json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.stdout.strip():
                events = json.loads(result.stdout)
                if isinstance(events, dict):
                    events = [events]

                for event in events:
                    self._send_event(
                        {
                            "event_type": "process_creation",
                            "timestamp": event.get("TimeCreated", ""),
                            "data": event.get("Message", ""),
                        }
                    )
        except Exception as e:
            logger.debug(f"Process collection error: {e}")

    def _collect_linux_process(self) -> None:
        """Collect Linux process events."""
        try:
            import subprocess

            result = subprocess.run(
                ["ps", "aux", "--no-headers"], capture_output=True, text=True, timeout=5
            )

            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) > 10:
                    self._send_event(
                        {
                            "event_type": "process_creation",
                            "timestamp": datetime.now().isoformat(),
                            "data": {
                                "pid": parts[1],
                                "user": parts[0],
                                "command": " ".join(parts[10:]),
                            },
                        }
                    )
        except Exception as e:
            logger.debug(f"Linux process collection error: {e}")

    def collect_network_events(self) -> None:
        """Collect network connection events."""
        if self.platform == "windows":
            self._collect_windows_network()
        else:
            self._collect_linux_network()

    def _collect_windows_network(self) -> None:
        """Collect Windows network events."""
        try:
            import subprocess

            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.stdout.strip():
                connections = json.loads(result.stdout)
                if isinstance(connections, dict):
                    connections = [connections]

                for conn in connections:
                    self._send_event(
                        {
                            "event_type": "network_connection",
                            "timestamp": datetime.now().isoformat(),
                            "data": conn,
                        }
                    )
        except Exception as e:
            logger.debug(f"Network collection error: {e}")

    def _collect_linux_network(self) -> None:
        """Collect Linux network events."""
        try:
            import subprocess

            result = subprocess.run(
                ["ss", "-tun"], capture_output=True, text=True, timeout=5
            )

            lines = result.stdout.strip().split("\n")[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    self._send_event(
                        {
                            "event_type": "network_connection",
                            "timestamp": datetime.now().isoformat(),
                            "data": {
                                "local": parts[4],
                                "peer": parts[5],
                                "state": parts[1],
                            },
                        }
                    )
        except Exception as e:
            logger.debug(f"Linux network collection error: {e}")

    def collect_authentication_events(self) -> None:
        """Collect authentication events."""
        if self.platform == "windows":
            self._collect_windows_auth()
        else:
            self._collect_linux_auth()

    def _collect_windows_auth(self) -> None:
        """Collect Windows authentication events."""
        try:
            import subprocess

            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625} -MaxEvents 5 2>$null | Select-Object TimeCreated,Message | ConvertTo-Json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.stdout.strip():
                events = json.loads(result.stdout)
                if isinstance(events, dict):
                    events = [events]

                for event in events:
                    self._send_event(
                        {
                            "event_type": "authentication",
                            "timestamp": event.get("TimeCreated", ""),
                            "data": event.get("Message", ""),
                        }
                    )
        except Exception as e:
            logger.debug(f"Auth collection error: {e}")

    def _collect_linux_auth(self) -> None:
        """Collect Linux authentication events."""
        auth_files = ["/var/log/auth.log", "/var/log/secure"]

        for auth_file in auth_files:
            if not os.path.exists(auth_file):
                continue

            try:
                with open(auth_file, "r") as f:
                    lines = f.readlines()[-5:]

                    for line in lines:
                        self._send_event(
                            {
                                "event_type": "authentication",
                                "timestamp": datetime.now().isoformat(),
                                "data": line.strip(),
                            }
                        )
            except Exception as e:
                logger.debug(f"Linux auth collection error: {e}")

    def _send_event(self, event: Dict[str, Any]) -> None:
        """Buffer event for sending."""
        event["agent_id"] = self.agent_id
        event["hostname"] = self.hostname
        event["platform"] = self.platform

        with self.buffer_lock:
            self.event_buffer.append(event)
            if len(self.event_buffer) > self.buffer_size:
                self.event_buffer = self.event_buffer[-50:]

    def flush_buffer(self) -> List[Dict[str, Any]]:
        """Get and clear the event buffer."""
        with self.buffer_lock:
            events = list(self.event_buffer)
            self.event_buffer.clear()
            return events

    def send_events(self) -> bool:
        """Send buffered events to server."""
        events = self.flush_buffer()

        if not events:
            return True

        try:
            import requests

            url = f"{self.server_url}/api/v1/events"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "agent_id": self.agent_id,
                "hostname": self.hostname,
                "events": events,
            }

            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                logger.debug(f"Sent {len(events)} events")
                return True
            else:
                logger.warning(f"Failed to send events: {response.status_code}")
                return False

        except ImportError:
            logger.warning("requests library not available, buffering events")
            with self.buffer_lock:
                self.event_buffer.extend(events)
            return False
        except Exception as e:
            logger.error(f"Error sending events: {e}")
            with self.buffer_lock:
                self.event_buffer.extend(events)
            return False

    def register(self) -> bool:
        """Register agent with server."""
        try:
            import requests

            url = f"{self.server_url}/api/v1/agents/register"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "agent_id": self.agent_id,
                "hostname": self.hostname,
                "platform": self.platform,
                "tags": self.tags,
            }

            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                logger.info(f"Agent registered: {self.agent_id}")
                return True
            else:
                logger.warning(f"Registration failed: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False

    def run_collection_cycle(self) -> None:
        """Run one collection cycle."""
        if self.collection_config.get("process_creation"):
            self.collect_process_events()

        if self.collection_config.get("network_connections"):
            self.collect_network_events()

        if self.collection_config.get("authentication"):
            self.collect_authentication_events()

    def start(self, collect_interval: int = 30, send_interval: int = 60) -> None:
        """Start the agent."""
        self.running = True

        logger.info(f"Starting CHRONOS agent: {self.agent_id}")

        self.register()

        def collection_loop():
            while self.running:
                try:
                    self.run_collection_cycle()
                except Exception as e:
                    logger.error(f"Collection error: {e}")
                finally:
                    time.sleep(collect_interval)

        def sender_loop():
            while self.running:
                try:
                    self.send_events()
                except Exception as e:
                    logger.error(f"Send error: {e}")
                finally:
                    time.sleep(send_interval)

        collection_thread = threading.Thread(target=collection_loop, daemon=True)
        collection_thread.start()

        sender_thread = threading.Thread(target=sender_loop, daemon=True)
        sender_thread.start()

        logger.info("Agent running...")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        """Stop the agent."""
        logger.info("Stopping agent...")
        self.running = False

        self.send_events()

        logger.info("Agent stopped")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="CHRONOS Endpoint Agent")
    parser.add_argument("--server", required=True, help="CHRONOS server URL")
    parser.add_argument(
        "--api-key",
        default="chronos-secret-key-2024",
        help="API key for authentication (default: chronos-secret-key-2024)",
    )
    parser.add_argument("--hostname", help="Custom hostname")
    parser.add_argument("--tags", nargs="+", default=[], help="Agent tags")
    parser.add_argument(
        "--collect-interval",
        type=int,
        default=30,
        help="Collection interval in seconds",
    )
    parser.add_argument(
        "--send-interval", type=int, default=60, help="Send interval in seconds"
    )

    args = parser.parse_args()

    agent = EndpointAgent(
        server_url=args.server,
        api_key=args.api_key,
        hostname=args.hostname,
        tags=args.tags,
    )

    def signal_handler(signum, frame):
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    agent.start(
        collect_interval=args.collect_interval,
        send_interval=args.send_interval,
    )


if __name__ == "__main__":
    main()
