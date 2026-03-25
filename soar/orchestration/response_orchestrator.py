"""
SOAR Response Orchestrator
Automated response actions based on alert severity
"""

import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from enum import Enum

from chronos.core.detection.alert import Alert, AlertSeverity

logger = logging.getLogger(__name__)


class ResponseAction(Enum):
    """Automated response actions."""

    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    ENABLE_MFA = "enable_mfa"
    BLOCK_IP = "block_ip"
    CAPTURE_MEMORY = "capture_memory"
    TRIGGER_DLP = "trigger_dlp"
    REVOKE_ADMIN = "revoke_admin"
    RESET_PASSWORD = "reset_password"
    NOTIFY_SOC = "notify_soc"
    ESCALATE = "escalate"


class ResponseOrchestrator:
    """Orchestrates automated response to security alerts."""

    def __init__(self, auto_response_config: Dict[str, Any]):
        self.config = auto_response_config
        self.response_handlers: Dict[ResponseAction, Callable] = {}
        self.action_history: List[Dict[str, Any]] = []

        self._register_handlers()

    def _register_handlers(self) -> None:
        """Register response action handlers."""
        self.response_handlers = {
            ResponseAction.ISOLATE_HOST: self._handle_isolate_host,
            ResponseAction.DISABLE_ACCOUNT: self._handle_disable_account,
            ResponseAction.ENABLE_MFA: self._handle_enable_mfa,
            ResponseAction.BLOCK_IP: self._handle_block_ip,
            ResponseAction.CAPTURE_MEMORY: self._handle_capture_memory,
            ResponseAction.TRIGGER_DLP: self._handle_trigger_dlp,
            ResponseAction.REVOKE_ADMIN: self._handle_revoke_admin,
            ResponseAction.RESET_PASSWORD: self._handle_reset_password,
            ResponseAction.NOTIFY_SOC: self._handle_notify_soc,
        }

    def evaluate_response(self, alert: Alert) -> List[Dict[str, Any]]:
        """Evaluate and execute automated response for an alert."""
        responses_executed = []

        alert_type = self._get_alert_type(alert)
        response_config = self.config.get(alert_type, {})

        if not response_config.get("enabled", False):
            logger.debug(f"Auto-response not enabled for {alert_type}")
            return responses_executed

        actions = response_config.get("actions", [])
        escalation_required = response_config.get("escalation_required", False)

        for action_name in actions:
            try:
                action = ResponseAction(action_name)

                if action in self.response_handlers:
                    result = self.response_handlers[action](alert)
                    responses_executed.append(
                        {
                            "action": action_name,
                            "success": result.get("success", False),
                            "message": result.get("message", ""),
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    )

                    self.action_history.append(
                        {
                            "alert_id": alert.id,
                            "action": action_name,
                            "result": result,
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    )

            except ValueError:
                logger.warning(f"Unknown action: {action_name}")

        if escalation_required:
            self._handle_escalate(alert)
            responses_executed.append(
                {
                    "action": "escalate",
                    "success": True,
                    "message": "Alert escalated to SOC team",
                }
            )

        logger.info(
            f"Executed {len(responses_executed)} response actions for alert: {alert.title}"
        )

        return responses_executed

    def _get_alert_type(self, alert: Alert) -> str:
        """Determine alert type based on technique."""
        technique = alert.technique.lower()

        if "beacon" in technique or "c2" in technique:
            return "c2_beacon"
        elif "lateral" in technique or "movement" in technique:
            return "lateral_movement"
        elif "exfiltration" in technique or "exfil" in technique:
            return "data_exfiltration"
        elif "escalation" in technique or "privilege" in technique:
            return "privilege_escalation"

        return "default"

    def _handle_isolate_host(self, alert: Alert) -> Dict[str, Any]:
        """Isolate affected host from network."""
        hostname = alert.hostname or alert.metadata.get("hostname")

        logger.warning(f"[MOCK] Isolating host: {hostname}")

        return {
            "success": True,
            "message": f"Host {hostname} isolated",
            "action": "isolate_host",
            "target": hostname,
        }

    def _handle_disable_account(self, alert: Alert) -> Dict[str, Any]:
        """Disable compromised account."""
        username = alert.user or alert.metadata.get("username")

        logger.warning(f"[MOCK] Disabling account: {username}")

        return {
            "success": True,
            "message": f"Account {username} disabled",
            "action": "disable_account",
            "target": username,
        }

    def _handle_enable_mfa(self, alert: Alert) -> Dict[str, Any]:
        """Enable multi-factor authentication for account."""
        username = alert.user or alert.metadata.get("username")

        logger.warning(f"[MOCK] Enabling MFA for: {username}")

        return {
            "success": True,
            "message": f"MFA enabled for {username}",
            "action": "enable_mfa",
            "target": username,
        }

    def _handle_block_ip(self, alert: Alert) -> Dict[str, Any]:
        """Block malicious IP address."""
        ip = alert.destination_ip or alert.metadata.get("source_ip")

        logger.warning(f"[MOCK] Blocking IP: {ip}")

        return {
            "success": True,
            "message": f"IP {ip} blocked",
            "action": "block_ip",
            "target": ip,
        }

    def _handle_capture_memory(self, alert: Alert) -> Dict[str, Any]:
        """Capture memory for forensics."""
        hostname = alert.hostname or alert.metadata.get("hostname")

        logger.warning(f"[MOCK] Capturing memory from: {hostname}")

        return {
            "success": True,
            "message": f"Memory capture initiated for {hostname}",
            "action": "capture_memory",
            "target": hostname,
        }

    def _handle_trigger_dlp(self, alert: Alert) -> Dict[str, Any]:
        """Trigger Data Loss Prevention scan."""
        hostname = alert.hostname or alert.metadata.get("hostname")

        logger.warning(f"[MOCK] Triggering DLP scan for: {hostname}")

        return {
            "success": True,
            "message": f"DLP scan triggered for {hostname}",
            "action": "trigger_dlp",
            "target": hostname,
        }

    def _handle_revoke_admin(self, alert: Alert) -> Dict[str, Any]:
        """Revoke admin privileges."""
        username = alert.user or alert.metadata.get("username")

        logger.warning(f"[MOCK] Revoking admin rights for: {username}")

        return {
            "success": True,
            "message": f"Admin rights revoked for {username}",
            "action": "revoke_admin",
            "target": username,
        }

    def _handle_reset_password(self, alert: Alert) -> Dict[str, Any]:
        """Reset user password."""
        username = alert.user or alert.metadata.get("username")

        logger.warning(f"[MOCK] Resetting password for: {username}")

        return {
            "success": True,
            "message": f"Password reset for {username}",
            "action": "reset_password",
            "target": username,
        }

    def _handle_notify_soc(self, alert: Alert) -> Dict[str, Any]:
        """Notify SOC team."""
        logger.warning(f"[MOCK] Notifying SOC about: {alert.title}")

        return {
            "success": True,
            "message": f"SOC notified about {alert.title}",
            "action": "notify_soc",
            "target": alert.id,
        }

    def _handle_escalate(self, alert: Alert) -> Dict[str, Any]:
        """Escalate alert to human analyst."""
        logger.warning(f"[MOCK] Escalating alert: {alert.title}")

        return {
            "success": True,
            "message": f"Alert escalated: {alert.title}",
            "action": "escalate",
            "target": alert.id,
        }

    def get_action_history(
        self, alert_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get response action history."""
        if alert_id:
            return [
                action
                for action in self.action_history[-limit:]
                if action.get("alert_id") == alert_id
            ]
        return self.action_history[-limit:]
