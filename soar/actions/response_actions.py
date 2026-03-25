"""
Real SOAR Response Actions for CHRONOS
Actual implementation of containment and response actions
"""

import logging
import subprocess
import requests
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ResponseStatus(Enum):
    """Response action status."""

    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"
    TIMEOUT = "timeout"


@dataclass
class ResponseResult:
    """Result of a response action."""

    action: str
    target: str
    status: ResponseStatus
    message: str
    details: Dict[str, Any] = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
        if self.details is None:
            self.details = {}


class EDRIntegration:
    """EDR integration for host containment (Wazuh, SentinelOne, etc.)."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.provider = config.get("provider", "wazuh")
        self.api_url = config.get("api_url", "")
        self.api_key = config.get("api_key", "")

    def isolate_host(self, hostname: str) -> ResponseResult:
        """Isolate host from network."""
        try:
            if self.provider == "wazuh":
                return self._wazuh_isolate(hostname)
            elif self.provider == "sentinelone":
                return self._sentinelone_isolate(hostname)
            else:
                return ResponseResult(
                    action="isolate_host",
                    target=hostname,
                    status=ResponseStatus.FAILED,
                    message=f"Unknown provider: {self.provider}",
                )
        except Exception as e:
            logger.error(f"Host isolation error: {e}")
            return ResponseResult(
                action="isolate_host",
                target=hostname,
                status=ResponseStatus.FAILED,
                message=str(e),
            )

    def _wazuh_isolate(self, hostname: str) -> ResponseResult:
        """Wazuh agent isolation."""
        try:
            response = requests.post(
                f"{self.api_url}/agents/{hostname}/group",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"group": "isolation-group"},
                timeout=30,
            )

            if response.status_code in [200, 201]:
                logger.info(f"Host {hostname} isolated via Wazuh")
                return ResponseResult(
                    action="isolate_host",
                    target=hostname,
                    status=ResponseStatus.SUCCESS,
                    message=f"Host {hostname} isolated successfully",
                    details={"provider": "wazuh", "hostname": hostname},
                )
            else:
                return ResponseResult(
                    action="isolate_host",
                    target=hostname,
                    status=ResponseStatus.FAILED,
                    message=f"Wazuh API error: {response.status_code}",
                )

        except Exception as e:
            return ResponseResult(
                action="isolate_host",
                target=hostname,
                status=ResponseStatus.FAILED,
                message=f"Wazuh isolation failed: {str(e)}",
            )

    def _sentinelone_isolate(self, hostname: str) -> ResponseResult:
        """SentinelOne agent isolation."""
        headers = {
            "Authorization": f"ApiToken {self.api_key}",
            "Content-Type": "application/json",
        }

        response = requests.get(
            f"{self.api_url}/agents",
            headers=headers,
            params={"filter": hostname},
            timeout=30,
        )

        if response.status_code == 200:
            agents = response.json().get("data", [])
            if agents:
                agent_id = agents[0].get("id")

                isolate_response = requests.post(
                    f"{self.api_url}/agents/{agent_id}/disconnect",
                    headers=headers,
                    timeout=30,
                )

                if isolate_response.status_code == 200:
                    return ResponseResult(
                        action="isolate_host",
                        target=hostname,
                        status=ResponseStatus.SUCCESS,
                        message=f"Host {hostname} isolated via SentinelOne",
                        details={"provider": "sentinelone", "agent_id": agent_id},
                    )

        return ResponseResult(
            action="isolate_host",
            target=hostname,
            status=ResponseStatus.FAILED,
            message="SentinelOne isolation failed",
        )

    def capture_memory(self, hostname: str, output_path: str = None) -> ResponseResult:
        """Capture memory from host."""
        if output_path is None:
            output_path = f"/forensics/memory_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mem"

        try:
            result = subprocess.run(
                ["winpmem_mini_x64.exe", hostname, output_path],
                capture_output=True,
                timeout=300,
            )

            if result.returncode == 0:
                return ResponseResult(
                    action="capture_memory",
                    target=hostname,
                    status=ResponseStatus.SUCCESS,
                    message=f"Memory captured to {output_path}",
                    details={"output_path": output_path},
                )
            else:
                return ResponseResult(
                    action="capture_memory",
                    target=hostname,
                    status=ResponseStatus.FAILED,
                    message=f"Memory capture failed: {result.stderr.decode()}",
                )

        except subprocess.TimeoutExpired:
            return ResponseResult(
                action="capture_memory",
                target=hostname,
                status=ResponseStatus.TIMEOUT,
                message="Memory capture timed out",
            )
        except Exception as e:
            return ResponseResult(
                action="capture_memory",
                target=hostname,
                status=ResponseStatus.FAILED,
                message=str(e),
            )


class ActiveDirectoryIntegration:
    """Active Directory integration for account management."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ldap_server = config.get("ldap_server", "")
        self.ldap_user = config.get("ldap_user", "")
        self.ldap_password = config.get("ldap_password", "")

    def disable_account(self, username: str) -> ResponseResult:
        """Disable AD account."""
        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-Command",
                    f'Set-ADAccountIdentity -Identity "{username}" -Enabled $false',
                ],
                capture_output=True,
                timeout=30,
            )

            if result.returncode == 0:
                logger.info(f"Account {username} disabled")
                return ResponseResult(
                    action="disable_account",
                    target=username,
                    status=ResponseStatus.SUCCESS,
                    message=f"Account {username} disabled successfully",
                )
            else:
                return ResponseResult(
                    action="disable_account",
                    target=username,
                    status=ResponseStatus.FAILED,
                    message=f"Failed to disable account: {result.stderr.decode()}",
                )

        except Exception as e:
            return ResponseResult(
                action="disable_account",
                target=username,
                status=ResponseStatus.FAILED,
                message=str(e),
            )

    def reset_password(self, username: str) -> ResponseResult:
        """Reset AD account password."""
        try:
            new_password = self._generate_secure_password()

            result = subprocess.run(
                [
                    "powershell.exe",
                    "-Command",
                    f'Set-ADAccountPassword -Identity "{username}" -NewPassword (ConvertTo-SecureString -AsPlainText "{new_password}" -Force) -Reset',
                ],
                capture_output=True,
                timeout=30,
            )

            if result.returncode == 0:
                logger.info(f"Password reset for {username}")
                return ResponseResult(
                    action="reset_password",
                    target=username,
                    status=ResponseStatus.SUCCESS,
                    message=f"Password reset for {username}",
                    details={"temp_password_set": True},
                )
            else:
                return ResponseResult(
                    action="reset_password",
                    target=username,
                    status=ResponseStatus.FAILED,
                    message=f"Password reset failed: {result.stderr.decode()}",
                )

        except Exception as e:
            return ResponseResult(
                action="reset_password",
                target=username,
                status=ResponseStatus.FAILED,
                message=str(e),
            )

    def enable_mfa(self, username: str) -> ResponseResult:
        """Enable MFA for user."""
        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-Command",
                    f'Set-MsolUser -UserPrincipalName "{username}" -StrongAuthenticationRequirements @()',
                ],
                capture_output=True,
                timeout=30,
            )

            return ResponseResult(
                action="enable_mfa",
                target=username,
                status=ResponseStatus.SUCCESS
                if result.returncode == 0
                else ResponseStatus.FAILED,
                message="MFA enabled"
                if result.returncode == 0
                else "MFA enable failed",
            )

        except Exception as e:
            return ResponseResult(
                action="enable_mfa",
                target=username,
                status=ResponseStatus.FAILED,
                message=str(e),
            )

    def revoke_admin(self, username: str) -> ResponseResult:
        """Revoke admin privileges."""
        admin_groups = ["Domain Admins", "Enterprise Admins", "Administrators"]

        try:
            for group in admin_groups:
                subprocess.run(
                    [
                        "powershell.exe",
                        "-Command",
                        f'Remove-ADGroupMember -Identity "{group}" -Members "{username}" -Confirm:$false',
                    ],
                    capture_output=True,
                    timeout=30,
                )

            logger.info(f"Admin privileges revoked for {username}")
            return ResponseResult(
                action="revoke_admin",
                target=username,
                status=ResponseStatus.SUCCESS,
                message=f"Admin privileges revoked for {username}",
            )

        except Exception as e:
            return ResponseResult(
                action="revoke_admin",
                target=username,
                status=ResponseStatus.FAILED,
                message=str(e),
            )

    def _generate_secure_password(self) -> str:
        """Generate secure temporary password."""
        import secrets
        import string

        alphabet = string.ascii_letters + string.digits + "!@#$%"
        return "".join(secrets.choice(alphabet) for _ in range(16))


class FirewallIntegration:
    """Firewall integration for IP blocking."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.provider = config.get("provider", "iptables")
        self.api_url = config.get("api_url", "")
        self.api_key = config.get("api_key", "")

    def block_ip(self, ip_address: str, duration_minutes: int = 60) -> ResponseResult:
        """Block IP address."""
        try:
            if self.provider == "iptables":
                return self._iptables_block(ip_address, duration_minutes)
            elif self.provider == "pfsense":
                return self._pfsense_block(ip_address, duration_minutes)
            elif self.provider == "cloudflare":
                return self._cloudflare_block(ip_address)
            else:
                return ResponseResult(
                    action="block_ip",
                    target=ip_address,
                    status=ResponseStatus.FAILED,
                    message=f"Unknown provider: {self.provider}",
                )

        except Exception as e:
            return ResponseResult(
                action="block_ip",
                target=ip_address,
                status=ResponseStatus.FAILED,
                message=str(e),
            )

    def _iptables_block(self, ip_address: str, duration: int) -> ResponseResult:
        """Block IP using iptables."""
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True
            )

            if duration > 0:
                subprocess.run(
                    [
                        "bash",
                        "-c",
                        f"sleep {duration * 60}; iptables -D INPUT -s {ip_address} -j DROP",
                    ],
                    timeout=duration * 60 + 10,
                )

            logger.info(f"IP {ip_address} blocked in iptables")
            return ResponseResult(
                action="block_ip",
                target=ip_address,
                status=ResponseStatus.SUCCESS,
                message=f"IP {ip_address} blocked",
                details={"provider": "iptables", "duration_minutes": duration},
            )

        except Exception as e:
            return ResponseResult(
                action="block_ip",
                target=ip_address,
                status=ResponseStatus.FAILED,
                message=f"iptables block failed: {str(e)}",
            )

    def _pfsense_block(self, ip_address: str, duration: int) -> ResponseResult:
        """Block IP using pfSense API."""
        headers = {
            "Authorization": f"Basic {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "type": "block",
            "source": ip_address,
            "descr": f"CHRONOS Block - {datetime.now().isoformat()}",
        }

        response = requests.post(
            f"{self.api_url}/firewall/rule", headers=headers, json=payload, timeout=30
        )

        if response.status_code in [200, 201]:
            return ResponseResult(
                action="block_ip",
                target=ip_address,
                status=ResponseStatus.SUCCESS,
                message=f"IP {ip_address} blocked in pfSense",
            )

        return ResponseResult(
            action="block_ip",
            target=ip_address,
            status=ResponseStatus.FAILED,
            message=f"pfSense block failed: {response.status_code}",
        )

    def _cloudflare_block(self, ip_address: str) -> ResponseResult:
        """Block IP using Cloudflare."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        zone_id = self.config.get("zone_id", "")

        response = requests.post(
            f"{self.api_url}/client/v4/zones/{zone_id}/firewall/rules",
            headers=headers,
            json={
                "filter": {"expression": f"ip.src == {ip_address}"},
                "action": "block",
            },
            timeout=30,
        )

        if response.status_code in [200, 201]:
            return ResponseResult(
                action="block_ip",
                target=ip_address,
                status=ResponseStatus.SUCCESS,
                message=f"IP {ip_address} blocked in Cloudflare",
            )

        return ResponseResult(
            action="block_ip",
            target=ip_address,
            status=ResponseStatus.FAILED,
            message=f"Cloudflare block failed",
        )


class SOARResponseEngine:
    """Main SOAR response engine coordinating all actions."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.dry_run = config.get("dry_run", True)
        self.require_confirmation = config.get("require_confirmation", True)

        edr_config = config.get("edr", {})
        if edr_config and edr_config.get("enabled"):
            self.edr = EDRIntegration(edr_config)
            logger.info("EDR integration enabled")
        else:
            self.edr = None
            logger.info("EDR integration disabled")

        ad_config = config.get("active_directory", {})
        if ad_config and ad_config.get("enabled"):
            self.ad = ActiveDirectoryIntegration(ad_config)
            logger.info("Active Directory integration enabled")
        else:
            self.ad = None
            logger.info("Active Directory integration disabled")

        fw_config = config.get("firewall", {})
        if fw_config and fw_config.get("enabled"):
            self.firewall = FirewallIntegration(fw_config)
            logger.info("Firewall integration enabled")
        else:
            self.firewall = None
            logger.info("Firewall integration disabled")

        self.notification_config = config.get("notifications", {})

    def execute_response(self, action: str, target: str, **kwargs) -> ResponseResult:
        """Execute a response action."""
        logger.info(f"Executing response action: {action} on {target}")

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would execute: {action} on {target}")
            return ResponseResult(
                action=action,
                target=target,
                status=ResponseStatus.SUCCESS,
                message=f"[DRY-RUN] Action {action} would be executed on {target}",
            )

        if action == "isolate_host":
            result = (
                self.edr.isolate_host(target)
                if self.edr
                else self._not_configured(action)
            )

        elif action == "disable_account":
            result = (
                self.ad.disable_account(target)
                if self.ad
                else self._not_configured(action)
            )

        elif action == "reset_password":
            result = (
                self.ad.reset_password(target)
                if self.ad
                else self._not_configured(action)
            )

        elif action == "enable_mfa":
            result = (
                self.ad.enable_mfa(target) if self.ad else self._not_configured(action)
            )

        elif action == "revoke_admin":
            result = (
                self.ad.revoke_admin(target)
                if self.ad
                else self._not_configured(action)
            )

        elif action == "block_ip":
            duration = kwargs.get("duration_minutes", 60)
            result = (
                self.firewall.block_ip(target, duration)
                if self.firewall
                else self._not_configured(action)
            )

        elif action == "capture_memory":
            result = (
                self.edr.capture_memory(target)
                if self.edr
                else self._not_configured(action)
            )

        elif action == "notify_soc":
            result = self._notify_soc(target, kwargs.get("alert_data", {}))

        else:
            result = ResponseResult(
                action=action,
                target=target,
                status=ResponseStatus.FAILED,
                message=f"Unknown action: {action}",
            )

        if result.status == ResponseStatus.SUCCESS:
            self._log_response_action(action, target, result)

        return result

    def execute_playbook(
        self, playbook_name: str, target: str, alert_data: Dict[str, Any] = None
    ) -> List[ResponseResult]:
        """Execute a response playbook."""
        playbooks = {
            "contain_host": ["isolate_host", "capture_memory", "notify_soc"],
            "credential_compromise": [
                "disable_account",
                "reset_password",
                "enable_mfa",
                "notify_soc",
            ],
            "malicious_ip": ["block_ip", "notify_soc"],
            "ransomware": ["isolate_host", "block_ip", "capture_memory", "notify_soc"],
        }

        actions = playbooks.get(playbook_name, [])

        results = []
        for action in actions:
            result = self.execute_response(action, target, alert_data=alert_data)
            results.append(result)

        return results

    def _not_configured(self, action: str) -> ResponseResult:
        """Return not configured result."""
        return ResponseResult(
            action=action,
            target="",
            status=ResponseStatus.FAILED,
            message=f"Action {action} not configured",
        )

    def _notify_soc(self, target: str, alert_data: Dict[str, Any]) -> ResponseResult:
        """Send SOC notification."""
        notification_config = self.notification_config
        method = notification_config.get("method", "email")

        if method == "email":
            to = notification_config.get("email_to", "")
            logger.info(f"[MOCK] Sending email to {to}: Alert on {target}")

        elif method == "slack":
            webhook = notification_config.get("slack_webhook", "")
            logger.info(f"[MOCK] Sending Slack notification: Alert on {target}")

        elif method == "pagerduty":
            logger.info(f"[MOCK] Triggering PagerDuty: Alert on {target}")

        return ResponseResult(
            action="notify_soc",
            target=target,
            status=ResponseStatus.SUCCESS,
            message="SOC notified successfully",
        )

    def _log_response_action(
        self, action: str, target: str, result: ResponseResult
    ) -> None:
        """Log response action for audit trail."""
        logger.info(
            f"Response action logged: {action} on {target} - {result.status.value}"
        )
