"""
Wazuh API Client - Handles authentication and alert retrieval.
"""

import re
import shlex
import requests
import json
import time
import structlog
import paramiko
from typing import Optional
from datetime import datetime, timezone, timedelta
from cachetools import TTLCache

logger = structlog.get_logger(__name__)


class WazuhClient:
    """Client for the Wazuh Manager REST API."""

    LOGTEST_TEMP_FILE = "/var/ossec/etc/rules/_ai_soc_validation_temp.xml"
    LOGTEST_BIN = "/var/ossec/bin/wazuh-logtest"

    def __init__(self, host: str, port: int = 55000, username: str = "",
                 password: str = "", verify_ssl: bool = True,
                 ssh_user: str = "", ssh_password: str = "",
                 ssh_key_path: str = "", ssh_key_passphrase: str = "",
                 ssh_sudo_nopasswd: bool = False,
                 tls_insecure_hostname: bool = False):
        # Belt-and-suspenders: if the operator (or wizard) supplied a host
        # that already contains an explicit ":<port>" suffix, do not
        # duplicate it — that produced "https://10.0.0.5:55000:55000" and
        # a "Failed to parse URL" on the cheersin install.
        self.base_url = self._build_base_url(host, port)
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.tls_insecure_hostname = tls_insecure_hostname
        self._session = self._build_session(tls_insecure_hostname)
        self._token: Optional[str] = None
        self._token_expiry: float = 0
        self._agent_cache = TTLCache(maxsize=500, ttl=300)

        # SSH config for wazuh-logtest validation
        # Extract hostname from base_url (strip https:// and port)
        self._ssh_host = re.sub(r'^https?://', '', host).split(':')[0]
        self._ssh_user = ssh_user
        self._ssh_password = ssh_password
        self._ssh_key_path = ssh_key_path
        self._ssh_key_passphrase = ssh_key_passphrase or None
        self._ssh_sudo_nopasswd = ssh_sudo_nopasswd

        if ssh_password and not ssh_key_path:
            logger.warning("ssh_password_auth_deprecated",
                           message="SSH password auth is deprecated. "
                                   "Configure ssh_key_path for key-based auth.")

    @staticmethod
    def _build_session(tls_insecure_hostname: bool):
        """Build the requests.Session used for every Wazuh API call.

        When tls_insecure_hostname is set, mount an adapter that disables
        hostname matching while keeping chain verification. This addresses
        the cheersin failure mode: Wazuh's default API cert ships with
        SAN=DNS:localhost only, so connecting via the manager's IP fails
        Python 3.10+'s strict hostname check (RFC 6125) even when the chain
        is valid. Skipping hostname validation is still defensible because
        chain verification stops a generic LAN MITM — the previous escape
        hatch (DEV_MODE + verify_ssl=false) skipped both.
        """
        session = requests.Session()
        if not tls_insecure_hostname:
            return session

        from requests.adapters import HTTPAdapter
        try:
            from urllib3.poolmanager import PoolManager
        except ImportError:
            from urllib3 import PoolManager  # urllib3 v2 layout fallback

        class _NoHostnameHTTPSAdapter(HTTPAdapter):
            def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
                pool_kwargs.setdefault("assert_hostname", False)
                self.poolmanager = PoolManager(
                    num_pools=connections,
                    maxsize=maxsize,
                    block=block,
                    **pool_kwargs,
                )

        session.mount("https://", _NoHostnameHTTPSAdapter())
        logger.warning("wazuh_tls_insecure_hostname_enabled",
                       msg="Hostname matching disabled on Wazuh API session. "
                           "Chain verification still active.")
        return session

    @staticmethod
    def _build_base_url(host: str, port: int) -> str:
        """Build the base URL, tolerating a host string that already includes
        a port. Returns '<scheme>://<host>:<port>' with the port appearing
        exactly once.
        """
        from urllib.parse import urlparse

        candidate = host.strip()
        if not candidate:
            return candidate

        # urlparse needs a scheme to populate hostname/port reliably.
        had_scheme = "://" in candidate
        if not had_scheme:
            candidate = f"https://{candidate}"

        parsed = urlparse(candidate)
        scheme = parsed.scheme or "https"
        hostname = parsed.hostname or candidate

        # Operator-supplied port wins over the keyword default.
        effective_port = parsed.port or port
        return f"{scheme}://{hostname}:{effective_port}"

    def _authenticate(self):
        """Get JWT token from Wazuh API."""
        try:
            resp = self._session.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=10
            )
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]
            self._token_expiry = time.time() + 850  # Tokens expire in 900s
            logger.info("wazuh_auth_success")
        except Exception as e:
            logger.error("wazuh_auth_failed", error=str(e))
            raise

    def _headers(self) -> dict:
        if not self._token or time.time() >= self._token_expiry:
            self._authenticate()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json"
        }

    def _get(self, endpoint: str, params: dict = None) -> dict:
        resp = self._session.get(
            f"{self.base_url}{endpoint}",
            headers=self._headers(),
            params=params,
            verify=self.verify_ssl,
            timeout=30
        )
        resp.raise_for_status()
        return resp.json()

    # ----- Alert Retrieval -----

    def get_alerts(self, min_level: int = 3, limit: int = 50,
                   offset: int = 0, sort: str = "-timestamp") -> list[dict]:
        """Fetch alerts from Wazuh API."""
        try:
            result = self._get("/alerts", params={
                "limit": limit,
                "offset": offset,
                "sort": sort,
                "q": f"rule.level>={min_level}"
            })
            alerts = result.get("data", {}).get("affected_items", [])
            logger.info("wazuh_alerts_fetched", count=len(alerts))
            return alerts
        except Exception as e:
            logger.error("wazuh_alerts_fetch_failed", error=str(e))
            return []

    def get_alert_by_id(self, alert_id: str) -> Optional[dict]:
        """Fetch a specific alert."""
        try:
            result = self._get(f"/alerts", params={
                "q": f"id={alert_id}",
                "limit": 1
            })
            items = result.get("data", {}).get("affected_items", [])
            return items[0] if items else None
        except Exception as e:
            logger.error("wazuh_alert_fetch_failed", alert_id=alert_id, error=str(e))
            return None

    # ----- Agent Info -----

    def get_agent_info(self, agent_id: str) -> Optional[dict]:
        """Get agent details (cached)."""
        if agent_id in self._agent_cache:
            return self._agent_cache[agent_id]
        try:
            result = self._get(f"/agents", params={
                "agents_list": agent_id
            })
            items = result.get("data", {}).get("affected_items", [])
            if items:
                self._agent_cache[agent_id] = items[0]
                return items[0]
        except Exception as e:
            logger.error("wazuh_agent_fetch_failed", agent_id=agent_id, error=str(e))
        return None

    def get_all_agents(self) -> list[dict]:
        """Get all registered agents."""
        try:
            result = self._get("/agents", params={"limit": 500})
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("wazuh_agents_fetch_failed", error=str(e))
            return []

    # ----- Rules -----

    def get_rule(self, rule_id: int) -> Optional[dict]:
        """Get rule details."""
        try:
            result = self._get(f"/rules", params={
                "rule_ids": str(rule_id)
            })
            items = result.get("data", {}).get("affected_items", [])
            return items[0] if items else None
        except Exception as e:
            logger.error("wazuh_rule_fetch_failed", rule_id=rule_id, error=str(e))
            return None

    def get_rules_by_file(self, filename: str) -> list[dict]:
        """Get all rules from a specific file."""
        try:
            result = self._get("/rules", params={
                "filename": filename,
                "limit": 500
            })
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("wazuh_rules_fetch_failed", filename=filename, error=str(e))
            return []

    # ----- Rule Files (for detection engineering) -----

    def get_rule_file_content(self, filename: str) -> Optional[str]:
        """Get raw XML content of a rule file."""
        try:
            # Use raw=true to get the actual XML string, not parsed dict
            resp = self._session.get(
                f"{self.base_url}/rules/files/{filename}",
                headers=self._headers(),
                params={"raw": "true"},
                verify=self.verify_ssl,
                timeout=30
            )
            resp.raise_for_status()
            text = resp.text
            # Wazuh may return JSON error body even with raw=true for missing files
            if text.lstrip().startswith('{'):
                logger.info("wazuh_rulefile_not_found", filename=filename)
                return None
            return text
        except Exception as e:
            logger.error("wazuh_rulefile_fetch_failed", filename=filename, error=str(e))
            return None

    def update_rule_file(self, filename: str, content: str) -> bool:
        """Update a custom rule file (requires manager restart)."""
        try:
            resp = self._session.put(
                f"{self.base_url}/rules/files/{filename}",
                headers={**self._headers(), "Content-Type": "application/octet-stream"},
                params={"overwrite": "true"},
                data=content.encode(),
                verify=self.verify_ssl,
                timeout=30
            )
            resp.raise_for_status()
            logger.info("wazuh_rulefile_updated", filename=filename)
            return True
        except Exception as e:
            logger.error("wazuh_rulefile_update_failed", filename=filename, error=str(e))
            return False

    def restart_manager(self) -> bool:
        """Restart Wazuh manager to reload rules after a rule file update."""
        try:
            result = self._put("/manager/restart")
            logger.info("wazuh_manager_restart_triggered",
                        data=result.get("data", {}))
            return True
        except Exception as e:
            logger.warning("wazuh_manager_restart_failed", error=str(e))
            return False

    def _put(self, endpoint: str, data: dict = None) -> dict:
        resp = self._session.put(
            f"{self.base_url}{endpoint}",
            headers=self._headers(),
            json=data,
            verify=self.verify_ssl,
            timeout=30
        )
        resp.raise_for_status()
        return resp.json()

    # ----- Rule Validation via wazuh-logtest -----

    def _delete_rule_file(self, filename: str) -> bool:
        """Delete a custom rule file from the Wazuh manager via API."""
        try:
            resp = self._session.delete(
                f"{self.base_url}/rules/files/{filename}",
                headers=self._headers(),
                verify=self.verify_ssl,
                timeout=30
            )
            resp.raise_for_status()
            logger.info("wazuh_rulefile_deleted", filename=filename)
            return True
        except Exception as e:
            logger.error("wazuh_rulefile_delete_failed",
                         filename=filename, error=str(e))
            return False

    def _ssh_run_logtest(self) -> str:
        """SSH to Wazuh manager and run wazuh-logtest with a dummy event.

        Prefers key-based auth when ssh_key_path is configured.
        Returns the combined stdout+stderr output from logtest.
        """
        client = paramiko.SSHClient()
        # WarningPolicy logs unknown host keys instead of silently accepting them,
        # preventing silent MITM. Use RejectPolicy or load known_hosts for stricter control.
        # Use RejectPolicy by default; load known_hosts if available.
        # Falls back to WarningPolicy only if no known_hosts file exists
        # and DEV_MODE is enabled.
        import os as _os
        known_hosts = _os.path.expanduser("~/.ssh/known_hosts")
        if _os.path.isfile(known_hosts):
            client.load_host_keys(known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        elif _os.environ.get("DEV_MODE", "").lower() in ("1", "true", "yes"):
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            connect_kwargs = {
                "hostname": self._ssh_host,
                "username": self._ssh_user,
                "timeout": 10,
            }

            if self._ssh_key_path:
                connect_kwargs["key_filename"] = self._ssh_key_path
                if self._ssh_key_passphrase:
                    connect_kwargs["passphrase"] = self._ssh_key_passphrase
            else:
                connect_kwargs["password"] = self._ssh_password
                connect_kwargs["allow_agent"] = False
                connect_kwargs["look_for_keys"] = False

            client.connect(**connect_kwargs)

            # Build the logtest command — use shlex.quote to prevent injection
            test_log = "Apr 1 00:00:00 test sshd[1]: test"
            safe_log = shlex.quote(test_log)
            if self._ssh_sudo_nopasswd:
                # NOPASSWD sudoers entry — no password piped via stdin
                cmd = (
                    f"sudo bash -c 'echo {safe_log} "
                    f"| {self.LOGTEST_BIN} -q' 2>&1"
                )
                stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
            else:
                # Pipe password via stdin (never embed in command string)
                cmd = (
                    f"sudo -S bash -c 'echo {safe_log} "
                    f"| {self.LOGTEST_BIN} -q' 2>&1"
                )
                stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
                stdin.write(self._ssh_password + "\n")
                stdin.flush()

            stdout.channel.recv_exit_status()
            return stdout.read().decode()
        finally:
            client.close()

    def _upload_temp_rule(self, filename: str, content: str) -> tuple[bool, str]:
        """Upload a rule file and check the Wazuh API response for errors.

        Returns (success, error_message). The Wazuh API returns HTTP 200 even
        for failed uploads, with errors in the response body.
        """
        try:
            resp = self._session.put(
                f"{self.base_url}/rules/files/{filename}",
                headers={**self._headers(),
                         "Content-Type": "application/octet-stream"},
                params={"overwrite": "true"},
                data=content.encode(),
                verify=self.verify_ssl,
                timeout=30
            )
            resp.raise_for_status()
            body = resp.json()
            failed = body.get("data", {}).get("total_failed_items", 0)
            if failed > 0:
                items = body.get("data", {}).get("failed_items", [])
                error_msg = items[0].get("error", {}).get("message", "Unknown XML error") if items else "XML validation failed"
                return False, error_msg
            return True, ""
        except Exception as e:
            return False, str(e)

    def validate_rule_with_logtest(self, rule_xml: str) -> tuple[bool, str]:
        """Validate rule XML against the Wazuh manager.

        Two-layer validation:
        1. Upload to Wazuh API — catches XML syntax errors (malformed tags,
           unclosed elements, encoding issues)
        2. Run wazuh-logtest via SSH — catches rule logic errors that only
           surface when analysisd loads the rules (bad references, schema issues)

        Returns (is_valid, error_message).
        Fail-closed in production: returns (False, reason) if validation
        infrastructure is unavailable, routing the rule to manual review.
        Set DEV_MODE=true for fail-open behavior during development.
        """
        # Wrap in <group> if not already wrapped (Wazuh requires it)
        xml_to_validate = rule_xml.strip()
        if '<group ' not in xml_to_validate[:500]:
            xml_to_validate = (
                '<group name="local,ai_soc_validation,">\n'
                f'{xml_to_validate}\n'
                '</group>'
            )

        temp_filename = "_ai_soc_validation_temp.xml"

        try:
            # Layer 1: Upload via Wazuh API (catches XML syntax errors)
            uploaded, api_error = self._upload_temp_rule(
                temp_filename, xml_to_validate
            )
            _dev_mode = __import__("os").environ.get(
                "DEV_MODE", "").lower() in ("1", "true", "yes")

            if not uploaded:
                if api_error:
                    logger.warning("wazuh_rule_validation_failed",
                                   layer="api", error=api_error)
                    return False, api_error
                if _dev_mode:
                    logger.warning("wazuh_validation_upload_error",
                                   detail="Validation skipped (fail-open, DEV_MODE)")
                    return True, ""
                logger.warning("wazuh_validation_upload_error",
                               detail="Validation skipped — routing to manual review (fail-closed)")
                return False, "Wazuh API unavailable for validation — manual review required"

            try:
                # Layer 2: Run wazuh-logtest via SSH (catches rule logic errors)
                if self._ssh_user:
                    output = self._ssh_run_logtest()
                    error_lines = [
                        line.strip() for line in output.splitlines()
                        if any(kw in line for kw in (
                            'ERROR:', 'CRITICAL:', 'XMLERR:',
                            'is duplicated', 'Invalid configuration',
                            'Invalid day format', 'Configuration error',
                        ))
                    ]
                    if error_lines:
                        error_msg = '; '.join(error_lines[:5])
                        logger.warning("wazuh_rule_validation_failed",
                                       layer="logtest", error=error_msg)
                        return False, error_msg

                logger.info("wazuh_rule_validation_passed")
                return True, ""

            finally:
                # ALWAYS clean up temp file
                self._delete_rule_file(temp_filename)

        except (paramiko.SSHException, OSError, TimeoutError) as e:
            logger.warning("wazuh_logtest_ssh_error", error=str(e))
            try:
                self._delete_rule_file(temp_filename)
            except Exception:
                pass
            if _dev_mode:
                logger.warning("ssh_validation_skipped_dev_mode")
                return True, ""
            return False, f"SSH validation unavailable — manual review required: {e}"
        except Exception as e:
            logger.warning("wazuh_validation_unexpected_error", error=str(e))
            try:
                self._delete_rule_file(temp_filename)
            except Exception:
                pass
            if _dev_mode:
                return True, ""
            return False, f"Validation error — manual review required: {e}"

    # ----- Vulnerability & SCA -----

    def get_agent_vulnerabilities(self, agent_id: str) -> list[dict]:
        """Get vulnerability data for an agent."""
        try:
            result = self._get(f"/vulnerability/{agent_id}", params={"limit": 100})
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("wazuh_vuln_fetch_failed", agent_id=agent_id, error=str(e))
            return []

    # ----- Syscollector -----

    def get_agent_processes(self, agent_id: str, limit: int = 500) -> list[dict]:
        """Get running processes for an agent via syscollector."""
        try:
            result = self._get(f"/syscollector/{agent_id}/processes",
                               params={"limit": limit, "sort": "-pid"})
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("syscollector_processes_failed",
                         agent_id=agent_id, error=str(e))
            return []

    def get_agent_ports(self, agent_id: str, limit: int = 500) -> list[dict]:
        """Get open ports/network connections for an agent."""
        try:
            result = self._get(f"/syscollector/{agent_id}/ports",
                               params={"limit": limit})
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("syscollector_ports_failed",
                         agent_id=agent_id, error=str(e))
            return []

    def get_agent_packages(self, agent_id: str, limit: int = 500) -> list[dict]:
        """Get installed packages for an agent."""
        try:
            result = self._get(f"/syscollector/{agent_id}/packages",
                               params={"limit": limit, "sort": "name"})
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("syscollector_packages_failed",
                         agent_id=agent_id, error=str(e))
            return []

    def get_agent_os(self, agent_id: str) -> dict:
        """Get OS information for an agent."""
        try:
            result = self._get(f"/syscollector/{agent_id}/os")
            items = result.get("data", {}).get("affected_items", [])
            return items[0] if items else {}
        except Exception as e:
            logger.error("syscollector_os_failed",
                         agent_id=agent_id, error=str(e))
            return {}

    # ----- Compliance / SCA -----

    def get_sca_list(self, agent_id: str) -> list[dict]:
        """Get SCA policy list for an agent."""
        try:
            result = self._get(f"/sca/{agent_id}",
                               params={"limit": 50})
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("sca_list_failed", agent_id=agent_id, error=str(e))
            return []

    def get_sca_checks(self, agent_id: str, policy_id: str,
                       result_filter: str = None, limit: int = 500) -> list[dict]:
        """Get SCA check results for a specific policy."""
        try:
            params = {"limit": limit}
            if result_filter:
                params["result"] = result_filter
            result = self._get(f"/sca/{agent_id}/checks/{policy_id}",
                               params=params)
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("sca_checks_failed", agent_id=agent_id,
                         policy_id=policy_id, error=str(e))
            return []

    # ----- Host Integrity (FIM / rootcheck / registry / groups) -----

    def get_agent_syscheck(self, agent_id: str, limit: int = 500) -> list[dict]:
        """Get FIM/syscheck results for an agent."""
        try:
            result = self._get(f"/syscheck/{agent_id}",
                               params={"limit": limit})
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("syscheck_fetch_failed",
                         agent_id=agent_id, error=str(e))
            return []

    def get_agent_rootcheck(self, agent_id: str, limit: int = 500) -> list[dict]:
        """Get rootcheck (policy monitoring) results for an agent."""
        try:
            result = self._get(f"/rootcheck/{agent_id}",
                               params={"limit": limit})
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("rootcheck_fetch_failed",
                         agent_id=agent_id, error=str(e))
            return []

    def get_agent_registry(self, agent_id: str, limit: int = 500) -> list[dict]:
        """Get Windows registry entries — a registry-typed view of FIM.

        Wazuh 4.x exposes registry data through the same /syscheck endpoint,
        filtered to registry types. The query param may vary by Wazuh
        version; this is defensive and fail-safes to [] on any error.
        """
        try:
            result = self._get(
                f"/syscheck/{agent_id}",
                params={"limit": limit,
                        "q": "type=registry_key,registry_value"})
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("registry_fetch_failed",
                         agent_id=agent_id, error=str(e))
            return []

    def get_agent_groups(self, limit: int = 500) -> list[dict]:
        """Get the Manager's agent group list (Manager-global)."""
        try:
            result = self._get("/groups", params={"limit": limit})
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("agent_groups_fetch_failed", error=str(e))
            return []

    # ----- Active Response -----

    # Allowlisted commands to prevent abuse
    ALLOWED_AR_COMMANDS = frozenset([
        "firewall-drop", "host-deny", "host-isolation",
        "disable-account", "enable-account",
        "kill-process", "quarantine", "restart-wazuh",
        "dns-sinkhole", "proxy-blocklist", "email-quarantine",
        "revoke-session", "run-command",
    ])

    # Characters that indicate shell injection attempts
    DANGEROUS_CHARS = set(";&|$(){}[]`!\\")

    def _sanitize_ar_param(self, value: str) -> str:
        """Sanitize active response parameters against injection."""
        s = str(value)
        # Reject control characters (newlines, nulls, etc.)
        if any(ord(c) < 32 or ord(c) == 127 for c in s):
            raise ValueError(f"Parameter contains control characters: {value!r}")
        if any(c in self.DANGEROUS_CHARS for c in s):
            raise ValueError(f"Parameter contains forbidden characters: {value}")
        return s.strip()

    def send_active_response(self, agent_id: str, command: str,
                             arguments: list[str] = None) -> dict:
        """Send an active response command to an agent.

        Returns dict with status and message.
        Requires the command to be in the allowlist.
        """
        if command not in self.ALLOWED_AR_COMMANDS:
            return {"success": False,
                    "error": f"Command '{command}' not in allowlist: "
                             f"{sorted(self.ALLOWED_AR_COMMANDS)}"}

        agent_id = self._sanitize_ar_param(agent_id)
        # Enforce strict numeric agent ID (Wazuh uses 000, 001, ..., 99999)
        if not __import__("re").match(r"^\d{1,5}$", agent_id):
            return {"success": False,
                    "error": f"Invalid agent ID format: {agent_id}. "
                             "Must be 1-5 digits."}
        clean_args = [self._sanitize_ar_param(a) for a in (arguments or [])]

        body = {
            "command": f"!{command}",
            "arguments": clean_args,
        }

        try:
            result = self._put(f"/active-response?agents_list={agent_id}",
                               data=body)
            logger.warning("active_response_sent",
                           agent_id=agent_id, command=command,
                           arguments=clean_args)
            return {"success": True, "data": result.get("data", {})}
        except requests.HTTPError as e:
            logger.error("active_response_failed",
                         agent_id=agent_id, command=command,
                         error=str(e))
            return {"success": False, "error": str(e)}

    def block_ip(self, agent_id: str, ip_address: str,
                 timeout: int = 3600) -> dict:
        """Block an IP address via firewall-drop."""
        return self.send_active_response(
            agent_id, "firewall-drop",
            ["-srcip", ip_address, "-timeout", str(timeout)]
        )

    def unblock_ip(self, agent_id: str, ip_address: str) -> dict:
        """Unblock a previously blocked IP."""
        return self.send_active_response(
            agent_id, "firewall-drop",
            ["-srcip", ip_address, "delete"]
        )

    def isolate_host(self, agent_id: str) -> dict:
        """Isolate a host from the network."""
        return self.send_active_response(agent_id, "host-isolation", [])

    def unisolate_host(self, agent_id: str) -> dict:
        """Remove host isolation."""
        return self.send_active_response(
            agent_id, "host-isolation", ["undo"]
        )

    def kill_process(self, agent_id: str, pid: str) -> dict:
        """Kill a process by PID."""
        return self.send_active_response(
            agent_id, "kill-process", [pid]
        )

    def disable_user(self, agent_id: str, username: str) -> dict:
        """Disable a user account."""
        return self.send_active_response(
            agent_id, "disable-account", [username]
        )

    def enable_user(self, agent_id: str, username: str) -> dict:
        """Re-enable a user account."""
        return self.send_active_response(
            agent_id, "enable-account", [username]
        )

    def quarantine_file(self, agent_id: str, file_path: str) -> dict:
        """Quarantine a file."""
        return self.send_active_response(
            agent_id, "quarantine", [file_path]
        )

    def restart_agent(self, agent_id: str) -> dict:
        """Restart a Wazuh agent."""
        # Enforce strict numeric agent ID
        if not __import__("re").match(r"^\d{1,5}$", str(agent_id).strip()):
            return {"success": False,
                    "error": f"Invalid agent ID format: {agent_id}"}
        agent_id = str(agent_id).strip()
        try:
            result = self._put(f"/agents/{agent_id}/restart")
            return {"success": True, "data": result.get("data", {})}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _send_active_response(self, agent_id: str, command: str,
                              target: str, undo: bool = False) -> dict:
        """Helper for active response commands with optional undo."""
        args = [target]
        if undo:
            args.append("delete")
        return self.send_active_response(agent_id, command, args)

    def dns_sinkhole(self, agent_id: str, domain: str) -> dict:
        """Add a domain to DNS sinkhole via active response."""
        return self._send_active_response(agent_id, "dns-sinkhole", domain)

    def remove_dns_sinkhole(self, agent_id: str, domain: str) -> dict:
        """Remove a domain from DNS sinkhole."""
        return self._send_active_response(agent_id, "dns-sinkhole", domain, undo=True)

    def proxy_blocklist(self, agent_id: str, url: str) -> dict:
        """Add URL to proxy blocklist via active response."""
        return self._send_active_response(agent_id, "proxy-blocklist", url)

    def remove_proxy_block(self, agent_id: str, url: str) -> dict:
        """Remove URL from proxy blocklist."""
        return self._send_active_response(agent_id, "proxy-blocklist", url, undo=True)

    def email_quarantine(self, agent_id: str, message_id: str) -> dict:
        """Quarantine an email message via active response."""
        return self._send_active_response(agent_id, "email-quarantine", message_id)

    def release_email_quarantine(self, agent_id: str, message_id: str) -> dict:
        """Release a quarantined email."""
        return self._send_active_response(agent_id, "email-quarantine", message_id, undo=True)

    def revoke_session(self, agent_id: str, user: str) -> dict:
        """Revoke all active sessions for a user."""
        return self._send_active_response(agent_id, "revoke-session", user)

    def restore_session(self, agent_id: str, user: str) -> dict:
        """Restore session capability for a user."""
        return self._send_active_response(agent_id, "revoke-session", user, undo=True)
