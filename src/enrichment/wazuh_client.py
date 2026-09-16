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


class WazuhRuleFileUnavailable(Exception):
    """We could not establish what a rule file currently contains.

    Raised to FAIL CLOSED, and deliberately distinct from a rule file that is
    genuinely not there (``get_rule_file_content`` returns ``None`` for that,
    and only when the manager positively said so).

    The two used to collapse into the same ``None`` (WO-H92): a network
    timeout, an auth failure or a 500 from the manager was indistinguishable
    from a clean first-ever deploy. ``_merge_into_local_rules`` read that
    ``None`` as "nothing is deployed yet", merged the new rule into an empty
    baseline, and wrote the result back over ``ai-soc-tuned.xml`` — deleting
    every previously approved and deployed tuned rule, with no error.

    Callers that legitimately treat absence as "start fresh" keep doing that on
    ``None``. They must NOT treat this exception the same way.
    """


class WazuhClient:
    """Client for the Wazuh Manager REST API."""

    # ── the rule-validation probe file ───────────────────────────────────
    # ONE definition. ``LOGTEST_TEMP_FILE`` used to sit here as a full path and
    # be referenced by NOTHING, while the code that actually validates rules
    # hardcoded the bare filename 60 lines further down. Two spellings of one
    # fact is how a second probe filename appears, and a second filename is not
    # cosmetic here — see below.
    #
    # WHY THE NAME MATTERS OUTSIDE THIS FILE (WO-H97). Writing this file into
    # the manager's live rules directory trips the estate's own
    # ``SIEM TAMPERING: detection rule/decoder file changed on the manager``
    # detection (rule 110128, level 12). Measured on the live tenant
    # 2026-08-24, 152 of 176 such alerts — 86% — are DHRUVA writing and
    # deleting its OWN probe files, and 6 of those escaped the estate's
    # suppression rule because they carried a SECOND filename
    # (``_dhruva_logtest_probe.xml``, added by a local patch) that the
    # suppression did not know about. Anything that suppresses, excludes or
    # explains this noise is keyed on the name, so the name has to come from
    # here and nowhere else.
    #
    # THE DIRECTORY IS NOT A CHOICE. Both validation layers require the probe
    # to be inside the manager's loaded ruleset:
    #   * layer 1 uploads via ``PUT /rules/files/{filename}``, which defaults to
    #     /var/ossec/etc/rules/. Wazuh 4.3+ DOES accept a ``relative_dirname``
    #     parameter — the earlier claim here that no path parameter exists was
    #     wrong — but it is constrained to a directory already declared as a
    #     ``<rule_dir>`` in ossec.conf. Using it means adding a rule_dir to
    #     every customer's manager config, which is a deployment change and its
    #     own work order, not a severity fix.
    #   * layer 2 runs ``wazuh-logtest``, which only exercises rules that
    #     analysisd has LOADED. A probe outside the ruleset is not loaded, so
    #     logtest cannot test it — which is the whole point of layer 2.
    # Moving the file therefore means giving up the two-layer validation that
    # stops the Detection Agent writing broken XML into a live shared ruleset
    # (WO-H62, WO-H64). If that trade is ever made, it is its own work order.
    LOGTEST_TEMP_FILENAME = "_ai_soc_validation_temp.xml"
    LOGTEST_RULES_DIR = "/var/ossec/etc/rules"
    LOGTEST_TEMP_FILE = f"{LOGTEST_RULES_DIR}/{LOGTEST_TEMP_FILENAME}"
    LOGTEST_BIN = "/var/ossec/bin/wazuh-logtest"

    def __init__(self, host: str, port: int = 55000, username: str = "",
                 password: str = "", verify_ssl: bool = True,
                 ssh_user: str = "", ssh_password: str = "",
                 ssh_key_path: str = "", ssh_key_passphrase: str = "",
                 ssh_sudo_nopasswd: bool = False,
                 tls_insecure_hostname: bool = False,
                 ssh_host: str = ""):
        # Belt-and-suspenders: if the operator (or wizard) supplied a host
        # that already contains an explicit ":<port>" suffix, do not
        # duplicate it — that produced "https://10.0.0.5:55000:55000" and
        # a "Failed to parse URL" on a client install.
        self.base_url = self._build_base_url(host, port)
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.tls_insecure_hostname = tls_insecure_hostname
        self._session = self._build_session(tls_insecure_hostname)
        self._token: Optional[str] = None
        self._token_expiry: float = 0
        self._agent_cache = TTLCache(maxsize=500, ttl=300)

        # SSH config for wazuh-logtest validation.
        #
        # `ssh_host` wins when set; otherwise fall back to the API host, which
        # is correct on a single-box install where the API and the manager are
        # the same machine.
        #
        # The fallback used to be the ONLY behaviour, and `config.yaml`'s
        # `ssh_host` was read by nothing (WO-H83). On a live tenant the API
        # is reached at localhost while the manager is a separate host, so every
        # rule validation SSH'd into the box it was already running on:
        # `wazuh_logtest_ssh_error error="Server 'localhost' not found in
        # known_hosts"`, 122 times in 3 days. `service.py` passed every OTHER
        # ssh_* setting through and omitted this one, so the key looked
        # supported, parsed fine, and did nothing.
        #
        # That mattered beyond the error count: wazuh-logtest is the LAYER-2
        # check that stops the Detection Agent writing broken XML into a live
        # shared ruleset (WO-H62, WO-H64). Unreachable, the agent spent five LLM
        # auto-fix rounds per proposal rewriting XML to satisfy a validator it
        # never reached, then parked the result as "manual tuning required" —
        # indistinguishable from a genuinely bad rule.
        _api_derived = re.sub(r'^https?://', '', host).split(':')[0]
        self._ssh_host = (ssh_host or "").strip() or _api_derived
        if ssh_host and self._ssh_host != _api_derived:
            logger.info("wazuh_logtest_ssh_host_override",
                        ssh_host=self._ssh_host, api_host=_api_derived)
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
        a failure mode seen on a client install: Wazuh's default API cert ships with
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

    # ----- Manager Statistics -----

    def get_analysisd_stats(self) -> Optional[dict]:
        """Live ``wazuh-analysisd`` counters, or ``None`` when unreadable.

        WO-H109. This is the only place in the stack that can answer "did an
        event fail to decode". The alerts index cannot: a document only exists
        there because a RULE matched, so an event that no decoder parsed and
        no rule matched never lands in it at all. analysisd counts the events
        it received and the events it decoded, and the gap between them is the
        real figure.

        Returns the counter dict verbatim (``events_received``,
        ``total_events_decoded``, ``events_dropped``, the per-type
        ``*_events_decoded``, and the ``*_queue_usage`` / ``*_queue_size``
        gauges). Every value Wazuh sends is a float; callers coerce.

        ``None`` means "we could not read it" and must NEVER be read as
        "healthy" — that is the WO-H105 lesson applied to a second data
        source. An empty ``affected_items`` is the same thing: the API
        answered, but not with a measurement.

        Counters are CUMULATIVE since analysisd last started, not windowed,
        and they reset to zero on restart. Anything deriving a rate from them
        has to difference consecutive readings and cope with the reset.

        Single node only: ``/manager/...`` reports the node this API serves.
        A clustered install would need ``/cluster/{node}/stats/analysisd`` per
        worker; no current deployment is clustered, so that is not built.
        """
        try:
            result = self._get("/manager/stats/analysisd")
            items = result.get("data", {}).get("affected_items", [])
            if not items or not isinstance(items[0], dict):
                logger.warning("wazuh_analysisd_stats_empty",
                               total_affected=result.get("data", {})
                               .get("total_affected_items"))
                return None
            return items[0]
        except Exception as e:                       # noqa: BLE001
            logger.error("wazuh_analysisd_stats_failed", error=str(e)[:300],
                         error_type=type(e).__name__)
            return None

    def get_cluster_status(self) -> Optional[dict]:
        """``{"enabled": "yes"/"no", "running": ...}``, or ``None``.

        WO-H109 audit. ``/manager/stats/analysisd`` reports the node this API
        serves and nothing else, so on a clustered manager one worker's
        counters would be presented as the whole estate's decode rate with no
        indication that the other workers were never asked. This exists so
        the health monitor can SAY so rather than quietly under-reporting.

        ``None`` means we could not tell — which is not "not clustered", and
        callers must not treat it as such.
        """
        try:
            result = self._get("/cluster/status")
            data = result.get("data", {})
            if not isinstance(data, dict) or not data:
                return None
            return data
        except Exception as e:                       # noqa: BLE001
            logger.warning("wazuh_cluster_status_failed", error=str(e)[:200],
                           error_type=type(e).__name__)
            return None

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

    def get_used_rule_ids(self) -> set[int]:
        """Every rule ID currently defined on the manager (WO-H65).

        Used to keep a generated tuning rule from claiming an ID that is
        already live. A duplicate ID makes the Wazuh ruleset fail to compile,
        which can stop ``wazuh-analysisd`` loading — i.e. alert processing
        stops. Observed twice on a live install, 2026-08-03/04.

        Returns an EMPTY set on failure. Callers must treat that as "unknown"
        and NOT as "nothing is taken" — see
        ``DetectionAgent._reassign_colliding_rule_ids``, which skips
        reassignment entirely rather than risk renumbering against a phantom
        empty ruleset.
        """
        ids: set[int] = set()
        try:
            offset, limit = 0, 500
            while True:
                result = self._get("/rules", params={
                    "limit": limit, "offset": offset, "select": "id",
                })
                items = result.get("data", {}).get("affected_items", [])
                for item in items:
                    try:
                        ids.add(int(item["id"]))
                    except (KeyError, TypeError, ValueError):
                        continue
                total = result.get("data", {}).get("total_affected_items", 0)
                offset += limit
                if offset >= total or not items:
                    break
            logger.info("wazuh_rule_ids_loaded", count=len(ids))
        except Exception as e:
            logger.warning("wazuh_rule_ids_fetch_failed", error=str(e))
            return set()
        return ids

    # ----- Rule Files (for detection engineering) -----

    def get_rule_file_content(self, filename: str) -> Optional[str]:
        """Get raw XML content of a rule file.

        Returns:
            ``str`` — the file's contents, or
            ``None`` — the manager answered and the file is NOT THERE.

        Raises:
            WazuhRuleFileUnavailable — we could not find out what the file
            contains (timeout, auth failure, 5xx, unreadable response). This is
            never the same answer as ``None``: see WO-H92. A caller about to
            rewrite a rule file must abort on this, not treat it as an empty
            starting point.
        """
        try:
            # Use raw=true to get the actual XML string, not parsed dict
            resp = self._session.get(
                f"{self.base_url}/rules/files/{filename}",
                headers=self._headers(),
                params={"raw": "true"},
                verify=self.verify_ssl,
                timeout=30
            )
            # A 404 is the manager telling us the file is absent — an answer,
            # not a failure. Checked before raise_for_status, which would
            # otherwise turn it into an indistinguishable transport error.
            if getattr(resp, "status_code", None) == 404:
                logger.info("wazuh_rulefile_not_found", filename=filename,
                            status_code=404)
                return None
            resp.raise_for_status()
            text = resp.text
            # Wazuh may return JSON error body even with raw=true for missing
            # files. Reached only on a 2xx, so the manager answered: absent.
            if text.lstrip().startswith('{'):
                logger.info("wazuh_rulefile_not_found", filename=filename)
                return None
            return text
        except Exception as e:
            logger.error("wazuh_rulefile_fetch_failed", filename=filename,
                         error=str(e)[:200],
                         detail="could not establish the file's current "
                                "contents; raising rather than reporting it "
                                "as absent")
            raise WazuhRuleFileUnavailable(
                f"could not read rule file {filename}: {str(e)[:200]}") from e

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

            # WO-H64: feed the test event over STDIN, never inside a shell
            # string.
            #
            # This used to build `sudo bash -c 'echo <shlex.quote(log)> | ...'`.
            # shlex.quote wraps the log in SINGLE quotes, which then collide
            # with the single quotes of `bash -c '...'` — the nesting collapses
            # and bash receives only `echo Apr`. The pipe to wazuh-logtest was
            # severed, so this function returned the literal string "Apr\n"
            # every single time.
            #
            # "Apr\n" contains none of the error keywords the caller greps for,
            # so layer-2 validation ALWAYS reported success. It has therefore
            # never actually validated anything: every rule was checked by the
            # Wazuh API alone (layer 1), whose only verdict is the generic
            # "XML syntax error". Confirmed on a live install 2026-08-04 —
            # `_ssh_run_logtest()` returned `'Apr\n'` (4 bytes) for a rule that
            # logtest, run by hand, rejects with
            # `Invalid option 'frequency' for rule '100998'`.
            #
            # Passing the event on stdin removes shell quoting from the picture
            # entirely, so there is nothing left to escape or to inject through.
            test_log = "Apr 1 00:00:00 test sshd[1]: test"
            sudo_flag = "-n" if self._ssh_sudo_nopasswd else "-S"
            cmd = f"sudo {sudo_flag} {self.LOGTEST_BIN} -q 2>&1"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
            if not self._ssh_sudo_nopasswd:
                # `sudo -S` consumes the FIRST stdin line as the password;
                # logtest then reads the event from what follows.
                stdin.write(self._ssh_password + "\n")
            stdin.write(test_log + "\n")
            stdin.flush()
            try:
                stdin.channel.shutdown_write()
            except Exception:
                # WO-H90 reviewed, left silent on purpose: cleanup on an SSH
                # channel we are done writing to and that `finally: client.close()`
                # below is about to tear down anyway. Nothing is lost if this
                # fails, and the real logtest result is still read and returned.
                pass

            stdout.channel.recv_exit_status()
            return stdout.read().decode()
        finally:
            client.close()

    def _logtest_error_detail(self) -> str:
        """Best-effort: ask wazuh-logtest for the SPECIFIC rule error (WO-H62).

        The Wazuh API reports a generic "XML syntax error" for anything it
        rejects, including rule-LOGIC faults on well-formed XML. logtest gives
        the real reason (e.g. ``Invalid option 'frequency' for rule '100502'``),
        which is what the self-repair loop actually needs to fix anything.

        Never raises: this runs on an error path, and losing the fallback
        message would be worse than losing the detail.
        """
        if not self._ssh_user:
            return ""
        try:
            return self._extract_logtest_errors(self._ssh_run_logtest())
        except Exception as e:
            logger.debug("logtest_detail_unavailable", error=str(e))
            return ""

    @staticmethod
    def _extract_logtest_errors(output: str) -> str:
        """Pull the error lines out of wazuh-logtest output. Pure; never raises."""
        lines = [
            line.strip() for line in (output or "").splitlines()
            if any(kw in line for kw in (
                'ERROR:', 'CRITICAL:', 'XMLERR:', 'is duplicated',
                'Invalid configuration', 'Invalid option',
                'Invalid day format', 'Configuration error',
            ))
        ]
        return '; '.join(lines[:5])

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
            # WO-H90 reviewed, left silent on purpose: the (False, error) tuple
            # is consumed by validate_rule_with_logtest(), which logs it as
            # `wazuh_rule_validation_failed` with the recovered detail. Logging
            # here as well would double-report every rejected rule proposal.
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

        # From the class constant — see LOGTEST_TEMP_FILENAME for why there is
        # exactly one spelling of this name in the codebase.
        temp_filename = self.LOGTEST_TEMP_FILENAME

        try:
            # Layer 1: Upload via Wazuh API (catches XML syntax errors)
            uploaded, api_error = self._upload_temp_rule(
                temp_filename, xml_to_validate
            )
            _dev_mode = __import__("os").environ.get(
                "DEV_MODE", "").lower() in ("1", "true", "yes")

            if not uploaded:
                if api_error:
                    # WO-H62: the Wazuh API's message is GENERIC — it says
                    # "XML syntax error" for anything it dislikes, including
                    # rule-LOGIC errors where the XML is perfectly well-formed.
                    # Returning that verbatim is what stalled the self-repair
                    # loop: the fix-agent was told "XML syntax error" for a rule
                    # whose real fault was `Invalid option 'frequency' for rule
                    # '100502'` (frequency requires if_matched_sid, not if_sid).
                    # It cannot fix what it cannot see, so it burned all 5
                    # attempts and the proposal was parked as
                    # needs_manual_tuning. Five proposals sat that way for weeks.
                    #
                    # Wazuh WRITES the file even when it reports the error, so
                    # wazuh-logtest can still be asked for the specific reason.
                    # Best-effort: if it yields nothing, fall back to the
                    # generic message rather than losing the error entirely.
                    detailed = self._logtest_error_detail()
                    error_out = detailed or api_error
                    logger.warning("wazuh_rule_validation_failed",
                                   layer="api", error=error_out,
                                   api_error=api_error,
                                   detail_recovered=bool(detailed))
                    return False, error_out
                if _dev_mode:
                    logger.warning("wazuh_validation_upload_error",
                                   detail="Validation skipped (fail-open, DEV_MODE)")
                    return True, ""
                logger.warning("wazuh_validation_upload_error",
                               detail="Validation skipped — routing to manual review (fail-closed)")
                return False, "Wazuh API unavailable for validation — manual review required"

            # Layer 2: wazuh-logtest via SSH (catches rule LOGIC errors that
            # only surface when analysisd loads the ruleset). Cleanup now lives
            # on the outer finally, so this no longer needs its own try.
            #
            # Calls SSH DIRECTLY rather than via _logtest_error_detail(): that
            # helper deliberately swallows exceptions because it runs on an
            # error path, and swallowing here would turn a genuine SSH failure
            # into a silent PASS. SSH validation must fail CLOSED.
            error_msg = ""
            if self._ssh_user:
                error_msg = self._extract_logtest_errors(self._ssh_run_logtest())
            if error_msg:
                logger.warning("wazuh_rule_validation_failed",
                               layer="logtest", error=error_msg)
                return False, error_msg

            logger.info("wazuh_rule_validation_passed")
            return True, ""

        except (paramiko.SSHException, OSError, TimeoutError) as e:
            logger.warning("wazuh_logtest_ssh_error", error=str(e))
            if _dev_mode:
                logger.warning("ssh_validation_skipped_dev_mode")
                return True, ""
            return False, f"SSH validation unavailable — manual review required: {e}"
        except Exception as e:
            logger.warning("wazuh_validation_unexpected_error", error=str(e))
            if _dev_mode:
                return True, ""
            return False, f"Validation error — manual review required: {e}"
        finally:
            # WO-H62: ALWAYS remove the probe file, on EVERY path out.
            #
            # The cleanup used to sit on the INNER try, which is only entered
            # when the API upload succeeded. On an upload FAILURE the function
            # returned early and never cleaned up — and Wazuh writes the file
            # even when it reports an error. So a failed validation left broken
            # XML in the LIVE ruleset, which then broke every SUBSEQUENT
            # validation and would have broken analysisd on the next restart.
            # Observed exactly that on a live install, 2026-08-03.
            try:
                self._delete_rule_file(temp_filename)
            except Exception as _cleanup_err:
                logger.error("wazuh_validation_temp_cleanup_failed",
                             filename=temp_filename, error=str(_cleanup_err),
                             detail="A broken probe rule may remain in the LIVE "
                                    "ruleset — remove it before restarting the "
                                    "manager.")

    # ----- Vulnerability & SCA -----

    def get_agent_vulnerabilities(self, agent_id: str) -> list[dict]:
        """Get vulnerability data for an agent via the Manager API.

        DEPRECATED (WO-H11): the Manager endpoint ``GET /vulnerability/{agent}``
        was REMOVED in Wazuh 4.8+ and 404s on modern stacks. The M4
        vuln-context enricher no longer calls this — it reads the vuln STATE
        index (``wazuh-states-vulnerabilities-*``) from OpenSearch instead (see
        ``VulnerabilityContextEnricher._fetch_vulns`` /
        ``OpenSearchClient.get_vulnerabilities``). Retained only for backward
        compatibility with any legacy caller on a pre-4.8 Manager.
        """
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

    def get_agent_packages(self, agent_id: str, limit: int = 500,
                           name: str = None) -> list[dict]:
        """Get installed packages for an agent.

        When ``name`` is given, the Wazuh API is filtered to that EXACT package
        name (``q=name=<pkg>``) so the target is returned regardless of the
        agent's total package count. Without it, the historical behavior is
        preserved: the first ``limit`` packages sorted by name (WO-H40: that
        top-N slice truncates large inventories, so a package sorting past the
        limit was falsely reported "not found" — by-name lookup fixes that for
        the CVE-remediation before/after version checks)."""
        try:
            params = {"limit": limit, "sort": "name"}
            if name:
                # Exact-match filter — Wazuh's query grammar; keeps the result
                # to the one package regardless of inventory size.
                params["q"] = f"name={name}"
            result = self._get(f"/syscollector/{agent_id}/packages",
                               params=params)
            return result.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("syscollector_packages_failed",
                         agent_id=agent_id, error=str(e))
            return []

    def get_agent_package_version(self, agent_id: str,
                                  package_name: str) -> str | None:
        """Resolve the installed version of ONE package by exact name, or None
        if it is not installed. Queries the Wazuh API by name (WO-H40) instead
        of scanning a truncated top-N list, so it is correct on agents with
        more than ``limit`` packages. Exact-matches by name in the returned
        items as a belt-and-suspenders check against a substring filter."""
        for p in self.get_agent_packages(agent_id, name=package_name):
            if p.get("name", "").lower() == package_name.lower():
                return p.get("version")
        return None

    # WO-H69 phase 3: the directory active-response scripts must live in, and a
    # script Wazuh ships on EVERY agent. The stock script is the probe for "is
    # this directory monitored by FIM at all" — without it we cannot tell a
    # genuinely absent script from one we simply cannot see, and reporting those
    # two the same way is how a missing script becomes a phantom success.
    AR_BIN_DIR = "/var/ossec/active-response/bin"
    AR_STOCK_PROBE = "firewall-drop"

    def get_agent_file_hash(self, agent_id: str, path: str) -> str | None:
        """SHA-256 of one file on an agent, as last recorded by FIM (syscheck).

        Returns None when the file is not in the agent's FIM inventory — which
        means EITHER it is absent OR the path is not monitored. The caller must
        disambiguate (see ``ar_script_state``); they are not the same thing.

        Read-only: this needs `syscheck:read` and adds no privilege. Note the
        reading is as fresh as the agent's last FIM scan (default every 12h
        unless the directory is configured ``realtime="yes"``).
        """
        try:
            result = self._get(f"/syscheck/{agent_id}",
                               params={"file": path, "select": "file,sha256",
                                       "limit": 1})
            for item in result.get("data", {}).get("affected_items", []):
                if item.get("file") == path:
                    return item.get("sha256") or None
        except Exception as e:
            logger.warning("syscheck_file_hash_failed",
                           agent_id=agent_id, path=path, error=str(e))
        return None

    def ar_script_state(self, agent_id: str, script_name: str,
                        expected_sha256: str | None) -> dict:
        """Whether an agent is running the AR script we expect it to.

        States, and why each exists:
          * ``current``    — hash matches what we ship.
          * ``stale``      — present but a DIFFERENT build. A remediation will
                             run the old script and can report a phantom success.
          * ``missing``    — the directory IS monitored and the script is not
                             there. A remediation dispatches and does nothing.
          * ``unmonitored``— FIM does not cover the AR directory, so we cannot
                             see anything. Reported honestly as "cannot tell",
                             never folded into ``current``.
          * ``unknown``    — we ship no reference hash to compare against.
        """
        path = f"{self.AR_BIN_DIR}/{script_name}"
        observed = self.get_agent_file_hash(agent_id, path)

        if observed and expected_sha256:
            state = "current" if observed == expected_sha256 else "stale"
            return {"agent_id": agent_id, "state": state,
                    "observed_sha256": observed,
                    "expected_sha256": expected_sha256, "path": path}

        if observed and not expected_sha256:
            return {"agent_id": agent_id, "state": "unknown",
                    "observed_sha256": observed, "expected_sha256": None,
                    "path": path,
                    "detail": "the script is present but DHRUVA has no "
                              "reference copy to compare it against"}

        # Nothing came back. Absent, or invisible? Probe with a script Wazuh
        # puts on every agent: if THAT is not in FIM either, the directory is
        # simply not monitored and we know nothing about this agent.
        probe = self.get_agent_file_hash(
            agent_id, f"{self.AR_BIN_DIR}/{self.AR_STOCK_PROBE}")
        if probe is None:
            return {"agent_id": agent_id, "state": "unmonitored",
                    "observed_sha256": None,
                    "expected_sha256": expected_sha256, "path": path,
                    "detail": (
                        f"{self.AR_BIN_DIR} is not covered by file integrity "
                        f"monitoring on this agent, so DHRUVA cannot tell "
                        f"whether the script is installed. This is NOT a "
                        f"statement that it is fine.")}

        return {"agent_id": agent_id, "state": "missing",
                "observed_sha256": None,
                "expected_sha256": expected_sha256, "path": path,
                "detail": ("the active-response directory is monitored and this "
                           "script is not in it — a remediation dispatched to "
                           "this agent will not apply anything")}

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
        # WO-H38: the SAFE CVE-remediation upgrade script (validates the
        # package name + only does --only-upgrade). execute_remediation
        # dispatches this command name instead of run-command so the shipped
        # ossec.conf registration (deploy/wazuh/active-response) is actually
        # what runs.
        "dhruva-pkg-upgrade",
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
        except Exception as e:                           # noqa: BLE001
            # WO-H90: was a silent `return {"success": False, ...}`. `_put()`
            # does not log, so an agent restart that never happened left no
            # trace in the log at all — only a row in the AR audit table that
            # nobody reads until an incident review. On-call could not tell a
            # restarted agent from an unreachable manager.
            logger.warning("wazuh_agent_restart_failed",
                           agent_id=agent_id, error=str(e)[:200])
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
