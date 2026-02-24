import atexit
import json
import re
import subprocess
import threading
import time
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from config import (
    DEBUG,
    SSL_CERT_FILE,
    SSL_KEY_FILE,
    XRAY_API_HOST,
    XRAY_API_PORT,
    INBOUNDS,
    XRAY_LOG_DIR,
    XRAY_ASSETS_PATH,
)
from logger import logger


LOG_CLEANUP_INTERVAL_DISABLED = 0
LOG_CLEANUP_INTERVAL_OPTIONS_SECONDS = (
    LOG_CLEANUP_INTERVAL_DISABLED,
    3600,
    10800,
    21600,
    86400,
)
VERIFY_PEER_CERT_BY_NAME_MIN_VERSION = "26.1.31"


def normalize_log_cleanup_interval(value) -> int:
    if value is None:
        return LOG_CLEANUP_INTERVAL_DISABLED
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return LOG_CLEANUP_INTERVAL_DISABLED
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return LOG_CLEANUP_INTERVAL_DISABLED
    if parsed in LOG_CLEANUP_INTERVAL_OPTIONS_SECONDS:
        return parsed
    return LOG_CLEANUP_INTERVAL_DISABLED


def _first_non_empty_string(value) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (list, tuple, set)):
        for item in value:
            candidate = str(item).strip()
            if candidate:
                return candidate
        return ""
    if value is None:
        return ""
    return str(value).strip()


def _normalize_name_list(value) -> list[str]:
    if isinstance(value, str):
        candidate = value.strip()
        return [candidate] if candidate else []
    if isinstance(value, (list, tuple, set)):
        names = [str(item).strip() for item in value]
        return [name for name in names if name]
    return []


def _parse_version_parts(version: Optional[str]) -> Optional[list[int]]:
    if not version:
        return None
    match = re.search(r"(\d+(?:\.\d+)+)", str(version))
    raw = match.group(1) if match else str(version)
    try:
        return [int(part) for part in raw.split(".")]
    except (TypeError, ValueError):
        return None


def is_xray_version_at_least(current_version: Optional[str], target_version: str) -> bool:
    current_parts = _parse_version_parts(current_version)
    target_parts = _parse_version_parts(target_version)
    if not current_parts or not target_parts:
        # Keep modern behavior when version cannot be determined.
        return True

    max_len = max(len(current_parts), len(target_parts))
    current_parts.extend([0] * (max_len - len(current_parts)))
    target_parts.extend([0] * (max_len - len(target_parts)))
    return tuple(current_parts) >= tuple(target_parts)


def normalize_tls_verify_peer_cert_fields(
    tls_settings: dict,
    *,
    use_verify_peer_cert_by_name: bool = True,
) -> dict:
    """
    Normalize TLS verify-peer fields by target Xray compatibility.

    - Newer Xray: use `verifyPeerCertByName` (string), remove old key.
    - Older Xray: use `verifyPeerCertInNames` (list), remove new key.
    """
    if not isinstance(tls_settings, dict):
        return {}

    normalized = dict(tls_settings)
    by_name = _first_non_empty_string(normalized.get("verifyPeerCertByName"))
    in_names = _normalize_name_list(normalized.get("verifyPeerCertInNames"))

    if not by_name and in_names:
        by_name = in_names[0]
    if not in_names and by_name:
        in_names = [by_name]

    if use_verify_peer_cert_by_name:
        if by_name:
            normalized["verifyPeerCertByName"] = by_name
        else:
            normalized.pop("verifyPeerCertByName", None)
        normalized.pop("verifyPeerCertInNames", None)
    else:
        if in_names:
            normalized["verifyPeerCertInNames"] = in_names
        else:
            normalized.pop("verifyPeerCertInNames", None)
        normalized.pop("verifyPeerCertByName", None)
    return normalized


class XRayConfig(dict):
    """
    Loads Xray config json
    config must contain an inbound with the API_INBOUND tag name which handles API requests
    """

    def __init__(self, config: str, peer_ip: str, xray_version: Optional[str] = None):
        config = json.loads(config)

        self.api_host = XRAY_API_HOST
        self.api_port = XRAY_API_PORT
        self.ssl_cert = SSL_CERT_FILE
        self.ssl_key = SSL_KEY_FILE
        self.peer_ip = peer_ip
        self.xray_version = xray_version

        super().__init__(config)
        self._migrate_deprecated_configs()
        self._apply_api()

    def to_json(self, **json_kwargs):
        self._migrate_deprecated_configs()
        return json.dumps(self, **json_kwargs)

    def _migrate_deprecated_configs(self):
        use_verify_peer_cert_by_name = is_xray_version_at_least(
            self.xray_version, VERIFY_PEER_CERT_BY_NAME_MIN_VERSION
        )

        def _migrate_stream(stream):
            if not isinstance(stream, dict):
                return
            tls_settings = stream.get("tlsSettings")
            if isinstance(tls_settings, dict):
                stream["tlsSettings"] = normalize_tls_verify_peer_cert_fields(
                    tls_settings,
                    use_verify_peer_cert_by_name=use_verify_peer_cert_by_name,
                )

        for inbound in self.get("inbounds", []):
            _migrate_stream(inbound.get("streamSettings"))

        for outbound in self.get("outbounds", []):
            _migrate_stream(outbound.get("streamSettings"))

    def _apply_api(self):
        for inbound in self.get("inbounds", []).copy():
            if inbound.get("protocol") == "dokodemo-door" and inbound.get("tag") == "API_INBOUND":
                self["inbounds"].remove(inbound)

            elif INBOUNDS and inbound.get("tag") not in INBOUNDS:
                self["inbounds"].remove(inbound)

        for rule in self.get("routing", {}).get("rules", []):
            api_tag = self.get("api", {}).get("tag")
            if api_tag and rule.get("outboundTag") == api_tag:
                self["routing"]["rules"].remove(rule)

        self["api"] = {"services": ["HandlerService", "StatsService", "LoggerService"], "tag": "API"}
        self["stats"] = {}
        inbound = {
            "listen": self.api_host,
            "port": self.api_port,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {"certificates": [{"certificateFile": self.ssl_cert, "keyFile": self.ssl_key}]},
            },
            "tag": "API_INBOUND",
        }
        try:
            self["inbounds"].insert(0, inbound)
        except KeyError:
            self["inbounds"] = []
            self["inbounds"].insert(0, inbound)

        rule = {
            "inboundTag": ["API_INBOUND"],
            "source": ["127.0.0.1", self.peer_ip],
            "outboundTag": "API",
            "type": "field",
        }
        try:
            self["routing"]["rules"].insert(0, rule)
        except KeyError:
            self["routing"] = {"rules": []}
            self["routing"]["rules"].insert(0, rule)


class XRayCore:
    def __init__(self, executable_path: str = "/usr/bin/xray", assets_path: str = "/usr/share/xray"):
        self.executable_path = executable_path
        self.assets_path = assets_path

        self.version = self.get_version()
        self.process = None
        self.restarting = False

        self._logs_buffer = deque(maxlen=100)
        self._temp_log_buffers = {}
        self._on_start_funcs = []
        self._on_stop_funcs = []
        self._env = {"XRAY_LOCATION_ASSET": assets_path}
        self.access_log_path: Optional[Path] = None
        self.error_log_path: Optional[Path] = None
        self.access_log_cleanup_interval = 0
        self.error_log_cleanup_interval = 0
        self._log_cleanup_lock = threading.Lock()
        self._log_cleanup_stop = threading.Event()
        self._log_cleanup_thread: Optional[threading.Thread] = None
        self._log_cleanup_targets = {}

        atexit.register(lambda: self.stop() if self.started else None)

    def get_version(self):
        cmd = [self.executable_path, "version"]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8")
        m = re.match(r"^Xray (\d+\.\d+\.\d+)", output)
        if m:
            return m.groups()[0]

    def _truncate_log_file(self, name: str, path: Path) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8"):
                pass
            logger.debug("Truncated %s log file: %s", name, path)
        except Exception as exc:
            logger.warning("Failed to truncate %s log file %s: %s", name, path, exc)

    def _log_cleanup_worker(self) -> None:
        while not self._log_cleanup_stop.wait(1):
            if not self.started:
                continue

            due = []
            now = time.time()
            with self._log_cleanup_lock:
                for name, meta in self._log_cleanup_targets.items():
                    path = meta.get("path")
                    interval = meta.get("interval")
                    next_run = meta.get("next_run")
                    if not isinstance(path, Path):
                        continue
                    if not isinstance(interval, int) or interval <= 0:
                        continue
                    if not isinstance(next_run, (int, float)):
                        continue
                    if now >= next_run:
                        due.append((name, path, interval))

            for name, path, interval in due:
                self._truncate_log_file(name, path)
                with self._log_cleanup_lock:
                    current = self._log_cleanup_targets.get(name)
                    if not current:
                        continue
                    if current.get("path") != path or current.get("interval") != interval:
                        continue
                    current["next_run"] = time.time() + interval

    def _start_log_cleanup_worker(self) -> None:
        if self._log_cleanup_thread and self._log_cleanup_thread.is_alive():
            return
        self._log_cleanup_stop.clear()
        self._log_cleanup_thread = threading.Thread(target=self._log_cleanup_worker, daemon=True)
        self._log_cleanup_thread.start()

    def _stop_log_cleanup_worker(self) -> None:
        self._log_cleanup_stop.set()
        thread = self._log_cleanup_thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=1)
        self._log_cleanup_thread = None
        with self._log_cleanup_lock:
            self._log_cleanup_targets = {}

    def _configure_log_cleanup(self) -> None:
        now = time.time()
        targets = {}
        if self.access_log_path and self.access_log_cleanup_interval > 0:
            targets["access"] = {
                "path": self.access_log_path,
                "interval": self.access_log_cleanup_interval,
                "next_run": now + self.access_log_cleanup_interval,
            }
        if self.error_log_path and self.error_log_cleanup_interval > 0:
            targets["error"] = {
                "path": self.error_log_path,
                "interval": self.error_log_cleanup_interval,
                "next_run": now + self.error_log_cleanup_interval,
            }
        with self._log_cleanup_lock:
            self._log_cleanup_targets = targets
        if targets and self.started:
            self._start_log_cleanup_worker()
        else:
            self._stop_log_cleanup_worker()

    def __capture_process_logs(self):
        def capture_and_debug_log():
            while self.process:
                output = self.process.stdout.readline()
                if output:
                    output = output.strip()
                    self._logs_buffer.append(output)
                    for buf in list(self._temp_log_buffers.values()):
                        buf.append(output)
                    logger.debug(output)

                elif not self.process or self.process.poll() is not None:
                    break

        def capture_only():
            while self.process:
                output = self.process.stdout.readline()
                if output:
                    output = output.strip()
                    self._logs_buffer.append(output)
                    for buf in list(self._temp_log_buffers.values()):
                        buf.append(output)

                elif not self.process or self.process.poll() is not None:
                    break

        if DEBUG:
            threading.Thread(target=capture_and_debug_log).start()
        else:
            threading.Thread(target=capture_only).start()

    @contextmanager
    def get_logs(self):
        buf = deque(self._logs_buffer, maxlen=100)
        buf_id = id(buf)
        try:
            self._temp_log_buffers[buf_id] = buf
            yield buf
        except (EOFError, TimeoutError):
            pass
        finally:
            del self._temp_log_buffers[buf_id]
            del buf

    @property
    def started(self):
        if not self.process:
            return False

        if self.process.poll() is None:
            return True

        return False

    def start(self, config: XRayConfig):
        if self.started is True:
            raise RuntimeError("Xray is started already")

        self._stop_log_cleanup_worker()

        if config.get("log", {}).get("logLevel") in ("none", "error"):
            config["log"]["logLevel"] = "warning"

        def _resolve_log_path(value, filename: str, base_dir: str) -> str | None:
            if value is None:
                return ""
            if isinstance(value, str):
                lowered = value.strip().lower()
                if lowered == "none":
                    return "none"
                if not value.strip():
                    return ""
                candidate = Path(value.strip())
                if not candidate.is_absolute() or candidate.parent == Path("/"):
                    return str(Path(base_dir) / candidate.name)
                return str(candidate)
            return str(Path(base_dir) / filename)

        base_log_dir = Path(XRAY_LOG_DIR or XRAY_ASSETS_PATH or "/var/log").expanduser()
        log_config = config.get("log", {}) if isinstance(config.get("log", {}), dict) else {}
        log_config.setdefault("access", "")
        log_config.setdefault("error", "")
        self.access_log_cleanup_interval = normalize_log_cleanup_interval(log_config.get("accessCleanupInterval"))
        self.error_log_cleanup_interval = normalize_log_cleanup_interval(log_config.get("errorCleanupInterval"))
        log_config["accessCleanupInterval"] = self.access_log_cleanup_interval
        log_config["errorCleanupInterval"] = self.error_log_cleanup_interval
        self.access_log_path = None
        self.error_log_path = None
        for key, fname in (("access", "access.log"), ("error", "error.log")):
            resolved = _resolve_log_path(log_config.get(key), fname, base_log_dir)
            log_config[key] = resolved
            if resolved and isinstance(resolved, str) and resolved.lower() != "none":
                try:
                    log_path = Path(resolved).expanduser()
                    log_dir = log_path.parent
                    log_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
                    log_path.touch(exist_ok=True)
                    logger.info(f"Log directory created: {log_dir}, log file: {log_path}")
                    if key == "access":
                        self.access_log_path = log_path
                    elif key == "error":
                        self.error_log_path = log_path
                except Exception as e:
                    logger.error(f"Failed to create log directory/file for {key}: {e}")
                    raise RuntimeError(f"Failed to create log directory for {key} at {resolved}: {e}")
        config["log"] = log_config

        runtime_config = json.loads(config.to_json())
        runtime_log_config = runtime_config.get("log", {}) if isinstance(runtime_config.get("log", {}), dict) else {}
        runtime_log_config.pop("accessCleanupInterval", None)
        runtime_log_config.pop("errorCleanupInterval", None)
        runtime_config["log"] = runtime_log_config

        self._env["XRAY_LOCATION_ASSET"] = str(self.assets_path)
        cmd = [self.executable_path, "run", "-config", "stdin:"]
        self.process = subprocess.Popen(
            cmd,
            env=self._env,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )
        self.process.stdin.write(json.dumps(runtime_config))
        self.process.stdin.flush()
        self.process.stdin.close()

        self._configure_log_cleanup()
        self.__capture_process_logs()

        # execute on start functions
        for func in self._on_start_funcs:
            threading.Thread(target=func).start()

    def stop(self):
        self._stop_log_cleanup_worker()

        if not self.started:
            return

        self.process.terminate()
        self.process = None
        logger.warning("Xray core stopped")
        self.access_log_path = None
        self.error_log_path = None
        self.access_log_cleanup_interval = 0
        self.error_log_cleanup_interval = 0

        # execute on stop functions
        for func in self._on_stop_funcs:
            threading.Thread(target=func).start()

    def restart(self, config: XRayConfig):
        if self.restarting is True:
            return

        self.restarting = True
        try:
            logger.warning("Restarting Xray core...")
            self.stop()
            self.start(config)
        finally:
            self.restarting = False

    def on_start(self, func: callable):
        self._on_start_funcs.append(func)
        return func

    def on_stop(self, func: callable):
        self._on_stop_funcs.append(func)
        return func
