import asyncio
import json
import time
from uuid import UUID, uuid4

from fastapi import APIRouter, Body, FastAPI, HTTPException, Request, WebSocket, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocketDisconnect

from config import (
    REBECCA_DATA_DIR,
    XRAY_ASSETS_PATH,
    XRAY_EXECUTABLE_PATH,
    NODE_SERVICE_HOST,
    NODE_SERVICE_PORT,
    NODE_SERVICE_SCHEME,
    NODE_VERSION,
)
from logger import logger
from xray import XRayConfig, XRayCore

import requests
import platform
import zipfile
import io
import os
import stat
import shutil
from pathlib import Path

app = FastAPI()


@app.exception_handler(RequestValidationError)
def validation_exception_handler(request: Request, exc: RequestValidationError):
    details = {}
    for error in exc.errors():
        details[error["loc"][-1]] = error.get("msg")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder({"detail": details}),
    )


def _update_env_envfile(env_path: Path, key: str, value: str) -> str:
    """Upsert key in .env file and return the effective value."""
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.touch(exist_ok=True)
    lines = env_path.read_text(encoding="utf-8").splitlines()
    found = False

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(f"{key}="):
            lines[i] = f'{key}="{value}"'
            found = True
            break

    if not found:
        lines.append(f'{key}="{value}"')

    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return value


class Service(object):
    def __init__(self):
        self.router = APIRouter()

        self.connected = False
        self.client_ip = None
        self.session_id = None
        self.data_dir = Path(REBECCA_DATA_DIR).expanduser().resolve()
        self.node_service_name = (os.getenv("REBECCA_NODE_SERVICE_NAME") or "rebecca-node").strip() or "rebecca-node"
        self.core = XRayCore(executable_path=XRAY_EXECUTABLE_PATH, assets_path=XRAY_ASSETS_PATH)
        self.core_version = self.core.get_version()
        self.node_version = NODE_VERSION
        self.config = None
        self._node_service_base = self._build_node_service_base()

        self.router.add_api_route("/", self.base, methods=["POST"])
        self.router.add_api_route("/ping", self.ping, methods=["POST"])
        self.router.add_api_route("/connect", self.connect, methods=["POST"])
        self.router.add_api_route("/disconnect", self.disconnect, methods=["POST"])
        self.router.add_api_route("/start", self.start, methods=["POST"])
        self.router.add_api_route("/stop", self.stop, methods=["POST"])
        self.router.add_api_route("/restart", self.restart, methods=["POST"])
        self.router.add_api_route("/update_core", self.update_core, methods=["POST"])
        self.router.add_api_route("/update_geo", self.update_geo, methods=["POST"])
        self.router.add_api_route("/maintenance/restart", self.restart_node_service, methods=["POST"])
        self.router.add_api_route("/maintenance/update", self.update_node_service, methods=["POST"])
        self.router.add_api_route("/access_logs", self.get_access_logs, methods=["POST"])

        self.router.add_websocket_route("/logs", self.logs)
        self.router.add_websocket_route("/access_logs/ws", self.access_logs_ws)

    def _build_node_service_base(self):
        host = (NODE_SERVICE_HOST or "").strip()
        scheme = (NODE_SERVICE_SCHEME or "").strip() or "http"
        if not host:
            return None

        base = f"{scheme}://{host}"
        if NODE_SERVICE_PORT:
            base = f"{base}:{NODE_SERVICE_PORT}"
        return base

    def _call_node_service(self, path: str, timeout: int = 180):
        if not self._node_service_base:
            raise HTTPException(status_code=503, detail="Node maintenance service is not configured on this node.")

        url = f"{self._node_service_base}{path}"
        try:
            res = requests.post(url, timeout=timeout)
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"Unable to reach node maintenance service: {exc}")

        try:
            data = res.json()
        except ValueError:
            data = {"detail": res.text or "Node maintenance service returned invalid response."}

        if res.status_code >= 400:
            detail = data.get("detail") if isinstance(data, dict) else data
            raise HTTPException(res.status_code, detail=detail)
        return data

    def match_session_id(self, session_id: UUID):
        if session_id != self.session_id:
            raise HTTPException(status_code=403, detail="Session ID mismatch.")
        return True

    def response(self, **kwargs):
        return {
            "connected": self.connected,
            "started": self.core.started,
            "core_version": self.core_version,
            "node_version": self.node_version,
            **kwargs,
        }

    def base(self):
        return self.response()

    def connect(self, request: Request):
        self.session_id = uuid4()
        self.client_ip = request.client.host

        if self.connected:
            logger.warning(
                f"New connection from {self.client_ip}, Core control access was taken away from previous client."
            )
            if self.core.started:
                try:
                    self.core.stop()
                except RuntimeError:
                    pass

        self.connected = True
        logger.info(f'{self.client_ip} connected, Session ID = "{self.session_id}".')

        return self.response(session_id=self.session_id)

    def disconnect(self):
        if self.connected:
            logger.info(f'{self.client_ip} disconnected, Session ID = "{self.session_id}".')

        self.session_id = None
        self.client_ip = None
        self.connected = False

        if self.core.started:
            try:
                self.core.stop()
            except RuntimeError:
                pass

        return self.response()

    def ping(self, session_id: UUID = Body(embed=True)):
        self.match_session_id(session_id)
        return {}

    def start(self, session_id: UUID = Body(embed=True), config: str = Body(embed=True)):
        self.match_session_id(session_id)

        try:
            config = XRayConfig(config, self.client_ip, xray_version=self.core_version)
        except json.decoder.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail={"config": f"Failed to decode config: {exc}"})

        self.config = config

        with self.core.get_logs() as logs:
            try:
                self.core.start(config)

                start_time = time.time()
                end_time = start_time + 3
                last_log = ""
                while time.time() < end_time:
                    while logs:
                        log = logs.popleft()
                        if log:
                            last_log = log
                        if f"Xray {self.core_version} started" in log:
                            break
                    time.sleep(0.1)

            except Exception as exc:
                logger.error(f"Failed to start core: {exc}")
                raise HTTPException(status_code=503, detail=str(exc))

        if not self.core.started:
            raise HTTPException(status_code=503, detail=last_log)

        return self.response()

    def stop(self, session_id: UUID = Body(embed=True)):
        self.match_session_id(session_id)

        try:
            self.core.stop()

        except RuntimeError:
            pass

        return self.response()

    def restart(self, session_id: UUID = Body(embed=True), config: str = Body(embed=True)):
        self.match_session_id(session_id)

        try:
            config = XRayConfig(config, self.client_ip, xray_version=self.core_version)
        except json.decoder.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail={"config": f"Failed to decode config: {exc}"})

        self.config = config

        try:
            with self.core.get_logs() as logs:
                if self.core.started:
                    try:
                        self.core.stop()
                        time.sleep(0.5)
                    except RuntimeError:
                        pass
                self.core.restart(config)

                start_time = time.time()
                end_time = start_time + 3
                last_log = ""
                while time.time() < end_time:
                    while logs:
                        log = logs.popleft()
                        if log:
                            last_log = log
                        if f"Xray {self.core_version} started" in log:
                            break
                    time.sleep(0.1)

        except Exception as exc:
            logger.error(f"Failed to restart core: {exc}")
            raise HTTPException(status_code=503, detail=str(exc))

        if not self.core.started:
            raise HTTPException(status_code=503, detail=last_log)

        return self.response()

    async def logs(self, websocket: WebSocket):
        session_id = websocket.query_params.get("session_id")
        interval = websocket.query_params.get("interval")

        try:
            session_id = UUID(session_id)
            if session_id != self.session_id:
                return await websocket.close(reason="Session ID mismatch.", code=4403)

        except ValueError:
            return await websocket.close(reason="session_id should be a valid UUID.", code=4400)

        if interval:
            try:
                interval = float(interval)
            except ValueError:
                return await websocket.close(reason="Invalid interval value", code=4400)

            if interval > 10:
                return await websocket.close(reason="Interval must be more than 0 and at most 10 seconds", code=4400)

        await websocket.accept()

        cache = ""
        last_sent_ts = 0
        with self.core.get_logs() as logs:
            while session_id == self.session_id:
                if interval and time.time() - last_sent_ts >= interval and cache:
                    try:
                        await websocket.send_text(cache)
                    except (WebSocketDisconnect, RuntimeError):
                        break
                    cache = ""
                    last_sent_ts = time.time()

                if not logs:
                    try:
                        await asyncio.wait_for(websocket.receive(), timeout=0.2)
                        continue
                    except asyncio.TimeoutError:
                        continue
                    except (WebSocketDisconnect, RuntimeError):
                        break

                log = logs.popleft()

                if interval:
                    cache += f"{log}\n"
                    continue

                try:
                    await websocket.send_text(log)
                except (WebSocketDisconnect, RuntimeError):
                    break

        await websocket.close()

    def _detect_asset_name(self):
        sys = platform.system().lower()
        arch = platform.machine().lower()
        if sys.startswith("linux"):
            if arch in ("x86_64", "amd64"):
                return "Xray-linux-64.zip"
            if arch in ("aarch64", "arm64"):
                return "Xray-linux-arm64-v8a.zip"
            if arch in ("armv7l", "armv7"):
                return "Xray-linux-arm32-v7a.zip"
            if arch in ("armv6l",):
                return "Xray-linux-arm32-v6.zip"
            if arch in ("riscv64",):
                return "Xray-linux-riscv64.zip"
        raise HTTPException(status_code=400, detail="Unsupported platform for node")

    def _install_zip_to(self, zip_bytes: bytes, target_dir: str):
        os.makedirs(target_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            z.extractall(target_dir)
        exe = os.path.join(target_dir, "xray")
        if platform.system().lower().startswith("windows"):
            exe = os.path.join(target_dir, "xray.exe")
        if not os.path.exists(exe):
            alt = os.path.join(target_dir, "Xray")
            alt_win = os.path.join(target_dir, "Xray.exe")
            exe = alt if os.path.exists(alt) else (alt_win if os.path.exists(alt_win) else exe)
        if not os.path.exists(exe):
            raise HTTPException(500, detail="xray binary not found in archive")
        try:
            st = os.stat(exe)
            os.chmod(exe, st.st_mode | stat.S_IEXEC)
        except Exception:
            pass
        return exe

    def _download_files_to(self, path: Path, files: list[dict]) -> list[dict]:
        """
        Download list of {name,url} into the given path.
        Returns list of saved files with absolute path.
        """
        saved = []
        for item in files:
            name = (item.get("name") or "").strip()
            url = (item.get("url") or "").strip()
            if not name or not url:
                raise HTTPException(422, detail="Each file must include non-empty 'name' and 'url'.")
            try:
                r = requests.get(url, timeout=120)
                r.raise_for_status()
            except Exception as e:
                raise HTTPException(502, detail=f"Failed to download {name}: {e}")
            dst = path / name
            try:
                with open(dst, "wb") as f:
                    f.write(r.content)
            except Exception as e:
                raise HTTPException(500, detail=f"Failed to save {name}: {e}")
            saved.append({"name": name, "path": str(dst)})
        return saved

    def _xray_dir(self) -> Path:
        target = (self.data_dir / "xray-core").resolve()
        target.mkdir(parents=True, exist_ok=True)
        return target

    def _persist_xray_env(self, *, executable_path: Path | None = None, assets_path: Path | None = None) -> None:
        env_targets = [Path(".env"), self.data_dir / ".env"]
        for env_path in env_targets:
            try:
                if executable_path is not None:
                    _update_env_envfile(env_path, "XRAY_EXECUTABLE_PATH", str(executable_path))
                if assets_path is not None:
                    _update_env_envfile(env_path, "XRAY_ASSETS_PATH", str(assets_path))
                _update_env_envfile(env_path, "REBECCA_DATA_DIR", str(self.data_dir))
            except Exception as exc:
                logger.warning("Failed to persist %s: %s", env_path, exc)

    def _compose_candidates(self) -> list[Path]:
        candidates: list[Path] = []
        for key in ("REBECCA_NODE_COMPOSE_FILE", "REBECCA_COMPOSE_FILE"):
            value = (os.getenv(key) or "").strip()
            if value:
                candidates.append(Path(value).expanduser())

        candidates.extend(
            [
                self.data_dir / "docker-compose.yml",
                Path("/opt/rebecca-node/docker-compose.yml"),
                Path("/opt/reb/docker-compose.yml"),
            ]
        )

        unique: list[Path] = []
        seen: set[str] = set()
        for path in candidates:
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            unique.append(path)
        return unique

    def _find_compose_file(self) -> Path | None:
        for candidate in self._compose_candidates():
            if candidate.exists():
                return candidate
        return None

    def _sync_compose_env(self, updates: dict[str, str]) -> None:
        compose_file = self._find_compose_file()
        if compose_file is None:
            logger.info("Compose file not found for env sync. Set REBECCA_NODE_COMPOSE_FILE if needed.")
            return
        self._update_docker_compose(compose_file, updates)

    def _update_docker_compose(self, compose_file: Path, updates: dict[str, str]) -> None:
        """
        Best-effort docker-compose env sync for installations that keep
        runtime env values in compose. Failures are non-fatal.
        """
        try:
            import yaml

            with compose_file.open("r", encoding="utf-8") as f:
                content = f.read()

            data = yaml.safe_load(content) or {}
            services = data.setdefault("services", {})
            service_key = self.node_service_name
            if service_key not in services:
                if "rebecca-node" in services:
                    service_key = "rebecca-node"
                else:
                    for name, service_data in services.items():
                        image = str((service_data or {}).get("image") or "").lower()
                        if "rebecca-node" in image:
                            service_key = str(name)
                            break
            node_service = services.setdefault(service_key, {})
            env_raw = node_service.get("environment") or {}

            env: dict[str, str] = {}
            if isinstance(env_raw, dict):
                env = {str(k): str(v) for k, v in env_raw.items()}
            elif isinstance(env_raw, list):
                for item in env_raw:
                    if not isinstance(item, str) or "=" not in item:
                        continue
                    k, v = item.split("=", 1)
                    env[k.strip()] = v.strip()

            for key, value in updates.items():
                env[key] = str(value)

            node_service["environment"] = env

            with compose_file.open("w", encoding="utf-8") as f:
                yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
        except Exception as exc:
            logger.warning("Failed to sync docker-compose env (%s): %s", compose_file, exc)

    def update_core(self, version: str = Body(embed=True)):
        if not version:
            raise HTTPException(422, detail="version is required")

        asset = self._detect_asset_name()
        url = f"https://github.com/XTLS/Xray-core/releases/download/{version}/{asset}"
        try:
            r = requests.get(url, timeout=120)
            r.raise_for_status()
            zip_bytes = r.content
        except Exception as e:
            raise HTTPException(502, detail=f"Download failed: {e}")

        base_dir = self._xray_dir()
        if self.core.started:
            try:
                self.core.stop()
            except RuntimeError:
                pass

        extracted_exe = Path(self._install_zip_to(zip_bytes, str(base_dir)))
        final_exe = base_dir / "xray"
        try:
            if extracted_exe != final_exe:
                if final_exe.exists():
                    final_exe.unlink()
                extracted_exe.rename(final_exe)
        except Exception:
            shutil.copyfile(str(extracted_exe), str(final_exe))
            if platform.system().lower().startswith("linux"):
                final_exe.chmod(final_exe.stat().st_mode | stat.S_IEXEC)

        exe_path = final_exe.resolve()

        self.core.executable_path = str(exe_path)
        self.core.assets_path = str(base_dir)
        self.core._env["XRAY_LOCATION_ASSET"] = str(base_dir)
        self.core_version = self.core.get_version()
        self._persist_xray_env(executable_path=exe_path, assets_path=base_dir)

        self._sync_compose_env(
            {
                "REBECCA_DATA_DIR": str(self.data_dir),
                "XRAY_EXECUTABLE_PATH": str(exe_path),
                "XRAY_ASSETS_PATH": str(base_dir),
            }
        )

        return {"detail": f"Node core ready at {exe_path}", "version": self.core_version}

    def update_geo(self, files: list = Body(embed=True)):
        """
        Download geo assets to host's mapped volume path and update docker-compose.yml.
        """
        if not isinstance(files, list) or not files:
            raise HTTPException(422, detail="'files' must be a non-empty list of {name,url}.")

        assets_dir = self._xray_dir()
        saved = self._download_files_to(assets_dir, files)

        try:
            self.core.assets_path = str(assets_dir)
            self.core._env["XRAY_LOCATION_ASSET"] = str(assets_dir)
        except Exception:
            pass
        self._persist_xray_env(assets_path=assets_dir)

        self._sync_compose_env(
            {
                "REBECCA_DATA_DIR": str(self.data_dir),
                "XRAY_ASSETS_PATH": str(assets_dir),
            }
        )

        return {"detail": f"Geo assets saved to {assets_dir}", "saved": saved}

    def _resolve_access_log_path(self) -> Path | None:
        def _resolve_log_path(value, filename: str, base_dir: Path) -> Path | None:
            """
            Resolve an access log path from config, honoring relative paths and 'none' sentinel.
            """
            if value is None:
                return base_dir / filename
            if isinstance(value, str):
                lowered = value.strip().lower()
                if lowered == "none":
                    return None
                if not value.strip():
                    return base_dir / filename
                candidate = Path(value.strip())
                if not candidate.is_absolute() or candidate.parent == Path("/"):
                    return base_dir / candidate.name
                return candidate
            return base_dir / filename

        from config import XRAY_LOG_DIR, XRAY_ASSETS_PATH

        runtime_assets = getattr(self.core, "assets_path", "") or XRAY_ASSETS_PATH
        base_dir = Path(XRAY_LOG_DIR or runtime_assets or "/var/log").expanduser()
        access_log_path = None
        if self.config and hasattr(self.config, "get"):
            try:
                log_config = self.config.get("log", {}) or {}
                if isinstance(log_config, dict):
                    access_log_path = _resolve_log_path(log_config.get("access"), "access.log", base_dir)
            except Exception:
                access_log_path = None

        if access_log_path is None:
            access_log_path = base_dir / "access.log"
        return Path(access_log_path)

    def _read_access_logs(self, max_lines: int) -> dict:
        access_log_file = self._resolve_access_log_path()

        if not access_log_file or not access_log_file.exists():
            return {
                "log_path": str(access_log_file) if access_log_file else "",
                "exists": False,
                "lines": [],
                "total_lines": 0,
            }

        try:
            lines = self._tail_file(access_log_file, max_lines)
            return {"log_path": str(access_log_file), "exists": True, "lines": lines, "total_lines": len(lines)}
        except Exception as e:
            logger.error(f"Failed to read access logs: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to read access logs: {e}")

    def get_access_logs(self, session_id: UUID = Body(embed=True), max_lines: int = Body(default=500, embed=True)):
        """
        Retrieve access logs from this node for forwarding to master.
        Returns the last N lines from the access log file.
        """
        self.match_session_id(session_id)
        return self._read_access_logs(max_lines)

    async def access_logs_ws(self, websocket: WebSocket):
        session_id_raw = websocket.query_params.get("session_id")
        max_lines_raw = websocket.query_params.get("max_lines")

        try:
            session_id = UUID(session_id_raw) if session_id_raw else None
            if not session_id:
                return await websocket.close(reason="session_id is required", code=4400)
            self.match_session_id(session_id)
        except ValueError:
            return await websocket.close(reason="session_id should be a valid UUID", code=4400)
        except HTTPException:
            return await websocket.close(reason="Session ID mismatch.", code=4403)

        max_lines = 500
        if max_lines_raw:
            try:
                max_lines = max(1, min(int(max_lines_raw), 5000))
            except ValueError:
                return await websocket.close(reason="max_lines should be integer", code=4400)

        await websocket.accept()
        try:
            payload = self._read_access_logs(max_lines)
            await websocket.send_text(json.dumps(payload))
        except Exception as exc:
            await websocket.send_text(json.dumps({"error": str(exc), "lines": []}))
        finally:
            try:
                await websocket.close()
            except Exception:
                pass

    def _tail_file(self, path: Path, max_lines: int) -> list[str]:
        """Read last N lines from a file efficiently."""
        if max_lines <= 0:
            return []

        lines = []
        buffer = b""
        chunk_size = 8192
        newline = b"\n"

        with path.open("rb") as fp:
            fp.seek(0, os.SEEK_END)
            position = fp.tell()

            while position > 0 and len(lines) < max_lines:
                read_size = min(chunk_size, position)
                position -= read_size
                fp.seek(position)
                data = fp.read(read_size)
                buffer = data + buffer
                parts = buffer.split(newline)
                buffer = parts[0]

                for line in reversed(parts[1:]):
                    if len(lines) >= max_lines:
                        break
                    if line.endswith(b"\r"):
                        line = line[:-1]
                    lines.append(line)

            if buffer and len(lines) < max_lines:
                lines.append(buffer.rstrip(b"\r"))

        return [line.decode("utf-8", errors="ignore") for line in reversed(lines)]

    def restart_node_service(self, session_id: UUID = Body(embed=True)):
        self.match_session_id(session_id)
        return self._call_node_service("/restart", timeout=300)

    def update_node_service(self, session_id: UUID = Body(embed=True)):
        self.match_session_id(session_id)
        return self._call_node_service("/update", timeout=900)


service = Service()
app.include_router(service.router)
