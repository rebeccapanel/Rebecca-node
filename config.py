import os
from pathlib import Path

from decouple import config
from dotenv import load_dotenv

load_dotenv()

NODE_VERSION_FALLBACK = "0.0.4"

SERVICE_HOST = config("SERVICE_HOST", default="0.0.0.0")
SERVICE_PORT = config("SERVICE_PORT", cast=int, default=62050)

XRAY_API_HOST = config("XRAY_API_HOST", default="0.0.0.0")
XRAY_API_PORT = config("XRAY_API_PORT", cast=int, default=62051)
REBECCA_DATA_DIR = Path(config("REBECCA_DATA_DIR", default="/var/lib/rebecca-node")).expanduser()
PERSISTENT_XRAY_DIR = REBECCA_DATA_DIR / "xray-core"
PERSISTENT_XRAY_EXECUTABLE = PERSISTENT_XRAY_DIR / "xray"


def _resolve_xray_executable_path() -> str:
    configured = (os.getenv("XRAY_EXECUTABLE_PATH") or "").strip()
    if PERSISTENT_XRAY_EXECUTABLE.exists():
        return str(PERSISTENT_XRAY_EXECUTABLE)
    if configured:
        return configured
    return "/usr/local/bin/xray"


def _resolve_xray_assets_path() -> str:
    configured = (os.getenv("XRAY_ASSETS_PATH") or "").strip()
    for candidate in (PERSISTENT_XRAY_DIR, REBECCA_DATA_DIR / "assets"):
        if (candidate / "geoip.dat").exists() or (candidate / "geosite.dat").exists():
            return str(candidate)
    if configured:
        return configured
    return "/usr/local/share/xray"


XRAY_EXECUTABLE_PATH = _resolve_xray_executable_path()
XRAY_ASSETS_PATH = _resolve_xray_assets_path()
XRAY_LOG_DIR = config("XRAY_LOG_DIR", default="").strip()

NODE_VERSION = config("NODE_VERSION", default=NODE_VERSION_FALLBACK)
NODE_SERVICE_SCHEME = config("REBECCA_NODE_SCRIPT_SCHEME", default="http")
NODE_SERVICE_HOST = config("REBECCA_NODE_SCRIPT_HOST", default="127.0.0.1")
NODE_SERVICE_PORT = config("REBECCA_NODE_SCRIPT_PORT", cast=int, default=3100)

SSL_CERT_FILE = config("SSL_CERT_FILE", default="/var/lib/rebecca-node/ssl_cert.pem")
SSL_KEY_FILE = config("SSL_KEY_FILE", default="/var/lib/rebecca-node/ssl_key.pem")
SSL_CLIENT_CERT_FILE = config("SSL_CLIENT_CERT_FILE", default="")

DEBUG = config("DEBUG", cast=bool, default=False)

INBOUNDS = config("INBOUNDS", cast=lambda v: [x.strip() for x in v.split(",")] if v else [], default="")
