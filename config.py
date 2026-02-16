from decouple import config
from dotenv import load_dotenv

load_dotenv()

NODE_VERSION_FALLBACK = "0.0.4"

SERVICE_HOST = config("SERVICE_HOST", default="0.0.0.0")
SERVICE_PORT = config("SERVICE_PORT", cast=int, default=62050)

XRAY_API_HOST = config("XRAY_API_HOST", default="0.0.0.0")
XRAY_API_PORT = config("XRAY_API_PORT", cast=int, default=62051)
XRAY_EXECUTABLE_PATH = config("XRAY_EXECUTABLE_PATH", default="/usr/local/bin/xray")
XRAY_ASSETS_PATH = config("XRAY_ASSETS_PATH", default="/usr/local/share/xray")
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
