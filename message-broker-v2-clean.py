# -*- coding: utf-8 -*-
import asyncio
import json
import logging
import os
import platform
import secrets
import sys
import time
import traceback
import re # Import missing re
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, AsyncGenerator, Union # Added Union
from collections import deque
import hashlib
import ipaddress

# --- Tortoise ORM Imports ---
# Ensure these are present
from tortoise import Tortoise, fields, models
from tortoise.exceptions import DoesNotExist, IntegrityError
from tortoise.transactions import in_transaction # <<< ESSENTIAL IMPORT FOR FIXES

# --- Dependency Imports (Try/Except for User Feedback) ---
try:
    from fastapi import (FastAPI, Request, Response, Depends, HTTPException, status,
                         BackgroundTasks, Path, Query as FastQuery)
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import (OAuth2PasswordBearer, OAuth2PasswordRequestForm,
                                  HTTPBearer, HTTPAuthorizationCredentials)
    from fastapi.responses import JSONResponse
    import uvicorn

    from jose import JWTError, jwt
    # Pydantic v2+ usage
    from pydantic import BaseModel, ValidationError, Field, EmailStr, ConfigDict, field_validator

    # Tortoise already imported above

    from colorama import init, Fore, Style

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    import psutil
    from werkzeug.utils import secure_filename

    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware

    import strawberry
    from strawberry.fastapi import GraphQLRouter
    from strawberry.types import Info

except ImportError as e:
    missing_pkg = str(e).split("'")[-2]
    print(f"\nERROR: Missing dependency '{missing_pkg}'.")
    print("Please install all required packages by running:")
    # Updated install command list
    print("\n  pip install fastapi uvicorn[standard] tortoise-orm aiosqlite pydantic[email] python-jose[cryptography] colorama cryptography psutil Werkzeug slowapi strawberry-graphql[fastapi] Jinja2 ipaddress passlib Werkzeug\n")
    sys.exit(1)

# --- Basic Setup ---
init(autoreset=True) # Initialize Colorama

# --- Settings ---
class Settings:
    PROJECT_NAME: str = "Message Broker API V3.1.5 (FastAPI/Tortoise/Fixes)" # Updated Name
    VERSION: str = "0.3.1.5-fastapi-tortoise-fixes" # Updated Version
    API_PORT: int = 8777
    # IMPORTANT: Generate a strong secret key and set it via environment variable in production!
    # Example generation: python -c 'import secrets; print(secrets.token_hex(32))'
    JWT_SECRET_KEY: str = os.environ.get('JWT_SECRET_KEY', '!!_CHANGE_ME_IN_PRODUCTION_' + secrets.token_hex(16) + '_!!')
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 1 # 1 hour
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    DB_DIR: str = 'databases'
    DB_FILENAME: str = 'message_broker_v3.db'
    DB_PATH: str = os.path.abspath(os.path.join(DB_DIR, DB_FILENAME))
    DATABASE_URL: str = f"sqlite:///{DB_PATH}"
    LOG_DIR: str = 'logs_v3'
    CERT_DIR: str = 'certs_v3'
    CERT_FILE: str = os.path.join(CERT_DIR, 'cert.pem')
    KEY_FILE: str = os.path.join(CERT_DIR, 'key_nopass.pem')
    ALLOWED_ORIGINS: List[str] = ["*"] # WARNING: "*" is insecure for production. List specific origins.
    DEFAULT_RATE_LIMIT: str = "200/minute" # Default limit for most endpoints
    HIGH_TRAFFIC_RATE_LIMIT: str = "200/second" # Higher limit for publish/consume/ack/nack
    LOG_LEVEL_STR: str = os.environ.get("LOG_LEVEL", "INFO").upper()
    LOG_LEVEL: int = getattr(logging, LOG_LEVEL_STR, logging.INFO)
    APP_ENV: str = os.environ.get("APP_ENV", "production").lower() # 'development' or 'production'

settings = Settings()

# --- Security Warnings ---
if "CHANGE_ME_IN_PRODUCTION" in settings.JWT_SECRET_KEY and settings.APP_ENV == "production":
    print(f"{Fore.RED}{Style.BRIGHT}🚨 CRITICAL SECURITY WARNING: Running in PRODUCTION environment with a DEFAULT JWT_SECRET_KEY! Generate a strong secret and set the JWT_SECRET_KEY environment variable.{Style.RESET_ALL}")
    # Consider exiting if in production with default secret: sys.exit(1)
elif "CHANGE_ME_IN_PRODUCTION" in settings.JWT_SECRET_KEY:
     print(f"{Fore.YELLOW}⚠️ SECURITY WARNING: Using a generated default JWT_SECRET_KEY. Set the JWT_SECRET_KEY environment variable for persistent sessions between restarts.{Style.RESET_ALL}")

if settings.ALLOWED_ORIGINS == ["*"] and settings.APP_ENV == "production":
    print(f"{Fore.YELLOW}⚠️ SECURITY WARNING: CORS ALLOWED_ORIGINS is set to '*' in production. This is insecure. Specify allowed origins explicitly.{Style.RESET_ALL}")


# --- Directory Setup ---
os.makedirs(settings.LOG_DIR, exist_ok=True)
os.makedirs(settings.CERT_DIR, exist_ok=True)
os.makedirs(settings.DB_DIR, exist_ok=True)

# --- Logging Setup ---
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
unique_hash = hashlib.sha1(str(os.getpid()).encode()).hexdigest()[:8]
LOG_FILENAME = os.path.join(settings.LOG_DIR, f"broker_log_{timestamp}_{unique_hash}.json")

class ColoramaFormatter(logging.Formatter):
    LEVEL_COLORS = { logging.DEBUG: Fore.CYAN, logging.INFO: Fore.GREEN, logging.WARNING: Fore.YELLOW, logging.ERROR: Fore.RED, logging.CRITICAL: Fore.MAGENTA }
    LEVEL_ICONS = { logging.DEBUG: "⚙️ ", logging.INFO: "ℹ️ ", logging.WARNING: "⚠️ ", logging.ERROR: "❌ ", logging.CRITICAL: "🔥 ", 'SUCCESS': "✅ ", 'PIPELINE': "➡️ ", 'DB': "💾 ", 'AUTH': "🔑 ", 'QUEUE': "📥 ", 'MSG': "✉️ ", 'HTTP': "🌐 ", 'STATS': "📊 ", 'LOGS': "📄 ", 'SEC': "🛡️ ", 'ASYNC': "⚡ ", 'GRAPHQL': "🍓 ", 'RATELIMIT': "⏱️ ", 'STARTUP': '🚀', 'SHUTDOWN': '🛑', 'GEN': '✨', 'SETUP': '🔧'}

    def format(self, record):
        level_color = self.LEVEL_COLORS.get(record.levelno, Fore.WHITE)
        icon_type = getattr(record, 'icon_type', record.levelname)
        icon = self.LEVEL_ICONS.get(icon_type, "")
        formatted_time = self.formatTime(record, self.datefmt)
        log_message_content = f"[{record.levelname}] {icon}{record.getMessage()}"
        log_line = f"{formatted_time} - {record.name} - {level_color}{Style.BRIGHT}{log_message_content}{Style.RESET_ALL}"
        return log_line

class JsonFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        return datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

    def format(self, record):
        log_record = {
            'timestamp': self.formatTime(record), 'level': record.levelname, 'name': record.name,
            'pid': record.process, 'thread': record.threadName, 'message': record.getMessage(),
            'pathname': record.pathname, 'lineno': record.lineno,
        }
        if hasattr(record, 'icon_type'): log_record['icon_type'] = record.icon_type
        if hasattr(record, 'extra_data') and isinstance(record.extra_data, dict): log_record.update(record.extra_data)
        if record.exc_info:
            # Only include full traceback in development for security
            traceback_str = "".join(traceback.format_exception(*record.exc_info)) if settings.APP_ENV == 'development' else 'Traceback hidden in production'
            log_record['exception'] = {
                'type': record.exc_info[0].__name__, 'value': str(record.exc_info[1]),
                'traceback': traceback_str
            }
        return json.dumps(log_record, ensure_ascii=False, default=str)

logger = logging.getLogger("MessageBroker")
logger.setLevel(settings.LOG_LEVEL)
logger.propagate = False
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

if not logger.handlers:
    # Console Handler (Colored Text)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(settings.LOG_LEVEL)
    console_formatter = ColoramaFormatter(datefmt=DATE_FORMAT)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File Handler (JSON)
    try:
        file_handler = logging.FileHandler(LOG_FILENAME, mode='a', encoding='utf-8')
        file_handler.setLevel(settings.LOG_LEVEL)
        file_formatter = JsonFormatter()
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    except Exception as e:
         # Log error about file handler to console if it fails
         logger.error(f"❌ CRITICAL: Failed to initialize file logging ({LOG_FILENAME}): {e}", exc_info=True)


# --- Logging Helper Functions ---
def log_debug(message: str, icon_type: str = 'DEBUG', extra: Optional[Dict[str, Any]] = None): logger.debug(message, extra={'icon_type': icon_type, 'extra_data': extra or {}})
def log_info(message: str, icon_type: str = 'INFO', extra: Optional[Dict[str, Any]] = None): logger.info(message, extra={'icon_type': icon_type, 'extra_data': extra or {}})
def log_success(message: str, icon_type: str = 'SUCCESS', extra: Optional[Dict[str, Any]] = None): logger.info(message, extra={'icon_type': icon_type, 'extra_data': extra or {}})
def log_warning(message: str, icon_type: str = 'WARNING', extra: Optional[Dict[str, Any]] = None): logger.warning(message, extra={'icon_type': icon_type, 'extra_data': extra or {}})
def log_error(message: str, exc_info: bool = False, icon_type: str = 'ERROR', extra: Optional[Dict[str, Any]] = None): logger.error(message, exc_info=exc_info, extra={'icon_type': icon_type, 'extra_data': extra or {}})
def log_critical(message: str, exc_info: bool = False, icon_type: str = 'CRITICAL', extra: Optional[Dict[str, Any]] = None): logger.critical(message, exc_info=exc_info, extra={'icon_type': icon_type, 'extra_data': extra or {}})
def log_pipeline(message: str, icon_type: str = 'PIPELINE', extra: Optional[Dict[str, Any]] = None): logger.info(message, extra={'icon_type': icon_type, 'extra_data': extra or {}})

# --- SSL Certificate Generation ---
def generate_self_signed_cert(cert_path: str, key_path: str, key_password: Optional[bytes] = None, common_name: str = "localhost"):
    log_info(f"🛡️ Generating new RSA private key and self-signed certificate for CN='{common_name}'...", icon_type='GEN')
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"XX"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"DefaultState"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"DefaultCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Message Broker SelfSigned"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        # Add Subject Alternative Name (SAN) for localhost IP and DNS name
        san_extension = x509.SubjectAlternativeName([
            x509.DNSName(common_name),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            # Add other IPs/DNS names if needed, e.g., x509.DNSName("my-service.local")
        ])
        cert_builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()) \
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(days=1)) \
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365*2)) \
            .add_extension(san_extension, critical=False) # SAN is not critical

        # Add Basic Constraints extension (recommended for self-signed certs)
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )

        certificate = cert_builder.sign(private_key, hashes.SHA256(), default_backend())

        # Choose key encryption (NoEncryption is fine for local dev, use password in staging/prod)
        key_pem_encryption = serialization.NoEncryption()
        if key_password:
             log_info("🔑 Encrypting private key with provided password.", icon_type='SEC')
             key_pem_encryption = serialization.BestAvailableEncryption(key_password)

        # Write private key to file
        with open(key_path, "wb") as f:
             f.write(private_key.private_bytes(
                 encoding=serialization.Encoding.PEM,
                 format=serialization.PrivateFormat.PKCS8, # Use PKCS8, more modern than TraditionalOpenSSL
                 encryption_algorithm=key_pem_encryption
             ))
        log_success(f"🔑 Private key saved: {key_path}", icon_type='SEC')

        # Write certificate to file
        with open(cert_path, "wb") as f:
             f.write(certificate.public_bytes(serialization.Encoding.PEM))
        log_success(f"📜 Self-signed certificate saved: {cert_path}", icon_type='SEC')
        return True
    except ImportError:
        # This should not happen if dependencies are installed, but good practice
        log_critical("The 'ipaddress' module is required for certificate generation. Please install it (`pip install ipaddress`).", icon_type='CRITICAL')
        return False
    except Exception as e:
        log_critical(f"Failed to generate certificates/key: {e}", exc_info=True, icon_type='CRITICAL')
        return False

# --- Application State & Stats ---
# Store timestamp as datetime object
# This dictionary holds the *source* data for the /stats endpoint
app_stats: Dict[str, Any] = {
    "start_time": datetime.now(timezone.utc),
    "requests_total": 0,
    "requests_by_route": {}, # Structure: {"/path": {"GET": count, "POST": count}, ...}
    "requests_by_status": {}, # Structure: {"200": count, "404": count, ...}
    "queues_total": 0,
    "messages_total": 0,
    "messages_pending": 0,
    "messages_processing": 0,
    "messages_processed": 0,
    "messages_failed": 0,
    "last_error": None,
    "last_error_timestamp": None, # <<< Keep as datetime or None
    "system": {
        "python_version": platform.python_version(), "platform": platform.system(),
        "platform_release": platform.release(), "architecture": platform.machine(),
    },
    "broker_specific": {
        "framework": "FastAPI", "version": settings.VERSION, "db_engine": "sqlite (tortoise-orm)",
        "auth_method": "jwt (access+refresh, python-jose)",
        "notification": "None", "rate_limit": "In-Memory (slowapi)",
        "graphql": "strawberry-graphql"
    }
}
stats_lock = asyncio.Lock() # Lock for thread-safe updates to app_stats

# --- Stats Update Functions ---
async def update_request_stats(route_template: str, method: str, status_code: int):
    """Increment request counters safely."""
    async with stats_lock:
        app_stats["requests_total"] += 1
        # Update requests by route/method
        route_stats = app_stats["requests_by_route"].setdefault(route_template, {})
        route_stats[method] = route_stats.get(method, 0) + 1
        # Update requests by status code
        status_code_str = str(status_code) # Ensure status code is string key
        app_stats["requests_by_status"][status_code_str] = app_stats["requests_by_status"].get(status_code_str, 0) + 1
        # Log the update for debugging if needed (set level higher than DEBUG usually)
        log_debug(f"Stats Update: route='{route_template}', method='{method}', status={status_code}. New totals: route={route_stats[method]}, status={app_stats['requests_by_status'][status_code_str]}", icon_type='STATS')

async def update_broker_stats():
    """Fetch queue and message counts from DB and update stats."""
    log_pipeline("📊 Fetching broker stats from DB...", icon_type='STATS')
    try:
        # <<< FIX: Check if Tortoise connections are initialized >>>
        # Using `Tortoise.apps` is a slightly more public/stable way than `_connections`
        if not Tortoise.apps:
             log_warning("DB not initialized, cannot update broker stats.", icon_type='DB')
             return

        # Use asyncio.gather for concurrent DB queries
        q_count_task = Queue.all().count()
        m_pending_task = Message.filter(status='pending').count()
        m_processing_task = Message.filter(status='processing').count()
        m_processed_task = Message.filter(status='processed').count()
        m_failed_task = Message.filter(status='failed').count()

        q_count, pending, processing, processed, failed = await asyncio.gather(
            q_count_task, m_pending_task, m_processing_task, m_processed_task, m_failed_task
        )
        total = pending + processing + processed + failed

        async with stats_lock:
            app_stats["queues_total"] = q_count
            app_stats["messages_pending"] = pending
            app_stats["messages_processing"] = processing
            app_stats["messages_processed"] = processed
            app_stats["messages_failed"] = failed
            app_stats["messages_total"] = total
            # Clear last error if update was successful and it was a stats update error
            if app_stats["last_error"] and "Broker Stats Update Failed" in app_stats["last_error"]:
                 app_stats["last_error"] = None
                 app_stats["last_error_timestamp"] = None # Reset timestamp as well
        log_success("📊 Broker stats updated.", icon_type='STATS', extra={'counts': {'queues': q_count, 'pending': pending, 'processing': processing, 'processed': processed, 'failed': failed}})
    except Exception as e:
        # Store timestamp as datetime object here
        error_time = datetime.now(timezone.utc)
        error_msg = f"Broker Stats Update Failed at {error_time.isoformat()}: {type(e).__name__}"
        log_error(f"Error updating broker stats: {e}", icon_type='STATS', exc_info=True)
        async with stats_lock:
            app_stats["last_error"] = error_msg
            app_stats["last_error_timestamp"] = error_time # <<< Store datetime object

# --- Tortoise ORM Setup ---
async def init_tortoise():
    """Initialize Tortoise ORM connection and generate schemas."""
    log_info(f"💾 Configuring Tortoise ORM for SQLite: {settings.DATABASE_URL}", icon_type='DB')
    try:
        await Tortoise.init(
            db_url=settings.DATABASE_URL,
            modules={'models': ['__main__']} # Looks for models in the current script (__name__ == '__main__')
        )
        log_info("💾 Generating DB schemas if necessary...", icon_type='DB')
        await Tortoise.generate_schemas(safe=True) # Creates tables if they don't exist, doesn't alter existing ones dangerously
        log_success("💾 ORM tables verified/created successfully.", icon_type='DB')
        # Initial stats population only after DB is confirmed ready
        await update_broker_stats()
    except Exception as e:
        log_critical(f"Fatal: Failed to initialize Tortoise ORM: {e}", icon_type='CRITICAL', exc_info=True)
        sys.exit(1) # Cannot run without DB

# --- Pydantic Models (Data Validation & Serialization) ---
# Use ConfigDict for Pydantic V2+
# Enable populate_by_name=True to allow using field names or aliases
# Enable from_attributes=True to allow creating models from ORM objects
PYDANTIC_CONFIG = ConfigDict(populate_by_name=True, from_attributes=True)

class QueueBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, pattern=r"^[a-zA-Z0-9_-]+$",
                      description="Unique queue name (alphanumeric, underscore, hyphen).")

class QueueCreatePayload(QueueBase): pass # Alias for input

class QueueResponse(QueueBase):
    id: int
    created_at: datetime
    updated_at: datetime
    message_count: int = Field(default=0, description="Current number of messages in the queue")
    model_config = PYDANTIC_CONFIG

class MessageBase(BaseModel):
    content: str = Field(..., min_length=1, description="The content/payload of the message (arbitrary string)")

class MessagePayload(MessageBase): pass # Alias for input

class MessageResponse(MessageBase):
    id: int
    queue_id: int
    status: str = Field(description="Current status: pending, processing, processed, failed")
    created_at: datetime
    updated_at: datetime
    model_config = PYDANTIC_CONFIG

class MessagePublishResponse(BaseModel):
    message: str = Field(default="Message published successfully")
    message_id: int
    model_config = PYDANTIC_CONFIG

class MessageConsumeResponse(BaseModel):
    message_id: int
    queue: str # Queue name included for context
    content: str
    status: str = Field(default='processing', description="Should always be 'processing' on successful consume")
    retrieved_at: datetime # Timestamp when the message status changed to 'processing'
    model_config = PYDANTIC_CONFIG

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    model_config = PYDANTIC_CONFIG

# <<< FIX: Correct typing for timestamp fields >>>
# This model defines the structure of the JSON response for the /stats endpoint
class StatsResponse(BaseModel):
    start_time: datetime # Keep as datetime, Pydantic handles serialization to ISO string
    uptime_seconds: float
    uptime_human: str
    requests_total: int
    # These match the keys in app_stats and the dashboard's expectations
    requests_by_route: Dict[str, Dict[str, int]] = Field(description="Count of requests per route template and HTTP method")
    requests_by_status: Dict[str, int] = Field(description="Count of requests per HTTP status code")
    queues_total: int
    messages_total: int
    messages_pending: int
    messages_processing: int
    messages_processed: int
    messages_failed: int
    last_error: Optional[str]
    last_error_timestamp: Optional[datetime] # Keep as datetime, Pydantic handles serialization
    system: Dict[str, Any]
    broker_specific: Dict[str, Any] # Allow more flexibility here
    model_config = PYDANTIC_CONFIG

class LogFileResponse(BaseModel):
    log_files: List[str]
    model_config = PYDANTIC_CONFIG

# --- Tortoise ORM Models ---
class Queue(models.Model):
    id = fields.IntField(pk=True)
    # Ensure name constraints match Pydantic validation
    name = fields.CharField(max_length=255, unique=True, index=True, description="Unique queue name")
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    # Reverse relation: allows accessing messages from a queue instance (queue.messages)
    messages: fields.ReverseRelation["Message"]

    class Meta:
        table = "queues"
        ordering = ["name"] # Default ordering when querying multiple queues

    def __str__(self):
        return self.name

class Message(models.Model):
    id = fields.IntField(pk=True)
    # Foreign key relation: defines the many-to-one relationship (many messages to one queue)
    queue: fields.ForeignKeyRelation[Queue] = fields.ForeignKeyField(
        'models.Queue', related_name='messages', on_delete=fields.CASCADE, # Cascade delete: deleting a queue deletes its messages
        description="The queue this message belongs to"
    )
    content = fields.TextField(description="Message payload")
    # Define allowed status values explicitly if possible, or use validation elsewhere
    status = fields.CharField(max_length=20, default='pending', index=True,
                              description="Status: pending, processing, processed, failed")
    created_at = fields.DatetimeField(auto_now_add=True, index=True) # Index for ordering/filtering
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "messages"
        # Compound index useful for finding the oldest pending message in a queue efficiently
        indexes = [("queue_id", "status", "created_at")]
        ordering = ["created_at"] # Default ordering for messages

    def __str__(self):
        return f"Message {self.id} (Queue: {self.queue_id}, Status: {self.status})"

# --- Lifespan Context Manager (Startup/Shutdown Events) ---
@asynccontextmanager
async def lifespan(app_ref: FastAPI): # Renamed arg to avoid shadowing 'app'
    # Startup Sequence
    log_info("🚀 Application Startup Initiated...", icon_type='STARTUP')
    await init_tortoise()
    # Note: Middleware (CORS, Rate Limiter, Stats) is added *after* FastAPI() instance creation
    # but *before* routes are defined or the server starts running requests.
    log_success("🚀 Application Startup Complete. Ready to accept connections.", icon_type='STARTUP')
    yield # Application runs here
    # Shutdown Sequence
    log_info("🛑 Application Shutdown Initiated...", icon_type='SHUTDOWN')
    try:
        log_info("💾 Closing database connections...", icon_type='DB')
        await Tortoise.close_connections()
        log_success("💾 Database connections closed gracefully.", icon_type='DB')
    except Exception as e:
         log_warning(f"⚠️ Error closing Tortoise connections during shutdown: {e}", icon_type='DB')
    log_success("🛑 Application Shutdown Complete.", icon_type='SHUTDOWN')


# --- FastAPI Application Setup ---
log_info(f"🚀 Initializing FastAPI Application ({settings.PROJECT_NAME} v{settings.VERSION})...", icon_type='SETUP')
app = FastAPI(
    title=settings.PROJECT_NAME, version=settings.VERSION,
    description="Asynchronous Message Broker API using FastAPI, Tortoise ORM, and SQLite.",
    lifespan=lifespan, # Assign the lifespan manager for startup/shutdown events
    docs_url="/docs", # URL for Swagger UI
    redoc_url="/redoc", # URL for ReDoc documentation
    openapi_tags=[ # Define tags for organizing endpoints in docs
        {"name": "General", "description": "Basic health and info endpoints"},
        {"name": "Authentication", "description": "User login and token management (JWT)"},
        {"name": "Monitoring", "description": "System statistics and log viewing"},
        {"name": "Queues", "description": "Operations for managing message queues"},
        {"name": "Messages", "description": "Publishing, consuming, and managing messages"},
        {"name": "GraphQL", "description": "GraphQL API endpoint (alternative to REST)"},
    ]
)

# --- Rate Limiter Setup (Must be added BEFORE routes are hit) ---
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.DEFAULT_RATE_LIMIT])
app.state.limiter = limiter # Make limiter accessible via app state if needed elsewhere
app.add_middleware(SlowAPIMiddleware) # Add the middleware to process requests
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler) # Handle rate limit exceeded errors globally
log_info(f"⏱️ Rate Limiter configured (Default: {settings.DEFAULT_RATE_LIMIT}, High Traffic: {settings.HIGH_TRAFFIC_RATE_LIMIT}).", icon_type='RATELIMIT')

# --- CORS Middleware ---
# IMPORTANT: Configure origins explicitly for production security.
app.add_middleware(
    CORSMiddleware, allow_origins=settings.ALLOWED_ORIGINS, allow_credentials=True,
    allow_methods=["*"], # Allow all standard methods
    allow_headers=["*"], # Allow all standard headers
)
log_info(f"🛡️ CORS configured for origins: {settings.ALLOWED_ORIGINS}", icon_type='SEC')

# --- Authentication Setup & Dependencies ---
# Token URL points to the /login endpoint
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False) # auto_error=False allows checking token existence manually in dependencies
bearer_scheme = HTTPBearer(auto_error=False) # For validating refresh tokens in Authorization header

async def create_jwt_token(data: dict, expires_delta: timedelta) -> str:
    """Creates a JWT token with expiry."""
    to_encode = data.copy()
    issue_time = datetime.now(timezone.utc)
    expire = issue_time + expires_delta
    to_encode.update({"exp": expire, "iat": issue_time})
    # Add 'iss' (issuer) and 'aud' (audience) claims for better practice if needed
    # to_encode.update({"iss": "MyBrokerApp", "aud": "BrokerClients"})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def create_access_token(username: str) -> str:
    """Creates an access token (short-lived)."""
    return await create_jwt_token(
        {"sub": username, "type": "access"},
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

async def create_refresh_token(username: str) -> str:
    """Creates a refresh token (long-lived)."""
    return await create_jwt_token(
        {"sub": username, "type": "refresh"},
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )

async def _decode_token(token: str, expected_type: str) -> str:
    """
    Decodes and validates a JWT token.
    Returns the username (subject) if valid and matches expected type.
    Raises HTTPException 401 otherwise.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Could not validate {expected_type} token",
        headers={"WWW-Authenticate": f"Bearer error=\"invalid_token\", error_description=\"Invalid {expected_type} token\""},
    )
    if not token:
        log_warning(f"Token decode attempt failed: No token provided (expected type: {expected_type}).", icon_type='AUTH')
        raise credentials_exception

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            # Specify audience if you set it during encoding: options={"verify_aud": True}, audience="BrokerClients"
            options={"verify_aud": False} # Disable audience verification if not used
        )
        username: Optional[str] = payload.get("sub")
        token_type: Optional[str] = payload.get("type")

        if username is None or token_type != expected_type:
            log_warning(f"{expected_type.capitalize()} token validation failed: 'sub' missing or type mismatch (Got '{token_type}', Expected '{expected_type}').", icon_type='AUTH', extra={"payload_keys": list(payload.keys())})
            raise credentials_exception

        # --- Optional: Add further checks ---
        # E.g., check if the user exists in a user database and is active
        # user = await get_user_from_db(username) # Hypothetical function
        # if not user or not user.is_active:
        #     log_warning(f"Authentication failed for '{username}': User not found or inactive.", icon_type='AUTH')
        #     raise credentials_exception
        # --- End Optional Checks ---

        # If all checks pass, return the username
        return username

    except JWTError as e:
        # Handles expired tokens, invalid signatures, etc.
        log_warning(f"{expected_type.capitalize()} token validation JWTError: {e}", icon_type='AUTH', extra={"token_preview": token[:10] + "..."})
        # Provide more specific error detail if possible
        detail = f"Invalid {expected_type} token: {e}"
        if "expired" in str(e).lower():
             detail = f"{expected_type.capitalize()} token has expired"
             credentials_exception.headers["WWW-Authenticate"] = f"Bearer error=\"invalid_token\", error_description=\"Token expired\""
        credentials_exception.detail = detail
        raise credentials_exception
    except Exception as e:
         # Catch unexpected errors during decoding
         log_error(f"Unexpected error during {expected_type} token decode: {e}", icon_type='AUTH', exc_info=True)
         # Raise a generic 401 to avoid leaking internal details
         raise credentials_exception

async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> str:
    """Dependency to get the current user from the access token in Authorization header."""
    if token is None:
        # This case happens if Authorization header is missing or not using Bearer scheme
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"} # Signal that Bearer token is expected
        )
    # Decode and validate the access token
    return await _decode_token(token, "access")

async def validate_refresh_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> str:
    """Dependency to validate a refresh token passed in the Authorization: Bearer header."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing or invalid Authorization header format",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_request\", error_description=\"Refresh token required\""}
        )
    # Decode and validate the refresh token
    return await _decode_token(credentials.credentials, "refresh")

# --- Middleware for Stats Update ---
@app.middleware("http")
async def update_stats_middleware(request: Request, call_next):
    """Middleware to update request stats and add X-Process-Time header."""
    start_time_mw = time.perf_counter()
    response = None # Initialize response to None
    status_code = 500 # Default to 500 in case of early exception
    try:
        response = await call_next(request)
        process_time_mw = time.perf_counter() - start_time_mw
        response.headers["X-Process-Time"] = f"{process_time_mw:.4f}s"
        status_code = response.status_code # Get status code from actual response

    except Exception as e:
         # If an exception occurs deeper in the stack, log it and re-raise
         # Let the global exception handlers determine the final status code
         process_time_mw = time.perf_counter() - start_time_mw
         # Log the unhandled exception here BEFORE it gets caught by global handlers
         # Use a distinct log message to differentiate from the global handler log
         log_error(
             f"Unhandled exception propagated to stats middleware ({request.method} {request.url.path}) after {process_time_mw:.4f}s: {type(e).__name__}: {e}",
             exc_info=True, # Include traceback here for context
             icon_type='ERROR'
         )
         # Re-raise the exception to be handled by FastAPI's exception handlers
         raise e
    finally:
        # Update stats regardless of whether an exception occurred, using the determined status code
        # Note: If an exception occurred, `response` might be None if `call_next` failed early
        route = request.scope.get("route")
        if route and hasattr(route, 'path'):
            route_template = route.path

            # --- FIX: Corrected ignore logic for stats ---
            # Define prefixes/paths to ignore for request counting more accurately
            # Ignore docs, IDEs, OpenAPI schema, GraphQL IDE/schema, and favicons by prefix
            ignored_prefixes = ('/docs', '/redoc', '/openapi.json', '/graphql', '/favicon.ico')
            # Ignore the root health check path, the stats endpoint itself, and the log listing endpoint explicitly by path
            ignored_paths = ('/', '/stats', '/logs') # Note: /logs/{filename} WILL be counted now.

            # Check if the current route should be ignored
            should_ignore = False
            if route_template:
                if any(route_template.startswith(prefix) for prefix in ignored_prefixes):
                    should_ignore = True
                    log_debug(f"Ignoring stats update for route (prefix match): {route_template}", icon_type='STATS')
                elif route_template in ignored_paths:
                     should_ignore = True
                     log_debug(f"Ignoring stats update for route (path match): {route_template}", icon_type='STATS')
            # --- End FIX ---

            # Only update stats if the route should NOT be ignored
            if route_template and not should_ignore:
                try:
                    # Use the status_code determined above (either from response or 500 for exception)
                    await update_request_stats(route_template, request.method, status_code)
                except Exception as stats_e:
                     # Log error if stats update fails, but don't fail the request
                     log_error(f"Failed to update request stats: {stats_e}", icon_type='STATS', exc_info=True)
            # else: # Kept for potential debugging
            #    if route_template: # Only log if template was found but ignored
            #        log_debug(f"Final decision: Ignoring stats update for route: {route_template}", icon_type='STATS')


    # If response was successfully generated, return it
    if response:
        return response
    else:
        # This case should ideally be handled by the global exception handler re-raising,
        # but as a fallback, return a generic error if response is still None.
        log_critical("Middleware finished without a response object (likely due to early exception). Returning 500.", icon_type="CRITICAL")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error occurred during request processing."},
        )


# --- Helper Function for DB Lookups with 404 ---
async def _get_queue_or_404(queue_name: str, conn=None) -> Queue:
    """Helper to fetch a Queue by name or raise HTTPException 404. Allows using an existing transaction connection."""
    try:
        query = Queue.all()
        if conn: # If a transaction connection is provided, use it
            # Correct way to apply connection to a QuerySet
            query = query.using_connection(conn)
        # Fetch the queue by name
        queue = await query.get(name=queue_name)
        return queue
    except DoesNotExist:
        log_warning(f"Queue '{queue_name}' not found in database.", icon_type='DB')
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Queue '{queue_name}' not found")
    except Exception as e:
        # Log unexpected DB errors
        log_error(f"Database error fetching queue '{queue_name}': {e}", icon_type='DB', exc_info=True)
        # Raise a generic 500 for unexpected DB issues
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error retrieving queue")

# --- API ROUTE DEFINITIONS ---

# --- General Endpoints ---
@app.get("/", tags=["General"], summary="Health Check")
@limiter.limit("5/second") # Lower limit for basic check
async def index(request: Request):
    """Provides a basic health check, server information, and current timestamp."""
    client_host = request.client.host if request.client else 'N/A'
    log_info("🌐 GET / request", icon_type='HTTP', extra={"client": client_host})
    return {
        "message": f"Welcome to {settings.PROJECT_NAME}",
        "status": "ok",
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# --- Authentication Endpoints ---
@app.post("/login", response_model=Token, tags=["Authentication"], summary="User Login")
@limiter.limit("10/minute") # Limit login attempts to mitigate brute-force
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Handles user login using standard OAuth2 password flow.
    **WARNING: Uses hardcoded 'admin'/'admin' credentials. Replace with secure authentication.**
    """
    client_host = request.client.host if request.client else 'N/A'
    log_info(f"🔑 POST /login attempt for user: '{form_data.username}'", icon_type='AUTH', extra={"client": client_host})

    # --- !!! VERY IMPORTANT: Replace this placeholder with secure password verification !!! ---
    # Example using passlib (install with `pip install passlib[bcrypt]`)
    # from passlib.context import CryptContext
    # pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    # async def verify_password(plain_password, hashed_password):
    #     return pwd_context.verify(plain_password, hashed_password)
    # # Replace with actual user lookup and password hash retrieval from DB
    # user = await get_user_from_db(form_data.username) # Hypothetical DB function
    # if not user or not await verify_password(form_data.password, user.hashed_password):
    #     log_warning(f"Login failed for '{form_data.username}': Invalid credentials.", icon_type='AUTH')
    #     raise HTTPException(
    #         status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password",
    #         headers={"WWW-Authenticate": "Bearer error=\"invalid_grant\""}, )
    # --- !!! End of Security Placeholder !!! ---

    # --- Hardcoded credentials (FOR DEVELOPMENT/DEMO ONLY) ---
    if form_data.username == 'admin' and form_data.password == 'admin':
        log_warning("🚨 Using hardcoded 'admin'/'admin' credentials for login. This is insecure!", icon_type='AUTH')
        # Credentials match, generate tokens
        access_token = await create_access_token(username=form_data.username)
        refresh_token = await create_refresh_token(username=form_data.username)
        log_success(f"Tokens generated for '{form_data.username}'.", icon_type='AUTH')
        return Token(access_token=access_token, refresh_token=refresh_token)
    else:
        # Credentials do not match
        log_warning(f"Login failed for '{form_data.username}': Invalid credentials.", icon_type='AUTH')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_grant\""}, # Standard OAuth2 error
        )

@app.post("/refresh", response_model=Token, tags=["Authentication"], summary="Refresh Access Token")
@limiter.limit("20/minute") # Allow slightly more refreshes than logins
async def refresh_access_token(request: Request, username: str = Depends(validate_refresh_token)):
    """
    Issues a new access and refresh token using a valid refresh token provided in the
    `Authorization: Bearer <refresh_token>` header.
    """
    client_host = request.client.host if request.client else 'N/A'
    log_info(f"🔑 POST /refresh request validated for user '{username}'", icon_type='AUTH', extra={"client": client_host})
    # If validate_refresh_token dependency succeeded, the username is valid
    new_access_token = await create_access_token(username=username)
    new_refresh_token = await create_refresh_token(username=username) # Issue a new refresh token as well (optional, but good practice)
    log_success(f"New access/refresh tokens generated for '{username}' via refresh.", icon_type='AUTH')
    return Token(access_token=new_access_token, refresh_token=new_refresh_token)

# --- Monitoring Endpoints ---
@app.get("/stats", response_model=StatsResponse, tags=["Monitoring"], summary="Get System Statistics")
@limiter.limit("30/minute") # Moderate limit for stats endpoint
async def get_stats(request: Request, current_user: str = Depends(get_current_user)) -> StatsResponse:
    """Returns current application, system, and message broker statistics. Requires authentication."""
    client_host = request.client.host if request.client else 'N/A'
    log_info(f"📊 GET /stats request by user '{current_user}'", icon_type='STATS', extra={"client": client_host})

    # Ensure broker stats are reasonably fresh before returning
    await update_broker_stats()

    # Collect system metrics using psutil in a non-blocking way
    system_metrics = {}
    try:
        process = psutil.Process(os.getpid())
        # Define the synchronous function to be run in a thread
        def _get_psutil_data_sync():
            # Use non-blocking calls or short intervals where possible
            mem_info = process.memory_info()
            # Get CPU percents (can be slightly blocking, use short interval)
            proc_cpu = process.cpu_percent(interval=0.05) # Very short interval
            sys_cpu = psutil.cpu_percent(interval=0.05)
            virt_mem = psutil.virtual_memory()

            # Disk usage (can be slow, especially on network drives)
            disk_usage_data = {}
            try:
                # Get only physical partitions (all=False) to potentially speed up
                partitions = psutil.disk_partitions(all=False)
            except Exception as disk_e:
                log_warning(f"Could not get disk partitions: {disk_e}", icon_type='STATS')
                partitions = []

            for part in partitions:
                # Filter out unwanted types and potentially problematic mounts
                unwanted_fstypes = ['squashfs', 'tmpfs', 'devtmpfs', 'fuse.gvfsd-fuse', 'overlay', 'autofs']
                mountpoint = getattr(part, 'mountpoint', None)
                if not mountpoint or 'loop' in part.device or 'snap' in part.device or part.fstype in unwanted_fstypes:
                    continue
                try:
                    # Check mountpoint exists before getting usage
                    if os.path.exists(mountpoint):
                       usage = psutil.disk_usage(mountpoint)
                       disk_usage_data[mountpoint] = {
                           "total_gb": round(usage.total / (1024**3), 2),
                           "used_gb": round(usage.used / (1024**3), 2),
                           "free_gb": round(usage.free / (1024**3), 2),
                           "percent": usage.percent
                       }
                except (FileNotFoundError, PermissionError, OSError) as part_e:
                    # Log errors for specific partitions but continue
                    log_warning(f"Could not get disk usage for {mountpoint}: {part_e}", icon_type='STATS')

            # Load average (only available on Unix-like systems)
            load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else "N/A"

            # Gather open file descriptors and thread count carefully
            open_fds = "N/A"
            thread_count = "N/A"
            try: open_fds = len(process.open_files())
            except (psutil.AccessDenied, NotImplementedError, Exception) as fd_e: log_warning(f"Could not get open file descriptors: {fd_e}", icon_type="STATS")
            try: thread_count = process.num_threads()
            except (psutil.AccessDenied, NotImplementedError, Exception) as th_e: log_warning(f"Could not get thread count: {th_e}", icon_type="STATS")


            return {
                "cpu_percent": sys_cpu,
                "memory_total_gb": round(virt_mem.total / (1024**3), 2),
                "memory_available_gb": round(virt_mem.available / (1024**3), 2),
                "memory_used_gb": round(virt_mem.used / (1024**3), 2),
                "memory_percent": virt_mem.percent,
                "disk_usage": disk_usage_data or {"info": "No valid partitions found or error reading usage."},
                "process_memory_rss_mb": round(mem_info.rss / (1024**2), 2), # Resident Set Size
                "process_memory_vms_mb": round(mem_info.vms / (1024**2), 2), # Virtual Memory Size
                "process_cpu_percent": proc_cpu,
                "load_average": load_avg,
                "cpu_count_logical": psutil.cpu_count(logical=True),
                "cpu_count_physical": psutil.cpu_count(logical=False),
                "open_file_descriptors": open_fds,
                "thread_count": thread_count,
                # <<< Dashboard expects process_memory_mb, let's add it >>>
                "process_memory_mb": round(mem_info.rss / (1024**2), 2) # Using RSS as the main process memory metric
            }
        # Run the synchronous function in a separate thread
        system_metrics = await asyncio.to_thread(_get_psutil_data_sync)

    except ImportError:
        system_metrics["error"] = "psutil package not installed. Cannot provide detailed system metrics."
        log_warning("psutil package not found. Install with `pip install psutil` for detailed system stats.", icon_type='STATS')
    except Exception as e:
        log_warning(f"Error collecting system stats with psutil: {e}", icon_type='STATS', exc_info=True)
        system_metrics["error"] = f"psutil data collection failed: {type(e).__name__}"

    # Prepare response data safely using the lock
    response_data = {}
    async with stats_lock:
        # Create a copy to avoid modifying the global state directly while processing
        # Ensure all expected keys from app_stats are copied
        current_stats_copy = app_stats.copy()

        # Merge collected system metrics into the system info dictionary
        # Ensure the 'system' key exists before merging
        if "system" not in current_stats_copy:
            current_stats_copy["system"] = {}
        current_stats_copy["system"].update(system_metrics)

        # Calculate uptime
        start_time_dt = current_stats_copy["start_time"]
        uptime_delta = datetime.now(timezone.utc) - start_time_dt
        uptime_seconds = uptime_delta.total_seconds()
        current_stats_copy["uptime_seconds"] = round(uptime_seconds, 2)

        # Format uptime into human-readable string (e.g., "2d 3h 15m 30s")
        days, rem = divmod(int(uptime_seconds), 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)
        parts = []
        if days: parts.append(f"{days}d")
        if hours: parts.append(f"{hours}h")
        if minutes: parts.append(f"{minutes}m")
        if seconds or not parts: parts.append(f"{seconds}s") # Always show seconds if other parts are zero
        current_stats_copy["uptime_human"] = " ".join(parts)

        # Timestamps (`start_time`, `last_error_timestamp`) are already datetime objects
        # Pydantic's `StatsResponse` model will handle serialization to ISO strings.

        # --- Ensure required fields for the dashboard are present ---
        # The middleware should be populating these, but ensure they exist in the dict before validation
        current_stats_copy.setdefault("requests_by_route", {})
        current_stats_copy.setdefault("requests_by_status", {})
        # ---

        response_data = current_stats_copy

        # Debugging: Log the exact data structure being passed to validation
        log_debug(f"Data before Pydantic validation in /stats: {response_data}", icon_type="STATS")

    log_success(f"Stats returned for user '{current_user}'.", icon_type='STATS')
    # Validate the final structure against the Pydantic model before returning
    try:
        # Pydantic automatically converts datetime to ISO strings during validation/serialization
        validated_response = StatsResponse.model_validate(response_data)
        # Log the structure *after* validation/serialization if needed for debugging dashboard issues
        # log_debug(f"Data *after* Pydantic validation/serialization in /stats: {validated_response.model_dump_json(indent=2)}", icon_type="STATS")
        return validated_response
    except ValidationError as e:
        # Log the validation error and the data that failed
        log_critical(f"Stats data failed Pydantic validation: {e.errors()}", icon_type='CRITICAL', extra={"invalid_stats_data": response_data})
        # Return 500 if the generated stats don't match the model schema
        raise HTTPException(status_code=500, detail="Internal Server Error: Failed to generate valid stats data.")



@app.get("/logs", response_model=LogFileResponse, tags=["Monitoring"], summary="List Log Files")
@limiter.limit("10/minute") # Less frequent access generally needed
async def list_log_files(request: Request, current_user: str = Depends(get_current_user)):
    """Lists available JSON log files found in the configured log directory. Requires authentication."""
    client_host = request.client.host if request.client else 'N/A'
    log_info(f"📄 GET /logs request by user '{current_user}'", icon_type='LOGS', extra={"client": client_host})
    try:
        # Use asyncio.to_thread for potentially blocking os.listdir
        def list_dir_sync():
            return os.listdir(settings.LOG_DIR)

        log_files_all = await asyncio.to_thread(list_dir_sync)

        # Filter for .json files and sort newest first (based on filename convention)
        log_files_json = sorted(
            [f for f in log_files_all if f.endswith('.json') and os.path.isfile(os.path.join(settings.LOG_DIR, f))],
            reverse=True # Assumes YYYYMMDD_HHMMSS prefix for sorting
        )
        log_success(f"Found {len(log_files_json)} JSON log files in '{settings.LOG_DIR}'.", icon_type='LOGS')
        return LogFileResponse(log_files=log_files_json)
    except FileNotFoundError:
        log_error(f"Log directory '{settings.LOG_DIR}' configured but not found.", icon_type='LOGS')
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log directory not found on server")
    except OSError as e:
        log_error(f"Error listing log files in '{settings.LOG_DIR}': {e}", exc_info=True, icon_type='LOGS')
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error accessing log directory")

@app.get("/logs/{filename:path}", response_model=List[Dict[str, Any]], tags=["Monitoring"], summary="Get Log File Content")
@limiter.limit("60/minute") # Allow more frequent access to view individual logs
async def get_log_file(
    request: Request,
    filename: str = Path(..., description="The name of the JSON log file to retrieve (e.g., broker_log_YYYYMMDD_HHMMSS_hash.json)."),
    start: Optional[int] = FastQuery(None, ge=1, description="Start reading from this line number (1-based index)."),
    end: Optional[int] = FastQuery(None, ge=1, description="Stop reading at this line number (inclusive, 1-based index)."),
    tail: Optional[int] = FastQuery(None, ge=1, le=10000, description="Retrieve only the last N lines (max 10000). Overrides start/end if provided."),
    current_user: str = Depends(get_current_user)
) -> List[Dict]:
    """
    Retrieves the content of a specific log file, parsing each line as JSON.
    Supports retrieving ranges of lines or the last N lines (tail). Requires authentication.
    """
    # --- Security: Sanitize filename ---
    # Prevents directory traversal (e.g., ../../etc/passwd) and ensures it's likely a log file.
    safe_filename = secure_filename(filename)
    if not safe_filename or safe_filename != filename or not safe_filename.startswith('broker_log_') or not safe_filename.endswith('.json'):
        log_warning(f"Invalid log file access attempt: '{filename}' by user '{current_user}'", icon_type='SEC')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or potentially unsafe log filename provided.")

    log_path = os.path.join(settings.LOG_DIR, safe_filename)
    log_info(f"📄 GET /logs/{safe_filename} request by '{current_user}' (start={start}, end={end}, tail={tail})", icon_type='LOGS')

    # --- File Reading and Parsing (in thread to avoid blocking) ---
    def read_and_parse_log_sync() -> Optional[List[Dict]]:
        if not os.path.isfile(log_path):
            log_warning(f"Log file not found at path: {log_path}", icon_type='LOGS')
            return None # Signal file not found

        lines_to_process: Union[deque, List[str]] = []
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                if tail is not None and tail > 0:
                    # Efficiently get last 'tail' lines using deque
                    lines_to_process = deque(f, maxlen=tail)
                else:
                    # Read line by line, applying start/end limits if present
                    lines_to_process = []
                    line_count_read = 0
                    # Line numbers are 1-based for user input, enumerate provides 0-based
                    for line_num_0based, line in enumerate(f):
                        line_num_1based = line_num_0based + 1
                        # Skip lines before start
                        if start is not None and line_num_1based < start:
                            continue
                        # Stop reading lines after end
                        if end is not None and line_num_1based > end:
                            break
                        # Add the line (strip whitespace)
                        stripped_line = line.strip()
                        if stripped_line: # Avoid adding empty lines
                            lines_to_process.append(stripped_line)
                            line_count_read += 1
                        # Safety break: Limit lines read if only start is given (prevent huge reads)
                        if start is not None and end is None and line_count_read >= 10000:
                            log_warning(f"Log read for {safe_filename} truncated at 10000 lines due to missing 'end' parameter.", icon_type='LOGS')
                            lines_to_process.append(json.dumps({"_warning": "Result set truncated at 10000 lines (specify 'end' for more)", "_limit": 10000}))
                            break
        except FileNotFoundError: # Should be caught by os.path.isfile, but handle defensively
             log_warning(f"Log file disappeared during read: {log_path}", icon_type='LOGS')
             return None
        except Exception as read_exc:
            log_error(f"Error reading log file '{safe_filename}': {read_exc}", exc_info=True, icon_type='LOGS')
            # Return a list containing just the error for the client
            return [{"_error": f"Failed to read file: {type(read_exc).__name__}. Check server logs for details."}]

        # --- Parse JSON lines ---
        parsed_lines: List[Dict[str, Any]] = []
        for i, line in enumerate(lines_to_process):
            if not line: continue # Skip empty lines (double check)

            line_num_info = f"tail_{i+1}" if tail else (start or 1) + i # Approximate original line number for context
            try:
                parsed_line_data = json.loads(line)
                if isinstance(parsed_line_data, dict): # Ensure it's a dictionary
                     parsed_lines.append(parsed_line_data)
                else:
                     # Handle cases where a line is valid JSON but not an object (e.g., just a string)
                     parsed_lines.append({"_warning": "Line parsed but is not a JSON object", "_line": line_num_info, "_type": type(parsed_line_data).__name__, "_raw": line[:250]})
            except json.JSONDecodeError:
                # Include error info and truncated raw line for debugging
                parsed_lines.append({"_error": "Invalid JSON format", "_line": line_num_info, "_raw": line[:250] + ('...' if len(line)>250 else '')})
            except Exception as parse_exc:
                 # Catch other potential parsing issues
                 parsed_lines.append({"_error": f"Parsing error: {parse_exc}", "_line": line_num_info, "_raw": line[:250] + ('...' if len(line)>250 else '')})
        return parsed_lines

    try:
        # Run the synchronous file I/O and parsing in a thread
        result_lines = await asyncio.to_thread(read_and_parse_log_sync)

        if result_lines is None:
            # File was not found by the reading function
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Log file '{safe_filename}' not found.")

        log_success(f"{len(result_lines)} log entries returned from '{safe_filename}'.", icon_type='LOGS')
        return result_lines
    except HTTPException:
        raise # Re-raise expected HTTP exceptions (400, 404)
    except Exception as e:
        log_error(f"Unexpected error processing log file '{safe_filename}': {e}", exc_info=True, icon_type='LOGS')
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected error processing log file. Check server logs.")

# --- Queue Management Endpoints ---
@app.get("/queues", response_model=List[QueueResponse], tags=["Queues"], summary="List All Queues")
@limiter.limit("60/minute") # Allow fairly frequent listing
async def list_queues(request: Request, current_user: str = Depends(get_current_user)) -> List[QueueResponse]:
    """Lists all available message queues, including a count of messages in each. Requires authentication."""
    log_info(f"📋 GET /queues request by user '{current_user}'", icon_type='QUEUE')
    try:
        # Fetch all queues ordered by name
        queues = await Queue.all().order_by('name')
        if not queues:
            log_info("No queues found in the database.", icon_type='QUEUE')
            return [] # Return empty list if no queues exist

        # Fetch message counts for all queues concurrently for efficiency
        count_tasks = {q.id: Message.filter(queue_id=q.id).count() for q in queues}
        # Run count queries in parallel
        message_counts_results = await asyncio.gather(*count_tasks.values())
        # Create a dictionary mapping queue_id to its count
        counts_dict = dict(zip(count_tasks.keys(), message_counts_results))

        # Build the response list, validating each item with the Pydantic model
        response_list = []
        for q in queues:
            try:
                 response_item = QueueResponse(
                     id=q.id, name=q.name, created_at=q.created_at, updated_at=q.updated_at,
                     message_count=counts_dict.get(q.id, 0) # Get count from dict, default 0
                 )
                 response_list.append(response_item)
            except ValidationError as e:
                 # Log if a specific queue fails validation, but continue with others
                 log_error(f"Queue data validation failed for queue ID {q.id} ('{q.name}'): {e.errors()}", icon_type='QUEUE')

        log_success(f"Returned {len(response_list)} queues.", icon_type='QUEUE')
        return response_list
    except Exception as e:
        log_error(f"Error listing queues: {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error retrieving queue list from database")

@app.post("/queues", response_model=QueueResponse, status_code=status.HTTP_201_CREATED, tags=["Queues"], summary="Create New Queue")
@limiter.limit("30/minute") # Less frequent operation than listing
async def create_queue(request: Request, payload: QueueCreatePayload, current_user: str = Depends(get_current_user)) -> QueueResponse:
    """
    Creates a new message queue. The name must be unique. Requires authentication.
    """
    queue_name = payload.name
    log_info(f"➕ POST /queues request by '{current_user}' to create queue '{queue_name}'", icon_type='QUEUE')
    try:
        # Use Tortoise's get_or_create for atomicity.
        # It attempts to get the queue, and if it doesn't exist, creates it within a transaction.
        new_queue, created = await Queue.get_or_create(name=queue_name)

        if not created:
            # The queue already existed
            log_warning(f"Queue '{queue_name}' already exists. Creation request denied (409).", icon_type='QUEUE')
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Queue with name '{queue_name}' already exists."
            )

        # Queue was successfully created
        log_success(f"✅ Queue '{queue_name}' created successfully (ID: {new_queue.id}).", icon_type='QUEUE')
        # Validate the newly created queue object against the response model
        # Manually set message_count to 0 for the response, as it's definitely empty
        response = QueueResponse.model_validate(new_queue)
        response.message_count = 0
        return response

    except IntegrityError: # Catch potential DB unique constraint violation as a fallback
        log_warning(f"IntegrityError during queue creation for '{queue_name}'. Likely already exists (concurrent request?).", icon_type='DB')
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Queue with name '{queue_name}' already exists (database constraint violation).")
    except ValidationError as e: # Catch Pydantic validation errors on the payload
        log_warning(f"Queue creation validation error for '{queue_name}': {e.errors()}", icon_type='QUEUE')
        # Return 422 for validation errors
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.errors())
    except Exception as e:
        log_error(f"Error creating queue '{queue_name}': {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected error creating queue")

@app.get("/queues/{queue_name}", response_model=QueueResponse, tags=["Queues"], summary="Get Queue Details")
@limiter.limit("60/minute")
async def get_queue(request: Request, queue_name: str = Path(..., description="The name of the queue to retrieve."), current_user: str = Depends(get_current_user)) -> QueueResponse:
    """Gets details for a specific queue by its name, including current message count. Requires authentication."""
    log_info(f"📥 GET /queues/{queue_name} request by user '{current_user}'", icon_type='QUEUE')
    try:
        # Use the helper function to get the queue or raise 404
        queue = await _get_queue_or_404(queue_name)
        # Get the count of messages associated with this queue
        message_count = await Message.filter(queue_id=queue.id).count()
        log_success(f"Details for queue '{queue_name}' (ID: {queue.id}) returned.", icon_type='QUEUE')
        # Validate the queue object and add the count before returning
        response = QueueResponse.model_validate(queue)
        response.message_count = message_count
        return response
    except HTTPException:
        raise # Re-raise 404 from helper or any 500 from DB errors
    except Exception as e:
        log_error(f"Unexpected error getting queue details for '{queue_name}': {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error retrieving queue details")

@app.delete("/queues/{queue_name}", status_code=status.HTTP_204_NO_CONTENT, tags=["Queues"], summary="Delete Queue")
@limiter.limit("10/minute") # Deletion should be infrequent and controlled
async def delete_queue(request: Request, queue_name: str = Path(..., description="The name of the queue to delete."), current_user: str = Depends(get_current_user)) -> Response:
    """
    Deletes a queue and all its associated messages (due to CASCADE constraint in the Message model).
    This operation is irreversible. Requires authentication.
    """
    log_info(f"🗑️ DELETE /queues/{queue_name} request by user '{current_user}'", icon_type='QUEUE')
    try:
        # Find the queue first to ensure it exists (raises 404 if not)
        queue = await _get_queue_or_404(queue_name)
        queue_id = queue.id # Get ID for logging before deletion
        log_pipeline(f"Queue '{queue_name}' (ID: {queue_id}) found. Proceeding with deletion...")

        # Perform the delete operation. Tortoise handles cascading deletes based on the model's ForeignKey definition.
        await queue.delete()

        log_success(f"✅ Queue '{queue_name}' (ID: {queue_id}) and associated messages deleted successfully.", icon_type='QUEUE')
        # Return 204 No Content on successful deletion
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except HTTPException:
        raise # Re-raise 404 from helper
    except Exception as e:
        log_error(f"Error deleting queue '{queue_name}': {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error deleting queue")


# --- Message Operations Endpoints ---
@app.post("/queues/{queue_name}/messages", response_model=MessagePublishResponse, status_code=status.HTTP_201_CREATED, tags=["Messages"], summary="Publish Message")
@limiter.limit(settings.HIGH_TRAFFIC_RATE_LIMIT) # Allow high traffic for publishing
async def publish_message(
    request: Request,
    payload: MessagePayload, # Request body containing the message content
    queue_name: str = Path(..., description="The name of the target queue."),
    current_user: str = Depends(get_current_user) # Requires authentication
) -> MessagePublishResponse:
    """Publishes a new message with the given content to the specified queue. Requires authentication."""
    # Log only a preview to avoid logging potentially large/sensitive content fully
    content_preview = payload.content[:80] + ('...' if len(payload.content) > 80 else '')
    log_info(f"📤 POST /queues/{queue_name}/messages request by '{current_user}'", icon_type='MSG', extra={"content_preview": content_preview})
    try:
        # Ensure the target queue exists (raises 404 if not)
        queue = await _get_queue_or_404(queue_name)
        log_pipeline(f"Queue '{queue_name}' (ID: {queue.id}) found. Creating message...")

        # Create the message in the database with 'pending' status
        new_message = await Message.create(queue=queue, content=payload.content, status='pending')

        log_success(f"✅ Message ID {new_message.id} published to queue '{queue_name}'.", icon_type='MSG')
        # Optionally, update overall broker stats in the background if performance is critical
        # background_tasks.add_task(update_broker_stats)
        return MessagePublishResponse(message_id=new_message.id)
    except HTTPException:
        raise # Re-raise 404 if queue not found
    except ValidationError as e: # Catch Pydantic validation errors on the payload
        log_warning(f"Message publish validation error to '{queue_name}': {e.errors()}", icon_type='MSG')
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.errors())
    except Exception as e:
        log_error(f"Error publishing message to queue '{queue_name}': {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error publishing message")


@app.post("/messages/{message_id}/ack", response_model=MessageResponse, tags=["Messages"], summary="Acknowledge Message")
@limiter.limit(settings.HIGH_TRAFFIC_RATE_LIMIT)  # High traffic endpoint
async def acknowledge_message(
    request: Request,  # Added request parameter for rate limiter
    message_id: int = Path(..., description="The ID of the message to acknowledge."),
    current_user: str = Depends(get_current_user)  # Requires authentication
) -> MessageResponse:
    """
    Acknowledges a previously consumed message by marking it as 'completed'.
    This confirms the message has been successfully processed by the consumer.
    The message must be in the 'processing' state to be acknowledged.
    Returns the final message status details.
    Requires authentication.
    """
    log_info(f"✅ POST /messages/{message_id}/ack request by '{current_user}'", icon_type='MSG')

    try:
        # Start transaction for atomic operations
        async with in_transaction("default") as tx:
            # Find the message - must exist and be in 'processing' state
            message = await Message.filter(id=message_id).select_for_update().first()
            
            if not message:
                log_warning(f"Message ID {message_id} not found during acknowledgment.", icon_type='MSG')
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Message with ID {message_id} not found."
                )
                
            if message.status != 'processing':
                log_warning(f"Cannot acknowledge message ID {message_id}: invalid status '{message.status}' (must be 'processing').", icon_type='MSG')
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Message must be in 'processing' status to be acknowledged. Current status: {message.status}"
                )
                
            # Update message status to completed
            message.status = 'completed'
            message.updated_at = datetime.now(timezone.utc)  # Record completion time
            
            # Save the changes
            await message.save(update_fields=['status', 'updated_at'])
            
            # Get queue name for response
            queue = await message.queue
            queue_name = queue.name if queue else "unknown"  # Fallback if relationship query fails
        
        # Transaction committed successfully at this point
        log_success(f"✅ Message ID {message_id} successfully acknowledged (status -> completed).", icon_type='MSG')
        
        # Return success response using MessageResponse model
        return MessageResponse(
            id=message.id,
            queue=queue_name,
            content=message.content,
            status=message.status,  # Will be 'completed'
            created_at=message.created_at,
            updated_at=message.updated_at  # Timestamp of acknowledgment
        )
        
    except HTTPException as http_exc:
        # Re-raise HTTP exceptions - already logged by handler
        raise http_exc
    except Exception as e:
        # Log unexpected errors and return 500
        log_error(f"Error acknowledging message {message_id}: {str(e)}", icon_type='ERROR', exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error acknowledging message"
        )


@app.post("/messages/{message_id}/ack", status_code=status.HTTP_200_OK, response_model=Dict[str, str], tags=["Messages"], summary="Acknowledge Message")
@limiter.limit(settings.HIGH_TRAFFIC_RATE_LIMIT) # High traffic expected
async def acknowledge_message(
    request: Request,
    background_tasks: BackgroundTasks, # Can be used for background tasks after ack
    message_id: int = Path(..., ge=1, description="The ID of the message to acknowledge."),
    current_user: str = Depends(get_current_user) # Requires authentication
) -> Dict[str, str]:
    """
    Marks a message currently in the 'processing' state as 'processed'.
    Uses a transaction with SELECT FOR UPDATE to prevent race conditions.
    Requires authentication.
    """
    log_info(f"✅ POST /messages/{message_id}/ack request by '{current_user}'", icon_type='MSG')
    try:
        # Start transaction for atomic find-and-update
        async with in_transaction("default") as tx:
            # Find the message by ID *only if its status is 'processing'*, lock it, using the transaction
            message = await Message.filter(id=message_id, status='processing') \
                                   .using_connection(tx) \
                                   .select_for_update() \
                                   .get_or_none() # Use get_or_none to handle not found gracefully

            # Check if the message was found in the correct state
            if not message:
                # If not found in 'processing' state, check if it exists at all or has a different status
                # Check status without locking again, just to provide a better error message
                existing_msg_status = await Message.filter(id=message_id) \
                                                   .using_connection(tx) \
                                                   .values_list('status', flat=True) \
                                                   .first()
                if existing_msg_status:
                    # Message exists but is not 'processing' (e.g., already acked, failed, or still pending)
                    log_warning(f"ACK failed for message {message_id}: Expected status 'processing', found '{existing_msg_status}'.", icon_type='MSG')
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"Message {message_id} is in status '{existing_msg_status}', cannot ACK. Only 'processing' messages can be acknowledged."
                    )
                else:
                    # Message ID does not exist in the database
                    log_warning(f"ACK failed: Message {message_id} not found.", icon_type='MSG')
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Message with ID {message_id} not found."
                    )

            # Message found and is in 'processing' state. Update status.
            message.status = 'processed'
            message.updated_at = datetime.now(timezone.utc)
            # Save changes using the transaction connection
            await message.save(using_connection=tx, update_fields=['status', 'updated_at'])
            # Transaction commits automatically here

        log_success(f"✅ Message ID {message_id} acknowledged successfully by '{current_user}' (status -> processed).", icon_type='MSG')
        # Optionally update overall broker stats in the background
        # background_tasks.add_task(update_broker_stats)
        return {"detail": f"Message {message_id} acknowledged successfully."}

    except HTTPException:
        raise # Re-raise 404, 409 from checks
    except IntegrityError as e:
         log_warning(f"DB integrity error during ACK for message {message_id}: {e}", icon_type='DB')
         raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Database conflict during message acknowledgement.")
    except Exception as e:
        log_error(f"Error acknowledging message {message_id}: {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error acknowledging message")


@app.post("/messages/{message_id}/nack", status_code=status.HTTP_200_OK, response_model=Dict[str, str], tags=["Messages"], summary="Negative Acknowledge Message")
@limiter.limit(settings.HIGH_TRAFFIC_RATE_LIMIT) # High traffic expected
async def negative_acknowledge_message(
    request: Request,
    background_tasks: BackgroundTasks, # For potential background tasks
    message_id: int = Path(..., ge=1, description="The ID of the message to NACK."),
    requeue: bool = FastQuery(False, description="If true, set status back to 'pending' for reprocessing. If false, set status to 'failed'."),
    current_user: str = Depends(get_current_user) # Requires authentication
) -> Dict[str, str]:
    """
    Negatively acknowledges a message currently in the 'processing' state.
    This typically means processing failed.
    - If `requeue` is true, the message status is set back to 'pending' to be consumed again later.
    - If `requeue` is false (default), the message status is set to 'failed'.
    Uses a transaction with SELECT FOR UPDATE. Requires authentication.
    """
    action = "requeued (pending)" if requeue else "marked as failed"
    log_info(f"❌ POST /messages/{message_id}/nack request by '{current_user}' (requeue={requeue})", icon_type='MSG')
    try:
        # Start transaction for atomic find-and-update
        async with in_transaction("default") as tx:
            # Find the message by ID *only if its status is 'processing'*, lock it, using the transaction
            message = await Message.filter(id=message_id, status='processing') \
                                   .using_connection(tx) \
                                   .select_for_update() \
                                   .get_or_none()

            # Check if the message was found in the correct state
            if not message:
                # If not found in 'processing' state, check if it exists at all or has a different status
                existing_msg_status = await Message.filter(id=message_id) \
                                                   .using_connection(tx) \
                                                   .values_list('status', flat=True) \
                                                   .first()
                if existing_msg_status:
                    # Message exists but is not 'processing'
                    log_warning(f"NACK failed for message {message_id}: Expected status 'processing', found '{existing_msg_status}'.", icon_type='MSG')
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"Message {message_id} is in status '{existing_msg_status}', cannot NACK. Only 'processing' messages can be negatively acknowledged."
                    )
                else:
                    # Message ID does not exist
                    log_warning(f"NACK failed: Message {message_id} not found.", icon_type='MSG')
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Message with ID {message_id} not found."
                    )

            # Message found and is 'processing'. Determine the new status based on 'requeue' flag.
            new_status = 'pending' if requeue else 'failed'
            message.status = new_status
            message.updated_at = datetime.now(timezone.utc)
            # Save changes using the transaction connection
            await message.save(using_connection=tx, update_fields=['status', 'updated_at'])
            # Transaction commits automatically here

        log_success(f"✅ Message ID {message_id} NACK'd successfully by '{current_user}' (status -> {new_status}).", icon_type='MSG')
        # Optionally update stats
        # background_tasks.add_task(update_broker_stats)
        return {"detail": f"Message {message_id} successfully {action}."}

    except HTTPException:
        raise # Re-raise 404, 409
    except IntegrityError as e:
         log_warning(f"DB integrity error during NACK for message {message_id}: {e}", icon_type='DB')
         raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Database conflict during message NACK operation.")
    except Exception as e:
        log_error(f"Error NACK'ing message {message_id} (action: {action}): {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error negatively acknowledging message (action: {action})")

# --- GraphQL Setup ---
# This section defines the Strawberry GraphQL schema and resolvers, providing an alternative API interface.
log_info("🍓 Configuring GraphQL endpoint with Strawberry...", icon_type='GRAPHQL')

# --- GraphQL Object Types (mirroring Pydantic/ORM models) ---
@strawberry.type(description="Represents a message in a queue")
class MessageGQL:
    id: strawberry.ID # Use strawberry.ID for GraphQL IDs
    queue_name: str = strawberry.field(description="Name of the queue this message belongs to")
    content: str
    status: str
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_orm(cls, model: Message, queue_name_str: str) -> "MessageGQL":
         """Helper to create MessageGQL from Tortoise Message model."""
         return cls(
             id=strawberry.ID(str(model.id)), # Convert int ID to string for GraphQL ID
             queue_name=queue_name_str,
             content=model.content,
             status=model.status,
             created_at=model.created_at,
             updated_at=model.updated_at
         )

@strawberry.type(description="Represents a message queue")
class QueueGQL:
    id: strawberry.ID
    name: str
    created_at: datetime
    updated_at: datetime

    @strawberry.field(description="Retrieves the current count of messages in this queue")
    async def message_count(self, info: Info) -> int:
        """Resolver for the message count field."""
        log_pipeline(f"GQL: Resolving message_count for Queue ID {self.id}", icon_type='GRAPHQL')
        try:
            # Convert Strawberry ID back to int for DB query
            return await Message.filter(queue_id=int(self.id)).count()
        except ValueError: # Handle invalid ID format
             log_error(f"GQL message_count: Invalid ID format '{self.id}'", icon_type='GRAPHQL')
             return 0
        except Exception as e:
            log_error(f"GQL message_count resolver error for queue ID {self.id}: {e}", exc_info=True, icon_type='GRAPHQL')
            return 0 # Return 0 on unexpected errors

    @strawberry.field(description="Retrieves messages belonging to this queue, with filtering and pagination")
    async def messages(
        self, info: Info, # Strawberry passes context via info
        status: Optional[str] = strawberry.field(default=None, description="Filter by message status (e.g., pending, processing, processed, failed)"),
        limit: int = strawberry.field(default=10, description="Maximum number of messages to return (1-100)"),
        offset: int = strawberry.field(default=0, description="Number of messages to skip (for pagination)")
    ) -> List[MessageGQL]:
        """Resolver for retrieving messages within a queue."""
        log_pipeline(f"GQL: Resolving messages for Queue ID {self.id} (status={status}, limit={limit}, offset={offset})", icon_type='GRAPHQL')
        # Validate status filter
        valid_statuses = ['pending', 'processing', 'processed', 'failed']
        if status and status not in valid_statuses:
            raise ValueError(f"Invalid status filter: '{status}'. Must be one of {valid_statuses}.")

        # Clamp limit to a reasonable range (prevent excessive data retrieval)
        limit = max(1, min(limit, 100))
        # Ensure offset is non-negative
        offset = max(0, offset)

        try:
             queue_id_int = int(self.id) # Convert GQL ID to int
             # Build the query
             query = Message.filter(queue_id=queue_id_int)
             if status:
                 query = query.filter(status=status)
             # Apply ordering, offset, and limit
             messages_db = await query.order_by('-created_at').offset(offset).limit(limit)

             # Convert ORM models to GraphQL types (Need queue name for MessageGQL)
             return [MessageGQL.from_orm(m, queue_name_str=self.name) for m in messages_db]
        except ValueError as ve: # Handles invalid ID or status
             log_warning(f"GQL messages resolver validation error for queue ID {self.id}: {ve}", icon_type='GRAPHQL')
             raise ve # Let Strawberry handle user input validation errors by raising them
        except Exception as e:
             log_error(f"GQL messages resolver error for queue ID {self.id}: {e}", exc_info=True, icon_type='GRAPHQL')
             return [] # Return empty list on internal server error

# --- GraphQL Root Query Type ---
@strawberry.type
class QueryGQL:
    @strawberry.field(description="Retrieves a list of all available message queues")
    async def all_queues(self, info: Info) -> List[QueueGQL]:
        """Resolver for the root 'allQueues' query."""
        log_info("🍓 GraphQL Query: all_queues", icon_type='GRAPHQL')
        try:
             queues_db = await Queue.all().order_by('name')
             # Convert ORM models to GraphQL types
             # Note: message_count resolver for each queue will be called by Strawberry if requested in the GQL query
             return [
                 QueueGQL(id=strawberry.ID(str(q.id)), name=q.name, created_at=q.created_at, updated_at=q.updated_at)
                 for q in queues_db
             ]
        except Exception as e:
            log_error(f"GraphQL 'all_queues' resolver error: {e}", icon_type='GRAPHQL', exc_info=True)
            return [] # Return empty list on error

    @strawberry.field(description="Retrieves a specific message queue by its unique name")
    async def queue_by_name(self, info: Info, name: str) -> Optional[QueueGQL]:
        """Resolver for the root 'queueByName' query."""
        log_info(f"🍓 GraphQL Query: queue_by_name (name='{name}')", icon_type='GRAPHQL')
        try:
            queue_db = await Queue.get_or_none(name=name)
            if queue_db:
                # Convert ORM model to GraphQL type
                return QueueGQL(id=strawberry.ID(str(queue_db.id)), name=queue_db.name, created_at=queue_db.created_at, updated_at=queue_db.updated_at)
            else:
                log_warning(f"GraphQL: Queue '{name}' not found via queue_by_name.", icon_type='GRAPHQL')
                return None # Return null if not found
        except Exception as e:
            log_error(f"GraphQL 'queue_by_name' resolver error for name '{name}': {e}", icon_type='GRAPHQL', exc_info=True)
            return None # Return null on error

    @strawberry.field(description="Retrieves a specific message by its unique ID")
    async def message_by_id(self, info: Info, id: strawberry.ID) -> Optional[MessageGQL]:
        """Resolver for the root 'messageById' query."""
        log_info(f"🍓 GraphQL Query: message_by_id (id={id})", icon_type='GRAPHQL')
        try:
            message_id_int = int(id) # Convert GQL ID string to int
            # Fetch message and its related queue in one query
            message_db = await Message.get_or_none(id=message_id_int).select_related('queue')

            if message_db and message_db.queue: # Ensure message and its queue exist
                # Convert ORM model to GraphQL type, passing the queue name
                return MessageGQL.from_orm(message_db, queue_name_str=message_db.queue.name)
            else:
                log_warning(f"GraphQL: Message ID {id} not found or has no associated queue.", icon_type='GRAPHQL')
                return None # Return null if not found or queue is missing
        except (ValueError, DoesNotExist): # Handle invalid ID format or message not found
            log_warning(f"GraphQL: Message ID {id} not found or invalid format.", icon_type='GRAPHQL')
            return None
        except Exception as e:
            log_error(f"GraphQL 'message_by_id' resolver error for ID {id}: {e}", icon_type='GRAPHQL', exc_info=True)
            return None

# --- GraphQL Root Mutation Type ---
@strawberry.type
class MutationGQL:
    @strawberry.mutation(description="Creates a new message queue")
    async def create_queue(self, info: Info, name: str) -> QueueGQL:
         """Resolver for the 'createQueue' mutation."""
         log_info(f"🍓 GraphQL Mutation: create_queue (name='{name}')", icon_type='GRAPHQL')
         # Add authentication check using context if needed
         # context = info.context
         # if not context.get("current_user"): raise Exception("Authentication required")
         try:
             # Validate name format (redundant if using Pydantic input type, but good practice here)
             if not re.match(r"^[a-zA-Z0-9_-]+$", name):
                 raise ValueError("Invalid queue name format. Use alphanumeric, underscore, hyphen.")
             if len(name) > 255:
                 raise ValueError("Queue name exceeds maximum length of 255 characters.")

             # Use get_or_create for atomicity
             new_queue, created = await Queue.get_or_create(name=name)
             if not created:
                 # Raise exception for Strawberry to format as a GraphQL error
                 raise Exception(f"Queue with name '{name}' already exists.")
             log_success(f"GQL: Queue '{name}' created (ID: {new_queue.id}).", icon_type='QUEUE')
             # Convert ORM model to GQL type for the response
             return QueueGQL(id=strawberry.ID(str(new_queue.id)), name=new_queue.name, created_at=new_queue.created_at, updated_at=new_queue.updated_at)
         except ValueError as ve: # Catch validation errors
              log_warning(f"GraphQL 'create_queue' validation error for name '{name}': {ve}", icon_type='GRAPHQL')
              raise Exception(str(ve)) # Re-raise with message
         except Exception as e:
             log_error(f"GraphQL 'create_queue' mutation error for name '{name}': {e}", icon_type='GRAPHQL', exc_info=True)
             # Re-raise for Strawberry to handle, providing a user-friendly message
             raise Exception(f"Failed to create queue '{name}': {e}")

    @strawberry.mutation(description="Deletes a queue and all its associated messages")
    async def delete_queue(self, info: Info, name: str) -> bool:
        """Resolver for the 'deleteQueue' mutation."""
        log_info(f"🍓 GraphQL Mutation: delete_queue (name='{name}')", icon_type='GRAPHQL')
        # Add authentication check if needed
        try:
            queue = await Queue.get_or_none(name=name)
            if not queue:
                raise Exception(f"Queue with name '{name}' not found.")
            await queue.delete() # Cascade delete handled by ORM relationship
            log_success(f"GQL: Queue '{name}' deleted successfully.", icon_type='QUEUE')
            return True # Return true on success
        except Exception as e:
            log_error(f"GraphQL 'delete_queue' mutation error for name '{name}': {e}", icon_type='GRAPHQL', exc_info=True)
            raise Exception(f"Failed to delete queue '{name}': {e}") # Re-raise for Strawberry

    @strawberry.mutation(description="Publishes a message to a specified queue")
    async def publish_message(self, info: Info, queue_name: str, content: str) -> MessageGQL:
        """Resolver for the 'publishMessage' mutation."""
        log_info(f"🍓 GraphQL Mutation: publish_message (queue='{queue_name}')", icon_type='GRAPHQL')
        # Add authentication check if needed
        try:
            # Validate content length (example)
            if not content:
                 raise ValueError("Message content cannot be empty.")

            queue = await Queue.get_or_none(name=queue_name)
            if not queue:
                raise Exception(f"Queue with name '{queue_name}' not found.")

            # Create the message
            new_message = await Message.create(queue=queue, content=content, status='pending')
            log_success(f"GQL: Message ID {new_message.id} published to queue '{queue_name}'.", icon_type='MSG')
            # Convert ORM model to GQL type for the response
            return MessageGQL.from_orm(new_message, queue_name_str=queue_name)
        except ValueError as ve:
             log_warning(f"GraphQL 'publish_message' validation error to queue '{queue_name}': {ve}", icon_type='GRAPHQL')
             raise Exception(str(ve))
        except Exception as e:
            log_error(f"GraphQL 'publish_message' mutation error to queue '{queue_name}': {e}", icon_type='GRAPHQL', exc_info=True)
            raise Exception(f"Failed to publish message to queue '{queue_name}': {e}")

# --- GraphQL Context Getter ---
async def get_graphql_context(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    # Use Bearer scheme for GraphQL Authorization header
    auth: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
) -> Dict:
    """
    Provides context dictionary accessible within GraphQL resolvers via `info.context`.
    Includes request/response objects, background tasks, and attempts to authenticate the user.
    """
    context = {
        "request": request,
        "response": response,
        "background_tasks": background_tasks,
        "current_user": None # Default to unauthenticated
    }
    if auth:
        try:
            # Attempt to validate the access token provided in the Authorization: Bearer header
            username = await _decode_token(auth.credentials, "access")
            context["current_user"] = username # Set username in context if valid
            log_debug(f"🍓 GraphQL request authenticated for user: '{username}'", icon_type='AUTH')
        except HTTPException as auth_exc:
            # Log failed auth attempts but don't block the request here.
            # Individual resolvers should check `info.context["current_user"]` if they require auth.
            log_warning(f"GraphQL authentication failed: {auth_exc.detail} (Status: {auth_exc.status_code})", icon_type='AUTH')
            # Optionally, you could set an error flag in the context: context["auth_error"] = auth_exc.detail
    else:
         log_debug("🍓 GraphQL request is unauthenticated (no Bearer token found).", icon_type='AUTH')

    return context

# --- GraphQL Schema and Router Setup ---
gql_schema = strawberry.Schema(query=QueryGQL, mutation=MutationGQL)
graphql_app = GraphQLRouter(
    gql_schema,
    context_getter=get_graphql_context, # Function to create the context dict
    graphiql=False, # Disable default GraphiQL
    graphql_ide="apollo-sandbox" # Use Apollo Sandbox (provides more features) hosted by Strawberry
    # Or set to None to disable the IDE: graphql_ide=None
)
# Include the GraphQL router in the main FastAPI application
app.include_router(graphql_app, prefix="/graphql", tags=["GraphQL"], include_in_schema=True) # include_in_schema adds it to OpenAPI docs
log_success("🍓 GraphQL endpoint /graphql configured with Apollo Sandbox IDE.", icon_type='GRAPHQL')

# --- Global Exception Handlers ---
# These handlers catch specific exceptions that might occur anywhere in the app
# and return standardized JSON error responses.

@app.exception_handler(DoesNotExist)
async def tortoise_does_not_exist_handler(request: Request, exc: DoesNotExist):
    """Handles Tortoise ORM's DoesNotExist errors globally, returning 404."""
    # Try to extract model name from the exception string for better context
    model_name_match = str(exc).split(":")
    model_name = model_name_match[0].strip() if len(model_name_match) > 0 else "Resource"
    detail = f"{model_name} not found."
    client_host = request.client.host if request.client else "N/A"
    log_warning(f"Resource Not Found (DB DoesNotExist): {exc} ({request.method} {request.url.path})", icon_type='DB', extra={"client": client_host})
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": detail}
    )

@app.exception_handler(IntegrityError)
async def tortoise_integrity_error_handler(request: Request, exc: IntegrityError):
    """Handles Tortoise ORM's IntegrityError (e.g., unique constraint violations), returning 409."""
    detail = "Database conflict occurred."
    # Try to get more specific error info from the exception arguments (driver-dependent)
    # Be cautious about leaking internal details
    error_info_str = str(exc) # Get the base error string
    if "UNIQUE constraint failed" in error_info_str:
        detail = "A resource with the same unique identifier already exists."
    elif settings.APP_ENV == 'development': # Show more details only in dev
        detail += f" Error: {error_info_str}"

    client_host = request.client.host if request.client else "N/A"
    log_warning(f"Database Integrity Conflict: {exc} ({request.method} {request.url.path})", icon_type='DB', extra={"client": client_host})
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"detail": detail}
    )

@app.exception_handler(ValidationError)
async def pydantic_validation_exception_handler(request: Request, exc: ValidationError):
    """Handles Pydantic validation errors (e.g., invalid request body/params), returning 422."""
    client_host = request.client.host if request.client else "N/A"
    try:
        # Use Pydantic's json() method for standardized error output
        error_content = {"detail": "Request validation failed", "errors": json.loads(exc.json())}
        log_warning(f"Request Validation Error (Pydantic): {error_content['errors']} ({request.method} {request.url.path})", icon_type='HTTP', extra={"client": client_host})
    except Exception as json_err: # Fallback if json.loads fails for some reason
        log_error(f"Error parsing Pydantic validation errors: {json_err}", icon_type="ERROR")
        error_content = {"detail": "Request validation failed", "errors": str(exc)} # Simple string representation
        log_warning(f"Request Validation Error (Pydantic - raw): {str(exc)} ({request.method} {request.url.path})", icon_type='HTTP', extra={"client": client_host})

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_content
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handles FastAPI's built-in HTTPExceptions, ensuring consistent logging and response format."""
    # Determine log level based on status code (warnings for 4xx, errors for 5xx)
    log_level = log_warning if 400 <= exc.status_code < 500 else log_error
    icon = 'HTTP' if 400 <= exc.status_code < 500 else 'ERROR'
    client_host = request.client.host if request.client else "N/A"
    log_level(
        f"HTTP Error Handled: Status={exc.status_code}, Detail='{exc.detail}' ({request.method} {request.url.path})",
        icon_type=icon,
        extra={"client": client_host, "headers": exc.headers} # Log associated headers (like WWW-Authenticate)
    )
    # Return the standard JSON response using details and headers from the exception
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None) # Include headers if the exception has them
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Handles any other unhandled exceptions as a generic 500 Internal Server Error.
    Logs the error critically and returns a safe error message to the client.
    """
    # Format traceback for logging
    tb_str = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    client_host = request.client.host if request.client else "N/A"
    error_time = datetime.now(timezone.utc)

    # Log critically, including a traceback summary
    log_critical(
        f"Unhandled Internal Server Error: {type(exc).__name__}: {exc} ({request.method} {request.url.path})",
        icon_type='CRITICAL',
        exc_info=False, # Avoid duplicating full traceback if JsonFormatter logs it
        extra={
            "client": client_host,
            # Log full traceback only in development for security/verbosity reasons
            "full_traceback": tb_str if settings.APP_ENV == 'development' else "Traceback hidden in production"
        }
    )
    # Update app stats to indicate the last error (store datetime object)
    async with stats_lock:
        app_stats["last_error"] = f"Unhandled {type(exc).__name__} at {request.method} {request.url.path}"
        app_stats["last_error_timestamp"] = error_time # <<< Store datetime object

    # Return a generic 500 response to the client
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected internal server error occurred. Please contact the administrator or check server logs."}
    )

# --- Main Execution Block ---
if __name__ == '__main__':
    # Add missing import for regex used in GraphQL mutation validation
    import re

    log_info("🏁 Main execution block entered...", icon_type='SETUP')

    # --- SSL Certificate Check/Generation ---
    log_info("Checking for SSL certificate and key...", icon_type='SEC')
    try:
        # Ensure certificate directory exists
        os.makedirs(settings.CERT_DIR, exist_ok=True)
        cert_exists = os.path.exists(settings.CERT_FILE)
        key_exists = os.path.exists(settings.KEY_FILE)

        if cert_exists and key_exists:
            log_success(f"🛡️ SSL Certificate '{os.path.basename(settings.CERT_FILE)}' and Key '{os.path.basename(settings.KEY_FILE)}' found in '{settings.CERT_DIR}'.", icon_type='SEC')
            # Optional: Add check for certificate expiry here if needed
        else:
            missing = [f for f, exists in [(os.path.basename(settings.CERT_FILE), cert_exists), (os.path.basename(settings.KEY_FILE), key_exists)] if not exists]
            log_warning(f"SSL file(s) not found: {', '.join(missing)}. Attempting to generate new self-signed certificate for 'localhost'...", icon_type='SEC')
            try:
                if not generate_self_signed_cert(settings.CERT_FILE, settings.KEY_FILE, common_name="localhost"):
                    log_critical("Critical failure generating self-signed SSL certificates. Cannot start server with HTTPS.", icon_type='CRITICAL')
                    sys.exit(1) # Exit if generation fails
                else:
                     log_success("✅ Successfully generated new self-signed SSL certificate and key.", icon_type='SEC')
            except Exception as cert_gen_e:
                log_critical(f"Unexpected error during certificate generation: {cert_gen_e}", icon_type='CRITICAL', exc_info=True)
                sys.exit(1)
    except Exception as setup_e:
        log_critical(f"Unexpected error during initial certificate setup check: {setup_e}", icon_type='CRITICAL', exc_info=True)
        sys.exit(1)

    # --- Log Final Configuration Summary ---
    log_info("=== Configuration Summary ===", icon_type='SETUP')
    log_info(f"  Project: {settings.PROJECT_NAME} v{settings.VERSION}", icon_type='INFO')
    log_info(f"  Environment: {settings.APP_ENV}", icon_type='INFO')
    log_info(f"  Log Level: {settings.LOG_LEVEL_STR}", icon_type='LOGS')
    log_info(f"  JWT Secret: {'Set via Env Var' if 'JWT_SECRET_KEY' in os.environ and 'CHANGE_ME' not in settings.JWT_SECRET_KEY else 'Using Generated/Default (INSECURE FOR PROD)'}", icon_type='AUTH')
    log_info(f"  DB Path: {settings.DB_PATH}", icon_type='DB')
    log_info(f"  Rate Limit (Default): {settings.DEFAULT_RATE_LIMIT}", icon_type='RATELIMIT')
    log_info(f"  Rate Limit (High Traffic): {settings.HIGH_TRAFFIC_RATE_LIMIT}", icon_type='RATELIMIT')
    log_info(f"  CORS Origins: {settings.ALLOWED_ORIGINS}", icon_type='HTTP')
    log_info(f"  Log Dir: {settings.LOG_DIR} (Current File: {os.path.basename(LOG_FILENAME)})", icon_type='LOGS')
    log_info(f"  Cert Dir: {settings.CERT_DIR}", icon_type='SEC')
    log_info(f"============================", icon_type='SETUP')

    # --- Determine Uvicorn settings ---
    # Enable auto-reload only in development environment
    reload_enabled = settings.APP_ENV == "development"
    if reload_enabled:
        log_warning("Running in DEVELOPMENT mode with auto-reload enabled.", icon_type='SETUP')

    # Map FastAPI log level to Uvicorn log level string
    # Uvicorn levels: 'critical', 'error', 'warning', 'info', 'debug', 'trace'
    log_level_uvicorn = settings.LOG_LEVEL_STR.lower()
    # Adjust if necessary (e.g., FastAPI DEBUG might map to uvicorn debug/trace)
    if log_level_uvicorn == 'debug' and reload_enabled:
        log_level_uvicorn = 'debug' # Keep debug for dev reload
    elif log_level_uvicorn == 'debug':
         # Avoid overly verbose uvicorn logs in non-reloading debug mode unless explicitly desired
        log_level_uvicorn = 'info'

    # --- Start Uvicorn Server ---
    log_info(f"🌐🚀 Starting Uvicorn server on https://0.0.0.0:{settings.API_PORT}", icon_type='STARTUP', extra={"reload": reload_enabled, "log_level": log_level_uvicorn})
    log_info(f"   Access API root at: https://localhost:{settings.API_PORT}/", icon_type='HTTP')
    log_info(f"   Swagger UI docs:  https://localhost:{settings.API_PORT}/docs", icon_type='HTTP')
    log_info(f"   ReDoc docs:       https://localhost:{settings.API_PORT}/redoc", icon_type='HTTP')
    log_info(f"   GraphQL endpoint: https://localhost:{settings.API_PORT}/graphql (Apollo Sandbox IDE)", icon_type='GRAPHQL')
    log_info("   Press Ctrl+C to stop the server.", icon_type='INFO')

    try:
        uvicorn.run(
            "__main__:app", # Points to the 'app' instance in this file when run directly
            host="0.0.0.0", # Listen on all available network interfaces
            port=settings.API_PORT,
            log_level=log_level_uvicorn, # Set Uvicorn's internal logging level
            ssl_keyfile=settings.KEY_FILE, # Path to SSL private key
            ssl_certfile=settings.CERT_FILE, # Path to SSL certificate
            reload=reload_enabled, # Enable auto-reload if in development
            use_colors=True, # Use colors in Uvicorn's console output if terminal supports it
            # Disable uvicorn access logs if our middleware/logging is sufficient
            access_log=False # Set to True if you want uvicorn's default access logs
        )
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        log_info("\n🚦 Server shutdown requested via Keyboard Interrupt (Ctrl+C).", icon_type='SHUTDOWN')
    except SystemExit as e:
         # Handle sys.exit() calls (e.g., from failed startup checks)
         log_info(f"🚦 Server exited with code {e.code}.", icon_type='SHUTDOWN')
    except Exception as e:
        # Catch potential errors during Uvicorn startup (e.g., port already in use)
        log_critical(f"❌ Fatal: Failed to start or run Uvicorn server: {e}", exc_info=True)
        sys.exit(1) # Exit with error code if Uvicorn fails to start
    finally:
        # This block runs after Uvicorn stops, regardless of the reason
        log_info("🏁 Uvicorn server process has finished.", icon_type='SHUTDOWN')