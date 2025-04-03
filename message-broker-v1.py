# -*- coding: utf-8 -*-
"""
Async Message Broker API V3.1.1 - FastAPI + Tortoise ORM + SQLite (Refactored)
----------------------------------------------------------------------------
Features:
- FastAPI async web framework
- Tortoise ORM with SQLite backend
- JWT Authentication (access & refresh tokens) via python-jose
- Message Queues (Create, List, Delete)
- Message Handling (Publish, Consume (async safe), Ack, Nack)
- Server-Sent Events (SSE) via StreamingResponse + Redis Pub/Sub
- Rate Limiting via SlowAPI + Redis
- GraphQL endpoint via Strawberry-graphql
- System Stats collection (psutil)
- Self-signed certificate generation
- Structured JSON and colored console logging
- Automatic OpenAPI/Swagger documentation
- Improved error handling, async operations, and code structure.
"""

# --- Standard Library Imports ---
import asyncio
import json
import logging
import os
import platform
import secrets
import sys
import time
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Union, AsyncGenerator
from collections import deque # For efficient log tailing

# --- Hashing ---
import hashlib
# from passlib.context import CryptContext # Recommended for password hashing (see login endpoint)

# --- Third-Party Imports ---
try:
    # Core FastAPI & ASGI
    from fastapi import (FastAPI, Request, Response, Depends, HTTPException, status,
                         BackgroundTasks, Path, Query as FastQuery)
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import (OAuth2PasswordBearer, OAuth2PasswordRequestForm,
                                  HTTPBearer, HTTPAuthorizationCredentials)
    from fastapi.responses import JSONResponse, StreamingResponse
    import uvicorn

    # JWT Handling
    from jose import JWTError, jwt
    # Use Field for validation, EmailStr for user examples
    from pydantic import BaseModel, ValidationError, Field, EmailStr, ConfigDict

    # Database (Tortoise ORM)
    from tortoise import Tortoise, fields, models
    # from tortoise.contrib.fastapi import register_tortoise # Not needed with lifespan
    from tortoise.exceptions import DoesNotExist, IntegrityError

    # Logging & Output
    from colorama import init, Fore, Style

    # Certificates
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # System Stats
    import psutil

    # Utilities
    from werkzeug.utils import secure_filename

    # Rate Limiting
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware

    # GraphQL
    import strawberry
    from strawberry.fastapi import GraphQLRouter
    from strawberry.types import Info

    # Redis Client (for SSE Pub/Sub and Rate Limiting)
    import redis.asyncio as aioredis # Use async redis client

except ImportError as e:
    missing_pkg = str(e).split("'")[-2]
    print(f"\nERROR: Missing dependency '{missing_pkg}'.")
    print("Please install all required packages by running:")
    print("\n  pip install fastapi uvicorn[standard] tortoise-orm aiosqlite pydantic[email] python-jose[cryptography] passlib[bcrypt] colorama cryptography psutil Werkzeug slowapi redis strawberry-graphql[fastapi] Jinja2\n")
    # Jinja2 needed by slowapi internals
    sys.exit(1)

# --- Initialize Colorama ---
init(autoreset=True)

# --- Configuration ---
class Settings:
    PROJECT_NAME: str = "Message Broker API V3.1.1 (FastAPI/Refactored)"
    VERSION: str = "0.3.1.1-fastapi-tortoise"
    API_PORT: int = 8777
    # Secrets (Use environment variables for production!)
    JWT_SECRET_KEY: str = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 1 # 1 hour
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    # Database (SQLite Async with Tortoise ORM)
    DB_DIR: str = 'databases'
    DB_FILENAME: str = 'message_broker_v3.db'
    DB_PATH: str = os.path.abspath(os.path.join(DB_DIR, DB_FILENAME))
    DATABASE_URL: str = f"sqlite:///{DB_PATH}" # Use triple slash for relative paths if needed, but absolute is safer
    # Redis (For SSE & Rate Limiting)
    REDIS_HOST: str = os.environ.get('REDIS_HOST', 'localhost')
    REDIS_PORT: int = int(os.environ.get('REDIS_PORT', 6379))
    REDIS_URL: str = f"redis://{REDIS_HOST}:{REDIS_PORT}"
    REDIS_SSE_DB: int = 0 # Use DB 0 for SSE Pub/Sub
    REDIS_RATE_LIMIT_DB: int = 1 # Use DB 1 for Rate Limiting
    # Directories
    LOG_DIR: str = 'logs_v3'
    CERT_DIR: str = 'certs_v3'
    # Files
    CERT_FILE: str = os.path.join(CERT_DIR, 'cert.pem')
    KEY_FILE: str = os.path.join(CERT_DIR, 'key_nopass.pem')
    # CORS
    ALLOWED_ORIGINS: List[str] = ["*"] # Be more specific in production
    # Rate Limiting
    DEFAULT_RATE_LIMIT: str = "100/minute"
    # Logging
    LOG_LEVEL_STR: str = os.environ.get("LOG_LEVEL", "INFO").upper()
    LOG_LEVEL: int = getattr(logging, LOG_LEVEL_STR, logging.INFO)
    LOG_FORMAT_CONSOLE: str = '%(asctime)s - %(levelname)s - %(message)s'
    # Env type for reload/debug toggle
    APP_ENV: str = os.environ.get("APP_ENV", "production").lower()

settings = Settings()

# --- Create Directories ---
os.makedirs(settings.LOG_DIR, exist_ok=True)
os.makedirs(settings.CERT_DIR, exist_ok=True)
os.makedirs(settings.DB_DIR, exist_ok=True)

# --- Logging Setup ---
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
unique_hash = hashlib.sha1(str(os.getpid()).encode()).hexdigest()[:8]
LOG_FILENAME = os.path.join(settings.LOG_DIR, f"broker_log_{timestamp}_{unique_hash}.json")

# --- Logging Setup ---
# ... (timestamp, unique_hash, LOG_FILENAME remain the same) ...

class ColoramaFormatter(logging.Formatter):
    LEVEL_COLORS = { logging.DEBUG: Fore.CYAN, logging.INFO: Fore.GREEN, logging.WARNING: Fore.YELLOW, logging.ERROR: Fore.RED, logging.CRITICAL: Fore.MAGENTA }
    LEVEL_ICONS = { logging.DEBUG: "⚙️ ", logging.INFO: "ℹ️ ", logging.WARNING: "⚠️ ", logging.ERROR: "❌ ", logging.CRITICAL: "🔥 ", 'SUCCESS': "✅ ", 'PIPELINE': "➡️ ", 'DB': "💾 ", 'AUTH': "🔑 ", 'QUEUE': "📥 ", 'MSG': "✉️ ", 'HTTP': "🌐 ", 'STATS': "📊 ", 'LOGS': "📄 ", 'SEC': "🛡️ ", 'ASYNC': "⚡ ", 'GRAPHQL': "🍓 ", 'SSE': "📡 ", 'RATELIMIT': "⏱️ ", 'STARTUP': '🚀', 'SHUTDOWN': '🛑'}
    # --- CORRECTED FORMAT METHOD ---
    def format(self, record):
        level_color = self.LEVEL_COLORS.get(record.levelno, Fore.WHITE)
        icon_type = getattr(record, 'icon_type', record.levelname) # Use icon_type if provided
        icon = self.LEVEL_ICONS.get(icon_type, "")

        # record.asctime is already formatted by the time format() is called,
        # based on the datefmt provided during Formatter initialization or to the Handler.
        # We will set the datefmt when creating the formatter instance below.
        log_message_content = f"[{record.levelname}] {icon}{record.getMessage()}"
        log_line = f"{record.asctime} - {record.name} - {level_color}{Style.BRIGHT}{log_message_content}{Style.RESET_ALL}"
        return log_line

class JsonFormatter(logging.Formatter):
    # Keep your existing JsonFormatter as it correctly uses datetime.isoformat()
    def formatTime(self, record, datefmt=None):
        return datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

    def format(self, record):
        log_record = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'name': record.name,
            'pid': record.process,
            'thread': record.threadName,
            'message': record.getMessage(),
            'pathname': record.pathname,
            'lineno': record.lineno,
        }
        if hasattr(record, 'icon_type'):
            log_record['icon_type'] = record.icon_type
        if hasattr(record, 'extra_data') and isinstance(record.extra_data, dict):
            log_record.update(record.extra_data)
        if record.exc_info:
            log_record['exception'] = {
                'type': record.exc_info[0].__name__,
                'value': str(record.exc_info[1]),
                'traceback': "".join(traceback.format_exception(*record.exc_info)) if settings.APP_ENV == 'development' else 'Traceback hidden in production'
            }
        return json.dumps(log_record, ensure_ascii=False, default=str)

# Configure root logger slightly differently if needed, but focusing on app logger
logger = logging.getLogger("MessageBroker")
logger.setLevel(settings.LOG_LEVEL)
logger.propagate = False # Prevent duplicate logs if root logger also has handlers

# Define the date format string ONCE
DATE_FORMAT = '%Y-%m-%d %H:%M:%S' # REMOVED %f

# Avoid adding handlers multiple times if script is reloaded
if not logger.handlers:
    # --- CONSOLE HANDLER ---
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(settings.LOG_LEVEL)
    # Instantiate the formatter and pass the date format
    console_formatter = ColoramaFormatter(datefmt=DATE_FORMAT)
    console_handler.setFormatter(console_formatter)

    # --- FILE HANDLER ---
    file_handler = logging.FileHandler(LOG_FILENAME, mode='a', encoding='utf-8')
    file_handler.setLevel(settings.LOG_LEVEL)
    # JsonFormatter handles its own timestamp formatting internally, no datefmt needed here
    file_formatter = JsonFormatter()
    file_handler.setFormatter(file_formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

# --- Logging Helper Functions ---
# ... (keep your log_debug, log_info, etc. functions as they are) ...

# --- Logging Helper Functions ---
def log_debug(message: str, icon_type: str = 'DEBUG', extra: Optional[Dict[str, Any]] = None): logger.debug(message, extra={'icon_type': icon_type, 'extra_data': extra or {}})
def log_info(message: str, icon_type: str = 'INFO', extra: Optional[Dict[str, Any]] = None): logger.info(message, extra={'icon_type': icon_type, 'extra_data': extra or {}})
def log_success(message: str, icon_type: str = 'SUCCESS', extra: Optional[Dict[str, Any]] = None): logger.info(message, extra={'icon_type': icon_type, 'extra_data': extra or {}})
def log_warning(message: str, icon_type: str = 'WARNING', extra: Optional[Dict[str, Any]] = None): logger.warning(message, extra={'icon_type': icon_type, 'extra_data': extra or {}})
def log_error(message: str, exc_info: bool = False, icon_type: str = 'ERROR', extra: Optional[Dict[str, Any]] = None): logger.error(message, exc_info=exc_info, extra={'icon_type': icon_type, 'extra_data': extra or {}})
def log_critical(message: str, exc_info: bool = False, icon_type: str = 'CRITICAL', extra: Optional[Dict[str, Any]] = None): logger.critical(message, exc_info=exc_info, extra={'icon_type': icon_type, 'extra_data': extra or {}})
def log_pipeline(message: str, icon_type: str = 'PIPELINE', extra: Optional[Dict[str, Any]] = None): logger.info(message, extra={'icon_type': icon_type, 'extra_data': extra or {}})


# --- Password Hashing Context ---
# !!! IMPORTANT SECURITY WARNING !!!
# The hardcoded 'admin':'admin' password in the /login route is INSECURE.
# For production, uncomment and use passlib for proper password hashing.
# Example:
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)
# def get_password_hash(password):
#     return pwd_context.hash(password)
# You would then store the HASHED password, not the plain one.


# --- Certificate Generation ---
def generate_self_signed_cert(cert_path: str, key_path: str, key_password: Optional[bytes] = None, common_name: str = "localhost"):
    log_info(f"🛡️ Generating new RSA private key and self-signed certificate for CN='{common_name}'...", icon_type='SEC')
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"XX"), x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Default"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Default"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Message Broker V3"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        # Add Subject Alternative Name (SAN) for browser compatibility (localhost + 127.0.0.1)
        san_extension = x509.SubjectAlternativeName([x509.DNSName(common_name), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
        import ipaddress # Need to import this

        cert_builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()) \
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)) \
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365)) \
            .add_extension(san_extension, critical=False) # Add SAN
        certificate = cert_builder.sign(private_key, hashes.SHA256(), default_backend())

        key_pem_encryption = serialization.NoEncryption()
        if key_password: key_pem_encryption = serialization.BestAvailableEncryption(key_password)
        with open(key_path, "wb") as f: f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=key_pem_encryption))
        log_success(f"🔑 Private key saved: {key_path}", icon_type='SEC')
        with open(cert_path, "wb") as f: f.write(certificate.public_bytes(serialization.Encoding.PEM))
        log_success(f"📜 Self-signed certificate saved: {cert_path}", icon_type='SEC')
        return True
    except ImportError:
        log_critical("The 'ipaddress' module is needed for certificate generation with IP SAN. Please install it.", icon_type='CRITICAL')
        return False
    except Exception as e:
        log_critical(f"Failed to generate certificates/key: {e}", exc_info=True, icon_type='CRITICAL')
        return False

# --- Application Statistics ---
app_stats: Dict[str, Any] = {
    "start_time": datetime.now(timezone.utc),
    "requests_total": 0, "requests_by_route": {}, "requests_by_status": {},
    "queues_total": 0, "messages_total": 0, "messages_pending": 0,
    "messages_processing": 0, "messages_processed": 0, "messages_failed": 0,
    "last_error": None,
    "system": {
        "python_version": platform.python_version(), "platform": platform.system(),
        "platform_release": platform.release(), "architecture": platform.machine(),
    },
    "broker_specific": {
        "framework": "FastAPI",
        "version": settings.VERSION,
        "db_engine": "sqlite (tortoise-orm)",
        "auth_method": "jwt (access+refresh, python-jose)",
        "notification": "sse (redis pub/sub)",
        "rate_limit": "redis (slowapi)",
        "graphql": "strawberry-graphql"
    }
}
stats_lock = asyncio.Lock() # Use asyncio Lock for safe async updates

async def update_request_stats(route_template: str, method: str, status_code: int):
    """Updates request counters asynchronously and safely."""
    async with stats_lock:
        app_stats["requests_total"] += 1
        route_stats = app_stats["requests_by_route"].setdefault(route_template, {})
        route_stats[method] = route_stats.get(method, 0) + 1
        app_stats["requests_by_status"][str(status_code)] = app_stats["requests_by_status"].get(str(status_code), 0) + 1

async def update_broker_stats():
    """Updates broker stats from the database asynchronously and concurrently."""
    log_pipeline("📊 Fetching broker stats from DB...", icon_type='STATS')
    try:
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
            # Clear last error on successful update if it was set
            if app_stats["last_error"] and "Broker Stats Update Failed" in app_stats["last_error"]:
                 app_stats["last_error"] = None

        log_success("📊 Broker stats updated.", icon_type='STATS', extra={'counts': {'queues': q_count, 'pending': pending, 'processing': processing, 'processed': processed, 'failed': failed}})

    except Exception as e:
        log_error(f"Error updating broker stats: {e}", icon_type='STATS', exc_info=True)
        async with stats_lock:
            app_stats["last_error"] = f"Broker Stats Update Failed: {datetime.now(timezone.utc).isoformat()}"

# --- Database Setup (Tortoise ORM with SQLite) ---
async def init_tortoise():
    """Initialize Tortoise ORM and create schemas if they don't exist."""
    log_info(f"💾 Configuring Tortoise ORM for SQLite: {settings.DATABASE_URL}", icon_type='DB')
    try:
        await Tortoise.init(
            db_url=settings.DATABASE_URL,
            modules={'models': ['__main__']} # Models are in this script
        )
        await Tortoise.generate_schemas(safe=True) # safe=True avoids errors if tables exist
        log_success("💾 ORM tables verified/created successfully.", icon_type='DB')
        await update_broker_stats() # Populate initial stats
    except Exception as e:
        log_critical(f"Fatal: Failed to initialize Tortoise ORM: {e}", icon_type='CRITICAL', exc_info=True)
        sys.exit(1)

# --- Pydantic Models (Input/Output Schemas) ---
class QueueBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Unique name for the queue")

class QueueCreate(QueueBase):
    pass

class QueueResponse(QueueBase):
    id: int
    created_at: datetime
    updated_at: datetime
    message_count: int = Field(default=0, description="Current number of messages in the queue")

    model_config = ConfigDict(from_attributes=True) # Pydantic v2 ORM mode

class MessageBase(BaseModel):
    content: str = Field(..., min_length=1, description="The content/payload of the message")

class MessageCreate(MessageBase):
    pass

class MessageResponse(MessageBase):
    id: int
    queue_id: int
    status: str = Field(description="Current status: pending, processing, processed, failed")
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class StatsResponse(BaseModel):
    start_time: str = Field(description="ISO 8601 timestamp when the server started (UTC)")
    uptime_seconds: float = Field(description="Server uptime in seconds")
    uptime_human: str = Field(description="Human-readable server uptime (e.g., 1d 2h 30m 15s)")
    requests_total: int
    requests_by_route: Dict[str, Dict[str, int]]
    requests_by_status: Dict[str, int] # Keys are string representations of status codes
    queues_total: int
    messages_total: int
    messages_pending: int
    messages_processing: int
    messages_processed: int
    messages_failed: int
    last_error: Optional[str] = Field(None, description="Timestamp and type of the last unhandled error, if any")
    system: Dict[str, Any] = Field(description="System metrics (CPU, Memory, Disk, etc.)")
    broker_specific: Dict[str, str] = Field(description="Broker implementation details")

class LogFileResponse(BaseModel):
    log_files: List[str]

# Payload Models for specific endpoints
class QueueCreatePayload(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)

class MessagePayload(BaseModel):
    content: str = Field(..., min_length=1)

class MessagePublishResponse(BaseModel):
    message: str = Field(default="Message published successfully")
    message_id: int

class MessageConsumeResponse(BaseModel):
    message_id: int
    queue: str
    content: str
    status: str = Field(default='processing') # Status after consumption
    retrieved_at: datetime

# --- Tortoise ORM Models ---
class Queue(models.Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=255, unique=True, index=True, description="Unique queue name")
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    # Relationship accessor from Message -> Queue
    messages: fields.ReverseRelation["Message"]

    class Meta:
        table = "queues"
        ordering = ["name"]

    def __str__(self):
        return self.name

class Message(models.Model):
    id = fields.IntField(pk=True)
    queue: fields.ForeignKeyRelation[Queue] = fields.ForeignKeyField(
        'models.Queue', related_name='messages', on_delete=fields.CASCADE, description="The queue this message belongs to"
    )
    content = fields.TextField(description="Message payload")
    status = fields.CharField(
        max_length=20, default='pending', index=True,
        description="Status: pending, processing, processed, failed"
    )
    created_at = fields.DatetimeField(auto_now_add=True, index=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "messages"
        # Composite index to speed up finding the oldest pending message in a queue
        indexes = [("queue_id", "status", "created_at")]
        ordering = ["created_at"] # Default ordering

    def __str__(self):
        return f"Message {self.id} ({self.status})"


# --- Redis Connection Pool ---
redis_sse_pool: Optional[aioredis.ConnectionPool] = None
redis_rate_limit_pool: Optional[aioredis.ConnectionPool] = None
redis_sse: Optional[aioredis.Redis] = None
redis_limiter_client: Optional[aioredis.Redis] = None

async def setup_redis():
    """Initializes Redis connection pools and clients."""
    global redis_sse_pool, redis_rate_limit_pool, redis_sse, redis_limiter_client
    try:
        log_pipeline("📡 Configuring Redis connections...", icon_type='SSE')
        redis_sse_pool = aioredis.ConnectionPool.from_url(f"{settings.REDIS_URL}/{settings.REDIS_SSE_DB}", decode_responses=True, max_connections=20, health_check_interval=30)
        redis_rate_limit_pool = aioredis.ConnectionPool.from_url(f"{settings.REDIS_URL}/{settings.REDIS_RATE_LIMIT_DB}", decode_responses=True, max_connections=20, health_check_interval=30)

        redis_sse = aioredis.Redis(connection_pool=redis_sse_pool)
        redis_limiter_client = aioredis.Redis(connection_pool=redis_rate_limit_pool)

        # Verify connections
        await redis_sse.ping()
        await redis_limiter_client.ping()
        log_success("📡 Redis connections established and verified.", icon_type='SSE')
        return True

    except aioredis.RedisError as e:
        log_critical(f"Fatal: Failed to connect to Redis at {settings.REDIS_URL}: {e}. SSE/Rate Limiting unavailable.", icon_type='CRITICAL', exc_info=True)
        # Allow startup without Redis? Depends on requirements. Set clients to None.
        redis_sse = None
        redis_limiter_client = None
        return False
    except Exception as e:
        log_critical(f"Fatal: Unexpected error during Redis setup: {e}", icon_type='CRITICAL', exc_info=True)
        redis_sse = None
        redis_limiter_client = None
        return False # Treat unexpected error as critical failure for Redis

async def shutdown_redis():
    """Closes Redis connections and pools gracefully."""
    log_pipeline("🔌 Closing Redis connections...", icon_type='SHUTDOWN')
    # Close clients first
    if redis_sse:
        try: await redis_sse.close()
        except Exception as e: log_warning(f"Error closing Redis SSE client: {e}", icon_type='SSE')
    if redis_limiter_client:
        try: await redis_limiter_client.close()
        except Exception as e: log_warning(f"Error closing Redis Limiter client: {e}", icon_type='RATELIMIT')
    # Then disconnect pools
    if redis_sse_pool:
        try: await redis_sse_pool.disconnect(inuse_connections=True)
        except Exception as e: log_warning(f"Error disconnecting Redis SSE pool: {e}", icon_type='SSE')
    if redis_rate_limit_pool:
        try: await redis_rate_limit_pool.disconnect(inuse_connections=True)
        except Exception as e: log_warning(f"Error disconnecting Redis Limiter pool: {e}", icon_type='RATELIMIT')
    log_success("🔌 Redis connections/pools closed.", icon_type='SHUTDOWN')

# --- Lifespan Context Manager (Startup/Shutdown Events) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup Sequence
    log_info("🚀 Application Startup Initiated...", icon_type='STARTUP')
    # 1. Initialize Tortoise ORM
    await init_tortoise()
    # 2. Initialize Redis
    redis_ok = await setup_redis()
    limiter_client = None # Initialize to None
    if redis_ok:
        # Store clients in app state for potential direct access (optional)
        app.state.redis_sse = redis_sse
        app.state.redis_limiter = redis_limiter_client
        limiter_client = redis_limiter_client # Get the client for SlowAPI
    else:
        log_warning("Redis setup failed, proceeding without Redis features (SSE, Rate Limiting).", icon_type='WARNING')
        app.state.redis_sse = None
        app.state.redis_limiter = None

    # --- MOVED FROM @app.on_event ---
    # 3. Configure and add SlowAPI middleware AFTER Redis client is potentially initialized
    if limiter_client:
        app.add_middleware(SlowAPIMiddleware, redis_client=limiter_client)
        log_info(f"⏱️ Rate Limiter configured with Redis backend (DB {settings.REDIS_RATE_LIMIT_DB}).", icon_type='RATELIMIT')
    else:
        # Fallback to in-memory store if Redis client setup failed
        app.add_middleware(SlowAPIMiddleware)
        log_warning("⏱️ Rate Limiter configured with In-Memory backend (Redis unavailable).", icon_type='RATELIMIT')
    # --- END MOVED SECTION ---

    log_success("🚀 Application Startup Complete.", icon_type='STARTUP')
    yield
    # Shutdown Sequence
    log_info("🛑 Application Shutdown Initiated...", icon_type='SHUTDOWN')
    # 1. Close Redis Connections
    await shutdown_redis()
    # 2. Close Database Connections
    try:
        await Tortoise.close_connections()
        log_success("💾 Database connections closed.", icon_type='DB')
    except Exception as e:
         log_warning(f"Error closing Tortoise connections: {e}", icon_type='DB')
    log_success("🛑 Application Shutdown Complete.", icon_type='SHUTDOWN')

# --- FastAPI Application Setup ---
log_info(f"🚀 Initializing FastAPI Application ({settings.PROJECT_NAME} v{settings.VERSION})...", icon_type='STARTUP')
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=__doc__.split('---')[0].strip(), # Use module docstring
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[ # Define tags for better organization in Swagger UI
        {"name": "General", "description": "Basic health and info endpoints"},
        {"name": "Authentication", "description": "User login and token management"},
        {"name": "Monitoring", "description": "System stats and log viewing"},
        {"name": "Queues", "description": "Operations for managing message queues"},
        {"name": "Messages", "description": "Publishing, consuming, and managing messages"},
        {"name": "Realtime (SSE)", "description": "Server-Sent Event streams for queue updates"},
        {"name": "GraphQL", "description": "GraphQL API endpoint"},
    ]
)

# --- Rate Limiter Setup (SlowAPI with Async Redis or Memory Fallback) ---
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.DEFAULT_RATE_LIMIT])
app.state.limiter = limiter # Make limiter available globally if needed
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.on_event("startup")
async def startup_configure_slowapi_middleware():
    """Adds SlowAPI middleware after Redis client is potentially initialized by lifespan."""
    # Access the client stored in app.state by the lifespan manager
    limiter_client = getattr(app.state, "redis_limiter", None)
    if limiter_client:
        app.add_middleware(SlowAPIMiddleware, redis_client=limiter_client)
        log_info(f"⏱️ Rate Limiter configured with Redis backend (DB {settings.REDIS_RATE_LIMIT_DB}).", icon_type='RATELIMIT')
    else:
        # Fallback to in-memory store if Redis client setup failed
        app.add_middleware(SlowAPIMiddleware)
        log_warning("⏱️ Rate Limiter configured with In-Memory backend (Redis unavailable).", icon_type='RATELIMIT')

# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
log_info(f"🛡️ CORS configured for origins: {settings.ALLOWED_ORIGINS}", icon_type='SEC')

# --- Authentication Dependencies ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False) # auto_error=False to handle optional auth later if needed
bearer_scheme = HTTPBearer(auto_error=False)

async def create_jwt_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def create_access_token(username: str) -> str:
    return await create_jwt_token(
        {"sub": username, "type": "access"}, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

async def create_refresh_token(username: str) -> str:
    return await create_jwt_token(
        {"sub": username, "type": "refresh"}, timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )

# Unified Token Decode Logic
async def _decode_token(token: str, expected_type: str) -> str:
    """Decodes JWT, validates type and sub, returns username or raises HTTPException."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"Could not validate {expected_type} token",
        headers={"WWW-Authenticate": f"Bearer error=\"invalid_token\", error_description=\"Invalid {expected_type} token\""},
    )
    if not token:
        raise credentials_exception

    try:
        payload = jwt.decode(
             token,
             settings.JWT_SECRET_KEY,
             algorithms=[settings.ALGORITHM],
             options={"verify_aud": False} # No audience verification for this example
        )
        username: Optional[str] = payload.get("sub")
        token_type: Optional[str] = payload.get("type")

        if username is None or token_type != expected_type:
            log_warning(f"{expected_type.capitalize()} token validation failed: 'sub' missing or type mismatch ('{token_type}' != '{expected_type}').", icon_type='AUTH', extra={"payload": payload})
            raise credentials_exception

        # log_debug(f"User '{username}' authenticated via {expected_type} token.", icon_type='AUTH')
        return username
    except JWTError as e:
        log_warning(f"{expected_type.capitalize()} token validation JWTError: {e}", icon_type='AUTH', extra={"token": token[:10] + "..."})
        raise credentials_exception
    except Exception as e:
         log_error(f"Unexpected error during {expected_type} token decode: {e}", icon_type='AUTH', exc_info=True)
         raise credentials_exception # Re-raise as the original unauthorized exception

# Dependency for Access Token
async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> str:
    """Dependency to validate JWT access token and return the username."""
    # If token is None (because auto_error=False), raise manually
    if token is None:
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await _decode_token(token, "access")

# Dependency for Refresh Token (expects Bearer header)
async def validate_refresh_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> str:
    """Dependency to validate JWT refresh token from Bearer header and return username."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing or invalid header",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_request\""},
        )
    return await _decode_token(credentials.credentials, "refresh")


# --- Stats Update Middleware ---
@app.middleware("http")
async def update_stats_middleware(request: Request, call_next):
    start_time_mw = time.perf_counter()
    response = await call_next(request)
    process_time_mw = time.perf_counter() - start_time_mw
    response.headers["X-Process-Time"] = f"{process_time_mw:.4f}s" # Add units

    # Update request stats after response is generated
    route = request.scope.get("route")
    if route and hasattr(route, 'path'):
        route_template = route.path
        # More robust ignore list, also handles potential None route path
        ignored_prefixes = ('/docs', '/redoc', '/openapi.json', '/stream', '/logs', '/graphql', '/favicon.ico', '/stats')
        if route_template and not route_template.startswith(ignored_prefixes):
            await update_request_stats(route_template, request.method, response.status_code)

    return response

# --- Helper Function for DB Lookups ---
async def _get_queue_or_404(queue_name: str, conn=None) -> Queue:
    """Fetches a queue by name or raises HTTPException 404. Can use existing transaction connection."""
    try:
        query = Queue.all()
        if conn: query = query.using_connection(conn)
        queue = await query.get(name=queue_name)
        return queue
    except DoesNotExist:
        log_warning(f"Queue '{queue_name}' not found in database.", icon_type='DB')
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Queue '{queue_name}' not found")
    except Exception as e:
        log_error(f"Database error fetching queue '{queue_name}': {e}", icon_type='DB', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error retrieving queue")

# --- SSE Notification Function ---
async def notify_sse(queue_name: str, message_id: int, event_type: str):
    """Publishes a notification via Redis Pub/Sub for SSE listeners."""
    if not redis_sse:
        log_warning(f"Cannot send SSE notification for queue '{queue_name}': Redis SSE client unavailable.", icon_type='SSE')
        return
    try:
        sse_data = json.dumps({"queue": queue_name, "message_id": message_id, "event": event_type, "timestamp": datetime.now(timezone.utc).isoformat()})
        redis_channel = f"sse:{queue_name}"
        # log_pipeline(f"📡 Publishing SSE to Redis '{redis_channel}': {sse_data}", icon_type='SSE') # Can be verbose
        published_count = await redis_sse.publish(redis_channel, sse_data)
        if published_count > 0:
             log_debug(f"📡 SSE published to '{redis_channel}' ({published_count} listeners). Data: {sse_data}", icon_type='SSE')
        else:
             log_debug(f"📡 SSE published to '{redis_channel}' (0 listeners). Data: {sse_data}", icon_type='SSE')

    except aioredis.RedisError as e:
        log_error(f"Redis error publishing SSE for queue '{queue_name}': {e}", icon_type='SSE', exc_info=True)
    except Exception as e:
        log_error(f"Error preparing/publishing SSE notification for queue '{queue_name}': {e}", icon_type='SSE', exc_info=True)


# --- =================== ---
# --- API ROUTE DEFINITIONS ---
# --- =================== ---

# --- General Routes ---
@app.get("/", tags=["General"], summary="Health Check")
@limiter.limit("5/second")
async def index(request: Request):
    """Provides a basic health check and server information."""
    log_info("🌐 GET / request", icon_type='HTTP', extra={"client": request.client.host})
    return {
        "message": settings.PROJECT_NAME,
        "status": "ok",
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# --- Authentication Routes ---
@app.post("/login", response_model=Token, tags=["Authentication"], summary="User Login")
@limiter.limit("10/minute") # Stricter limit for login attempts
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """
    Handles user login using OAuth2 compatible form data (username/password).

    **Note:** Uses insecure hardcoded credentials ('admin'/'admin') for demo purposes.
    Replace with secure password verification (e.g., using passlib) in production.
    """
    log_info(f"🔑 POST /login attempt for user: '{form_data.username}'", icon_type='AUTH', extra={"client": request.client.host})

    # --- !!! REPLACE WITH SECURE PASSWORD VERIFICATION !!! ---
    # Example using passlib (if pwd_context is configured):
    # user = await User.get_or_none(username=form_data.username) # Fetch user from DB
    # if not user or not verify_password(form_data.password, user.hashed_password):
    #     log_warning(...)
    #     raise HTTPException(...)
    if form_data.username == 'admin' and form_data.password == 'admin': # INSECURE DEMO
        log_pipeline(f"Credentials valid for '{form_data.username}'. Generating tokens...")
        access_token = await create_access_token(username=form_data.username)
        refresh_token = await create_refresh_token(username=form_data.username)
        log_success(f"Tokens generated for '{form_data.username}'.", icon_type='AUTH')
        return Token(access_token=access_token, refresh_token=refresh_token)
    else:
        log_warning(f"Login failed for '{form_data.username}': Invalid credentials.", icon_type='AUTH')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_grant\""},
        )

@app.post("/refresh", response_model=Token, tags=["Authentication"], summary="Refresh Access Token")
@limiter.limit("20/minute")
async def refresh_access_token(
    request: Request,
    username: str = Depends(validate_refresh_token) # Validates refresh token in header
):
    """Issues a new access and refresh token using a valid refresh token (passed via Bearer auth header)."""
    log_info(f"🔑 POST /refresh request by user '{username}'", icon_type='AUTH', extra={"client": request.client.host})
    new_access_token = await create_access_token(username=username)
    # Rotate refresh token for better security
    new_refresh_token = await create_refresh_token(username=username)
    log_success(f"New access/refresh tokens generated for '{username}'.", icon_type='AUTH')
    return Token(access_token=new_access_token, refresh_token=new_refresh_token)

# --- Monitoring Routes ---
@app.get("/stats", response_model=StatsResponse, tags=["Monitoring"], summary="Get System Statistics")
@limiter.limit("30/minute")
async def get_stats(
    request: Request,
    current_user: str = Depends(get_current_user)
) -> StatsResponse:
    """Returns current application, system, and broker statistics (requires authentication)."""
    log_info(f"📊 GET /stats request by user '{current_user}'", icon_type='STATS', extra={"client": request.client.host})

    # Update broker stats from DB (uses Tortoise)
    await update_broker_stats()

    # Collect system stats using psutil (in thread pool for potentially blocking calls)
    system_metrics = {}
    try:
        process = psutil.Process(os.getpid())

        async def _get_psutil_data():
            mem_info = process.memory_info()
            proc_cpu = process.cpu_percent(interval=0.1) # Blocking call
            sys_cpu = psutil.cpu_percent(interval=0.1) # Blocking call
            virt_mem = psutil.virtual_memory() # Blocking call
            try:
                disk_parts = psutil.disk_partitions(all=False) # Blocking call
            except Exception as disk_e:
                log_warning(f"Could not get disk partitions: {disk_e}", icon_type='STATS')
                disk_parts = []

            disk_usage_data = {}
            for part in disk_parts:
                try:
                    # Basic filtering of irrelevant partitions
                    if not os.path.exists(part.mountpoint) or not os.path.ismount(part.mountpoint): continue
                    if 'loop' in part.device or 'snap' in part.device or part.fstype in ['squashfs', 'tmpfs', 'devtmpfs', 'fuse.gvfsd-fuse', 'overlay']: continue
                    usage = psutil.disk_usage(part.mountpoint) # Blocking call
                    disk_usage_data[part.mountpoint] = {
                        "total_gb": round(usage.total / (1024**3), 2),
                        "used_gb": round(usage.used / (1024**3), 2),
                        "free_gb": round(usage.free / (1024**3), 2),
                        "percent": usage.percent
                    }
                except Exception as part_e:
                    log_warning(f"Could not get disk usage for {getattr(part, 'mountpoint', 'N/A')}: {part_e}", icon_type='STATS')

            return {
                "cpu_percent": sys_cpu,
                "memory_total_gb": round(virt_mem.total / (1024**3), 2),
                "memory_available_gb": round(virt_mem.available / (1024**3), 2),
                "memory_used_gb": round(virt_mem.used / (1024**3), 2),
                "memory_percent": virt_mem.percent,
                "disk_usage": disk_usage_data or {"info": "No valid partitions found or error reading usage."},
                "process_memory_mb": round(mem_info.rss / (1024**2), 2),
                "process_cpu_percent": proc_cpu,
                "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else "N/A",
                "cpu_count_logical": psutil.cpu_count(logical=True),
                "cpu_count_physical": psutil.cpu_count(logical=False),
            }

        system_metrics = await asyncio.to_thread(_get_psutil_data)

    except ImportError:
        log_warning("psutil not installed, system stats unavailable.", icon_type='STATS')
        system_metrics["error"] = "psutil package not installed"
    except Exception as e:
        log_warning(f"Error collecting system stats: {e}", icon_type='STATS', exc_info=True)
        system_metrics["error"] = f"psutil data collection failed: {type(e).__name__}"

    # Construct response data safely using the lock
    response_data = {}
    async with stats_lock:
        current_stats_copy = app_stats.copy() # Work on a copy
        current_stats_copy["system"].update(system_metrics) # Merge system metrics

        # Calculate uptime
        start_time_dt = current_stats_copy["start_time"]
        uptime_delta = datetime.now(timezone.utc) - start_time_dt
        uptime_seconds = uptime_delta.total_seconds()
        current_stats_copy["uptime_seconds"] = round(uptime_seconds, 2)

        days, rem = divmod(int(uptime_seconds), 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)
        parts = [f"{days}d" if days else "", f"{hours}h" if hours else "", f"{minutes}m" if minutes else "", f"{seconds}s"]
        current_stats_copy["uptime_human"] = " ".join(p for p in parts if p) or "0s"

        # Ensure dates are strings, status codes are strings
        current_stats_copy["start_time"] = start_time_dt.isoformat()
        # requests_by_status keys are already strings from update_request_stats
        response_data = current_stats_copy

    log_success(f"Stats returned for user '{current_user}'.", icon_type='STATS')
    try:
        # Validate final data against the Pydantic model
        return StatsResponse.model_validate(response_data)
    except ValidationError as e:
        log_critical(f"Stats data validation failed: {e.errors()}", icon_type='CRITICAL', extra={"invalid_stats": response_data})
        raise HTTPException(status_code=500, detail="Internal Server Error: Failed to generate valid stats data.")


@app.get("/logs", response_model=LogFileResponse, tags=["Monitoring"], summary="List Log Files")
@limiter.limit("10/minute")
async def list_log_files(
    request: Request,
    current_user: str = Depends(get_current_user)
):
    """Lists available JSON log files in the configured log directory (requires authentication)."""
    log_info(f"📄 GET /logs request by user '{current_user}'", icon_type='LOGS', extra={"client": request.client.host})
    try:
        # Use asyncio.to_thread for os.listdir
        log_files_all = await asyncio.to_thread(os.listdir, settings.LOG_DIR)
        log_files_json = sorted(
            [f for f in log_files_all if f.endswith('.json') and os.path.isfile(os.path.join(settings.LOG_DIR, f))],
            reverse=True # Show newest first
        )
        log_success(f"Found {len(log_files_json)} JSON log files.", icon_type='LOGS')
        return LogFileResponse(log_files=log_files_json)
    except FileNotFoundError:
         log_error(f"Log directory '{settings.LOG_DIR}' not found.", icon_type='LOGS')
         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log directory configured but not found")
    except OSError as e:
        log_error(f"Error listing log files in '{settings.LOG_DIR}': {e}", exc_info=True, icon_type='LOGS')
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error accessing log directory")

@app.get("/logs/{filename:path}", response_model=List[Dict[str, Any]], tags=["Monitoring"], summary="Get Log File Content")
@limiter.limit("60/minute") # Limit log reads
async def get_log_file(
    request: Request,
    filename: str = Path(..., title="Log filename", description="Name of the JSON log file to retrieve"),
    start: Optional[int] = FastQuery(None, ge=1, description="Start line number (1-based index)"),
    end: Optional[int] = FastQuery(None, ge=1, description="End line number (inclusive)"),
    tail: Optional[int] = FastQuery(None, ge=1, le=10000, description="Return last N lines (max 10000)"), # Limit tail size
    current_user: str = Depends(get_current_user)
) -> List[Dict]:
    """
    Retrieves the content of a specific JSON log file, allowing slicing or tailing (requires authentication).
    Each line is parsed as JSON. Invalid lines are returned with an error indicator.
    """
    safe_filename = secure_filename(filename)
    if not safe_filename or safe_filename != filename or not safe_filename.endswith('.json'):
        log_warning(f"Invalid log file access attempt: '{filename}' by user '{current_user}'", icon_type='SEC')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or non-JSON log filename provided")

    log_path = os.path.join(settings.LOG_DIR, safe_filename)
    log_info(f"📄 GET /logs/{safe_filename} request by '{current_user}' (start={start}, end={end}, tail={tail})", icon_type='LOGS')

    # Define synchronous file reading logic
    def read_and_parse_log_sync():
        if not os.path.isfile(log_path):
            return None # Indicate file not found

        lines_to_parse = []
        try:
            if tail is not None and tail > 0:
                with open(log_path, 'r', encoding='utf-8') as f:
                    # Use deque for efficient tailing
                    lines_to_parse = deque(f, maxlen=tail)
            else:
                with open(log_path, 'r', encoding='utf-8') as f:
                    all_lines_iter = enumerate(f, 1) # 1-based line numbers
                    line_count_in_range = 0
                    for line_num, line in all_lines_iter:
                        if start is not None and line_num < start: continue
                        if end is not None and line_num > end: break
                        lines_to_parse.append(line.strip())
                        line_count_in_range += 1
                        # Prevent excessive memory usage for open-ended ranges
                        if start is not None and end is None and line_count_in_range >= 10000:
                            log_warning(f"Log file read for '{safe_filename}' truncated at 10000 lines (start={start}, no end).", icon_type='LOGS')
                            lines_to_parse.append(json.dumps({"_warning": "Result set truncated at 10000 lines", "_limit": 10000}))
                            break
        except Exception as read_exc:
            log_error(f"Error reading log file '{safe_filename}': {read_exc}", exc_info=True, icon_type='LOGS')
            # Return an error entry instead of raising here to indicate read failure
            return [{"_error": f"Failed to read file: {read_exc}"}]

        # Parse JSON lines
        parsed_lines = []
        for i, line in enumerate(lines_to_parse):
            line_num_info = f"tail_{i+1}" if tail else (start or 1) + i
            try:
                if line: # Avoid parsing empty lines
                    parsed_lines.append(json.loads(line))
                # Optionally add indicator for empty lines if not tailing:
                # elif tail is None: parsed_lines.append({"_info": "Empty line", "_line": line_num_info})
            except json.JSONDecodeError:
                parsed_lines.append({"_error": "Invalid JSON", "_line": line_num_info, "_raw": line[:250]}) # Include raw snippet
            except Exception as parse_exc:
                 parsed_lines.append({"_error": f"Parsing error: {parse_exc}", "_line": line_num_info, "_raw": line[:250]})

        return parsed_lines

    # Run the synchronous function in a thread pool
    try:
        result_lines = await asyncio.to_thread(read_and_parse_log_sync)

        if result_lines is None:
            log_warning(f"Log file not found: {log_path}", icon_type='LOGS')
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Log file '{safe_filename}' not found")

        log_success(f"{len(result_lines)} log entries returned from '{safe_filename}'.", icon_type='LOGS')
        return result_lines

    except HTTPException:
        raise # Re-raise existing HTTP exceptions
    except Exception as e:
        log_error(f"Unexpected error processing log file '{safe_filename}': {e}", exc_info=True, icon_type='LOGS')
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected error processing log file")

# --- Queue Routes ---
@app.get("/queues", response_model=List[QueueResponse], tags=["Queues"], summary="List All Queues")
@limiter.limit("60/minute")
async def list_queues(
    request: Request,
    current_user: str = Depends(get_current_user),
) -> List[QueueResponse]:
    """Lists all available message queues, including the count of messages in each (requires authentication)."""
    log_info(f"📋 GET /queues request by user '{current_user}'", icon_type='QUEUE')
    try:
        queues = await Queue.all().order_by('name')
        if not queues:
            return [] # Return empty list if no queues exist

        # Fetch message counts concurrently
        count_tasks = {q.id: Message.filter(queue_id=q.id).count() for q in queues}
        message_counts = await asyncio.gather(*count_tasks.values())
        # Map counts back to queues using the keys from count_tasks
        counts_dict = dict(zip(count_tasks.keys(), message_counts))

        response_list = [
            QueueResponse(
                id=q.id,
                name=q.name,
                created_at=q.created_at,
                updated_at=q.updated_at,
                message_count=counts_dict.get(q.id, 0) # Get count from gathered results
            ) for q in queues
        ]
        log_success(f"Returned {len(response_list)} queues.", icon_type='QUEUE')
        return response_list
    except Exception as e:
        log_error(f"Error listing queues: {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error retrieving queue list")

@app.post("/queues", response_model=QueueResponse, status_code=status.HTTP_201_CREATED, tags=["Queues"], summary="Create New Queue")
@limiter.limit("30/minute")
async def create_queue(
    request: Request,
    payload: QueueCreatePayload, # Use dedicated payload model
    current_user: str = Depends(get_current_user),
) -> QueueResponse:
    """Creates a new message queue. Returns 409 Conflict if the queue name already exists (requires authentication)."""
    queue_name = payload.name
    log_info(f"➕ POST /queues request by '{current_user}' to create '{queue_name}'", icon_type='QUEUE')
    try:
        # Use get_or_create for atomic check-and-create
        new_queue, created = await Queue.get_or_create(name=queue_name)
        if not created:
            log_warning(f"Queue '{queue_name}' already exists. Creation request denied (409).", icon_type='QUEUE')
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Queue with name '{queue_name}' already exists."
            )
        log_success(f"Queue '{queue_name}' created successfully (ID: {new_queue.id}).", icon_type='QUEUE')
        # Convert ORM model to Pydantic response model (message_count defaults to 0)
        return QueueResponse.model_validate(new_queue)
    except IntegrityError: # Should be caught by get_or_create, but as a fallback
         log_warning(f"IntegrityError during queue creation for '{queue_name}'. Likely already exists.", icon_type='DB')
         raise HTTPException(
             status_code=status.HTTP_409_CONFLICT,
             detail=f"Queue with name '{queue_name}' already exists (database constraint)."
         )
    except Exception as e:
        log_error(f"Error creating queue '{queue_name}': {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error creating queue")

@app.get("/queues/{queue_name}", response_model=QueueResponse, tags=["Queues"], summary="Get Queue Details")
@limiter.limit("60/minute")
async def get_queue(
    request: Request,
    queue_name: str = Path(..., description="Name of the queue"),
    current_user: str = Depends(get_current_user),
) -> QueueResponse:
    """Gets details for a specific queue by name, including its message count (requires authentication)."""
    log_info(f"📥 GET /queues/{queue_name} request by user '{current_user}'", icon_type='QUEUE')
    try:
        queue = await _get_queue_or_404(queue_name) # Handles 404
        message_count = await Message.filter(queue_id=queue.id).count()
        log_success(f"Details for queue '{queue_name}' returned.", icon_type='QUEUE')
        response = QueueResponse.model_validate(queue)
        response.message_count = message_count
        return response
    except HTTPException:
        raise # Let 404 from _get_queue_or_404 pass through
    except Exception as e:
        log_error(f"Error getting queue details for '{queue_name}': {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error retrieving queue details")

@app.delete("/queues/{queue_name}", status_code=status.HTTP_204_NO_CONTENT, tags=["Queues"], summary="Delete Queue")
@limiter.limit("10/minute") # Lower limit for destructive actions
async def delete_queue(
    request: Request,
    queue_name: str = Path(..., description="Name of the queue to delete"),
    current_user: str = Depends(get_current_user),
) -> Response:
    """
    Deletes a queue and all its associated messages (due to cascade delete).
    Returns 204 No Content on success (requires authentication).
    """
    log_info(f"🗑️ DELETE /queues/{queue_name} request by user '{current_user}'", icon_type='QUEUE')
    try:
        queue = await _get_queue_or_404(queue_name) # Handles 404
        queue_id = queue.id # Get ID for logging before deletion
        log_pipeline(f"Queue '{queue_name}' (ID: {queue_id}) found. Proceeding with deletion...")

        # Tortoise ORM handles cascade deletion based on the ForeignKey(on_delete=CASCADE)
        await queue.delete()

        log_success(f"Queue '{queue_name}' (ID: {queue_id}) and associated messages deleted successfully.", icon_type='QUEUE')
        # Return an empty response with 204 status code
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except HTTPException:
        raise # Let 404 pass through
    except Exception as e:
        log_error(f"Error deleting queue '{queue_name}': {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error deleting queue")


# --- Message Routes ---
@app.post("/queues/{queue_name}/messages", response_model=MessagePublishResponse, status_code=status.HTTP_201_CREATED, tags=["Messages"], summary="Publish Message")
@limiter.limit("100/second") # Allow higher rate for publishing
async def publish_message(
    # Non-default arguments first
    request: Request,
    payload: MessagePayload,           # Request body
    background_tasks: BackgroundTasks, # FastAPI dependency injection
    # Default arguments (Path, Depends) last
    queue_name: str = Path(..., description="Name of the target queue"),
    current_user: str = Depends(get_current_user), # Authentication
) -> MessagePublishResponse:
    """Publishes a new message with the given content to the specified queue (requires authentication)."""
    log_info(f"📤 POST /queues/{queue_name}/messages by '{current_user}'", icon_type='MSG', extra={"content_preview": payload.content[:50] + "..."})
    try:
        queue = await _get_queue_or_404(queue_name) # Handles 404
        log_pipeline(f"Queue '{queue_name}' found. Creating message...")
        new_message = await Message.create(
            queue=queue, # Pass the ORM object
            content=payload.content,
            status='pending' # Initial status
        )
        log_success(f"Message ID {new_message.id} published to queue '{queue_name}'.", icon_type='MSG')

        # Notify SSE listeners in the background
        background_tasks.add_task(notify_sse, queue_name, new_message.id, "new_message")

        return MessagePublishResponse(message_id=new_message.id)
    except HTTPException:
        raise # Let 404 pass through
    except Exception as e:
        log_error(f"Error publishing message to queue '{queue_name}': {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error publishing message")

@app.get("/queues/{queue_name}/messages/consume", response_model=Optional[MessageConsumeResponse], tags=["Messages"], summary="Consume Message")
@limiter.limit("60/second") # Rate limit consumption attempts
async def consume_message(
    request: Request,
    queue_name: str = Path(..., description="Name of the queue to consume from"),
    current_user: str = Depends(get_current_user),
) -> Optional[MessageConsumeResponse]:
    """
    Atomically consumes the oldest 'pending' message from the specified queue.
    Marks the message status as 'processing' and returns it.
    Returns null (HTTP 200) if the queue is empty or has no 'pending' messages.
    Requires authentication.
    """
    log_info(f"📩 GET /queues/{queue_name}/messages/consume request by '{current_user}'", icon_type='MSG', extra={"client": request.client.host})
    try:
        queue = await _get_queue_or_404(queue_name) # Handles 404

        # Use a transaction for atomic read-then-update
        conn = Tortoise.get_connection("default")
        async with conn.in_transaction() as tx:
            # Find the oldest pending message and lock the row (best effort in SQLite)
            message = await Message.filter(
                queue_id=queue.id,
                status='pending'
            ).using_connection(tx).order_by('created_at').select_for_update().first()

            if not message:
                log_info(f"No pending messages found in queue '{queue_name}' for consumption.", icon_type='MSG')
                # Return None, FastAPI converts Optional[Model] to null in JSON response with HTTP 200
                return None

            # Mark as processing and update timestamp
            message.status = 'processing'
            message.updated_at = datetime.now(timezone.utc)
            # Save only the changed fields
            await message.save(using_connection=tx, update_fields=['status', 'updated_at'])

            log_success(f"Message ID {message.id} consumed from queue '{queue_name}' by '{current_user}' (status -> processing).", icon_type='MSG')
            # Return the consumed message details
            return MessageConsumeResponse(
                message_id=message.id,
                queue=queue_name,
                content=message.content,
                status=message.status, # Should be 'processing'
                retrieved_at=message.updated_at
            )

    except HTTPException:
        raise # Let 404 pass through
    except IntegrityError as e: # e.g., if locking causes issues or unexpected constraint violation
        log_warning(f"DB integrity error during consumption from '{queue_name}': {e}", icon_type='DB')
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Conflict during message consumption attempt, try again.")
    except Exception as e:
        log_error(f"Error consuming message from queue '{queue_name}': {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error consuming message")

@app.post("/messages/{message_id}/ack", status_code=status.HTTP_200_OK, response_model=Dict[str, str], tags=["Messages"], summary="Acknowledge Message")
@limiter.limit("100/second")
async def acknowledge_message(
    # Non-default args first
    request: Request,
    background_tasks: BackgroundTasks,
    # Default args last
    message_id: int = Path(..., ge=1, description="ID of the message to acknowledge"),
    current_user: str = Depends(get_current_user)
) -> Dict[str, str]:
    """
    Marks a message currently in the 'processing' state as 'processed'.
    Requires authentication. Returns 404 if message not found, or 409 if message is not 'processing'.
    """
    log_info(f"✅ POST /messages/{message_id}/ack request by '{current_user}'", icon_type='MSG')
    try:
        conn = Tortoise.get_connection("default")
        async with conn.in_transaction() as tx:
            # Find the message, ensuring it's 'processing' and lock it
            message = await Message.filter(
                id=message_id,
                status='processing' # MUST be 'processing' to be ACK'd
            ).using_connection(tx).select_for_update().get_or_none()

            if not message:
                # Check if message exists but has wrong status
                existing_msg = await Message.filter(id=message_id).using_connection(tx).first()
                if existing_msg:
                    log_warning(f"ACK failed for message {message_id}: Found but status is '{existing_msg.status}', not 'processing'.", icon_type='MSG')
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"Message {message_id} is in '{existing_msg.status}' state, cannot ACK."
                    )
                else:
                    log_warning(f"ACK failed for message {message_id}: Not found.", icon_type='MSG')
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Message {message_id} not found."
                    )

            # Mark as processed
            original_queue = await message.queue.first().using_connection(tx) # Get related queue within transaction
            if not original_queue:
                 # This shouldn't happen due to FK constraints, but defensively check
                 log_error(f"Critical: Message {message_id} has no associated queue during ACK.", icon_type='DB')
                 raise HTTPException(status_code=500, detail="Internal error: Message queue association lost.")
            original_queue_name = original_queue.name

            message.status = 'processed'
            message.updated_at = datetime.now(timezone.utc)
            await message.save(using_connection=tx, update_fields=['status', 'updated_at'])

            # Optional: Delete the message after successful processing?
            # await message.delete(using_connection=tx)
            # log_pipeline(f"Message ID {message_id} deleted after ACK.", icon_type='MSG')

            log_success(f"Message ID {message_id} acknowledged by '{current_user}' (status -> processed).", icon_type='MSG')
            # Notify SSE listeners about the successful processing
            background_tasks.add_task(notify_sse, original_queue_name, message.id, "message_processed")
            return {"detail": f"Message {message_id} acknowledged successfully."}

    except HTTPException:
        raise # Let 404/409 pass through
    except Exception as e:
        log_error(f"Error acknowledging message {message_id}: {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error acknowledging message")

@app.post("/messages/{message_id}/nack", status_code=status.HTTP_200_OK, response_model=Dict[str, str], tags=["Messages"], summary="Negative Acknowledge Message")
@limiter.limit("100/second")
async def negative_acknowledge_message(
    # Non-default args first
    request: Request,
    background_tasks: BackgroundTasks,
    # Default args last
    message_id: int = Path(..., ge=1, description="ID of the message to NACK"),
    requeue: bool = FastQuery(False, description="If true, reset status to 'pending'. If false, set status to 'failed'."),
    current_user: str = Depends(get_current_user)
) -> Dict[str, str]:
    """
    Marks a 'processing' message as 'failed' or requeues it ('pending').
    Requires authentication. Returns 404 if message not found, or 409 if message is not 'processing'.
    """
    action = "requeued" if requeue else "marked as failed"
    log_info(f"❌ POST /messages/{message_id}/nack request by '{current_user}' (requeue={requeue})", icon_type='MSG')
    try:
        conn = Tortoise.get_connection("default")
        async with conn.in_transaction() as tx:
            message = await Message.filter(
                id=message_id,
                status='processing' # MUST be 'processing' to be NACK'd
            ).using_connection(tx).select_for_update().get_or_none()

            if not message:
                existing_msg = await Message.filter(id=message_id).using_connection(tx).first()
                if existing_msg:
                    log_warning(f"NACK failed for message {message_id}: Found but status is '{existing_msg.status}', not 'processing'.", icon_type='MSG')
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Message {message_id} is in '{existing_msg.status}' state, cannot NACK.")
                else:
                    log_warning(f"NACK failed for message {message_id}: Not found.", icon_type='MSG')
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Message {message_id} not found.")

            original_queue = await message.queue.first().using_connection(tx)
            if not original_queue:
                 log_error(f"Critical: Message {message_id} has no associated queue during NACK.", icon_type='DB')
                 raise HTTPException(status_code=500, detail="Internal error: Message queue association lost.")
            original_queue_name = original_queue.name

            new_status = 'pending' if requeue else 'failed'
            message.status = new_status
            message.updated_at = datetime.now(timezone.utc)
            await message.save(using_connection=tx, update_fields=['status', 'updated_at'])

            log_success(f"Message ID {message_id} NACK'd by '{current_user}' (status -> {new_status}).", icon_type='MSG')
            event_type = "message_requeued" if requeue else "message_failed"
            background_tasks.add_task(notify_sse, original_queue_name, message.id, event_type)

            return {"detail": f"Message {message_id} successfully {action}."}

    except HTTPException:
        raise # Let 404/409 pass through
    except Exception as e:
        log_error(f"Error NACK'ing message {message_id}: {e}", icon_type='CRITICAL', exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error negatively acknowledging message (action: {action})")


# --- Server-Sent Events (SSE) Stream ---
@app.get("/stream/{queue_name}", tags=["Realtime (SSE)"], summary="Subscribe to Queue Events")
async def sse_stream_queue(
    request: Request,
    queue_name: str = Path(..., description="Queue name to subscribe to for events"),
    current_user: str = Depends(get_current_user) # Protect stream
):
    """Provides a Server-Sent Event stream for real-time updates on a specific queue (requires authentication)."""
    if not redis_sse:
         log_error("SSE stream unavailable: Redis client not configured or connection failed.", icon_type='CRITICAL')
         raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="SSE service is currently unavailable due to Redis connection issues.")

    log_info(f"📡 SSE stream requested for queue '{queue_name}' by user '{current_user}'", icon_type='SSE', extra={"client": request.client.host})

    # Validate queue exists before starting the potentially long-running generator
    try:
        await _get_queue_or_404(queue_name)
    except HTTPException as e:
        # Log the attempt and re-raise the exception (e.g., 404)
        log_warning(f"Attempt to stream non-existent queue '{queue_name}' by '{current_user}'. Denying.", icon_type='SSE')
        raise e # Re-raise the HTTP 404 exception

    async def event_generator() -> AsyncGenerator[str, None]:
        pubsub = None
        redis_channel = f"sse:{queue_name}"
        is_subscribed = False
        keep_alive_interval = 15 # Send keep-alive every 15 seconds
        disconnect_check_interval = 2 # Check for client disconnect every 2 seconds

        try:
            pubsub = redis_sse.pubsub(ignore_subscribe_messages=True)
            await pubsub.subscribe(redis_channel)
            is_subscribed = True
            log_success(f"📡 Subscribed to Redis channel '{redis_channel}' for SSE stream (user: {current_user}).", icon_type='SSE')

            # Send initial connection confirmation message
            connect_data = json.dumps({'event': 'connected', 'queue': queue_name, 'channel': redis_channel, 'timestamp': datetime.now(timezone.utc).isoformat()})
            yield f"event: system\ndata: {connect_data}\n\n"

            last_keep_alive = time.monotonic()

            while True:
                # Check for client disconnect periodically
                if await request.is_disconnected():
                     log_info(f"📡 SSE client for '{queue_name}' disconnected (user: {current_user}). Closing stream.", icon_type='SSE')
                     break

                try:
                    # Wait for a message with a timeout slightly longer than disconnect check
                    message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=disconnect_check_interval)
                    if message and message.get("type") == "message":
                        data = message['data']
                        # log_debug(f"📡 SSE Data Received from Redis '{redis_channel}': {data[:150]}...", icon_type='SSE')
                        # Assume data from notify_sse is already valid JSON
                        yield f"event: message\ndata: {data}\n\n"
                        last_keep_alive = time.monotonic() # Reset keep-alive timer on message

                    # Send keep-alive periodically if no messages received
                    elif time.monotonic() - last_keep_alive > keep_alive_interval:
                        yield ": keep-alive\n\n"
                        last_keep_alive = time.monotonic()

                except asyncio.TimeoutError:
                    # Timeout just means no message received, continue loop
                    # Send keep-alive if needed based on timer check above
                    if time.monotonic() - last_keep_alive > keep_alive_interval:
                        yield ": keep-alive\n\n"
                        last_keep_alive = time.monotonic()
                    continue # Go back to checking disconnect/waiting for message
                except aioredis.RedisError as redis_err:
                    log_error(f"Redis error reading pub/sub for '{redis_channel}': {redis_err}", icon_type='SSE', exc_info=True)
                    error_data = json.dumps({'error': 'Redis connection error', 'channel': redis_channel, 'timestamp': datetime.now(timezone.utc).isoformat()})
                    yield f"event: error\ndata: {error_data}\n\n"
                    await asyncio.sleep(5) # Backoff before breaking
                    break # Exit on persistent Redis errors
                except Exception as e:
                    # Catch unexpected errors within the loop
                    log_error(f"Unexpected error in SSE generator for '{redis_channel}': {e}", icon_type='CRITICAL', exc_info=True)
                    try:
                         error_data = json.dumps({'error': 'Internal server error in SSE stream', 'channel': redis_channel, 'timestamp': datetime.now(timezone.utc).isoformat()})
                         yield f"event: error\ndata: {error_data}\n\n"
                    except Exception: pass # Ignore if can't send error message
                    break # Exit loop on unexpected error
        except asyncio.CancelledError:
             log_info(f"📡 SSE stream for '{queue_name}' task cancelled (user: {current_user}).", icon_type='SSE')
        except Exception as e:
             # Catch errors during initial setup (subscribe etc.)
             log_error(f"Error setting up SSE stream generator for '{queue_name}': {e}", icon_type='CRITICAL', exc_info=True)
             # Can't yield here if setup failed, error handled by FastAPI's exception handlers
        finally:
            # Cleanup Redis PubSub resources
            if pubsub:
                try:
                    if is_subscribed:
                        log_pipeline(f"📡 Unsubscribing from Redis channel '{redis_channel}'...", icon_type='SSE')
                        await pubsub.unsubscribe(redis_channel)
                    await pubsub.close()
                    log_pipeline(f"📡 Closed Redis PubSub client for '{redis_channel}'.", icon_type='SSE')
                except Exception as close_e:
                    log_warning(f"Error closing Redis PubSub resources for '{redis_channel}': {close_e}", icon_type='SSE')

    # Return the streaming response
    headers = {'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no'} # Nginx buffering off
    return StreamingResponse(event_generator(), media_type="text/event-stream", headers=headers)


# --- GraphQL Setup (Strawberry) ---
log_info("🍓 Configuring GraphQL endpoint with Strawberry...", icon_type='GRAPHQL')

# --- Strawberry Type Definitions ---
@strawberry.type(description="Represents a message queue")
class QueueGQL:
    # ... (id, name, created_at, updated_at, message_count field definitions) ...

    @strawberry.field(description="Retrieves messages belonging to this queue, filterable by status")
    async def messages(
        self, info: Info,
        # --- CORRECTED ARGUMENTS ---
        status: Optional[str] = strawberry.field(default=None, description="Filter messages by status (pending, processing, processed, failed)"),
        limit: int = strawberry.field(default=10, description="Maximum number of messages to return (1-100)"),
        offset: int = strawberry.field(default=0, description="Number of messages to skip (for pagination)")
        # --- END CORRECTIONS ---
    ) -> List["MessageGQL"]:
        """Resolver to fetch messages related to this queue with filtering and pagination."""
        log_debug(f"GQL: Fetching messages for Queue ID {self.id} (status={status}, limit={limit}, offset={offset})")
        valid_statuses = ['pending', 'processing', 'processed', 'failed']
        if status and status not in valid_statuses:
             # Use Strawberry's error handling
             raise ValueError(f"Invalid status filter: '{status}'. Must be one of {valid_statuses}.")

        # Sanitize limit and offset
        limit = max(1, min(limit, 100)) # Enforce reasonable limit
        offset = max(0, offset)

        try:
             # Convert strawberry.ID back to int for DB query
             queue_id_int = int(self.id)
             query = Message.filter(queue_id=queue_id_int)
             if status:
                 query = query.filter(status=status)

             # Apply ordering, limit, and offset
             messages_db = await query.order_by('-created_at').offset(offset).limit(limit) # Get latest first

             # Map ORM models to GQL types (queue name is available from self.name)
             return [MessageGQL.from_orm(m, queue_name_str=self.name) for m in messages_db]
        except ValueError as ve: # Catch ID parsing error or status validation error
            log_warning(f"GQL messages resolver validation error for queue {self.id}: {ve}")
            raise ve # Let Strawberry handle the GraphQL error response
        except Exception as e:
            log_error(f"GQL messages resolver error for queue {self.id}: {e}", exc_info=True)
            # Returning empty list on error is safer than raising a generic 500 in GQL
            return []

@strawberry.type(description="Represents a message within a queue")
class MessageGQL:
    id: strawberry.ID = strawberry.field(description="Unique identifier for the message")
    queue_name: str = strawberry.field(description="Name of the queue this message belongs to")
    content: str = strawberry.field(description="Payload content of the message")
    status: str = strawberry.field(description="Current status (pending, processing, processed, failed)")
    created_at: datetime = strawberry.field(description="Timestamp when the message was created (UTC)")
    updated_at: datetime = strawberry.field(description="Timestamp when the message was last updated (UTC)")

    @classmethod
    def from_orm(cls, model: Message, queue_name_str: str) -> "MessageGQL":
         """Helper to map from Tortoise ORM model, injecting queue name."""
         return cls(
             id=strawberry.ID(str(model.id)),
             queue_name=queue_name_str, # Inject name passed from QueueGQL resolver
             content=model.content,
             status=model.status,
             created_at=model.created_at,
             updated_at=model.updated_at,
         )

# --- Strawberry Query Root ---
@strawberry.type
class QueryGQL:
    @strawberry.field(description="Retrieves a list of all available message queues")
    async def all_queues(self, info: Info) -> List[QueueGQL]:
        log_info("🍓 GraphQL Query: all_queues", icon_type='GRAPHQL')
        try:
             queues_db = await Queue.all().order_by('name')
             # Map ORM models to GQL types
             # message_count and messages are resolved by QueueGQL field resolvers
             return [
                 QueueGQL(
                     id=strawberry.ID(str(q.id)),
                     name=q.name,
                     created_at=q.created_at,
                     updated_at=q.updated_at
                 ) for q in queues_db
             ]
        except Exception as e:
             log_error(f"GraphQL all_queues error: {e}", icon_type='GRAPHQL', exc_info=True)
             # Return empty list on error
             return []

    @strawberry.field(description="Retrieves a specific message queue by its unique name")
    async def queue_by_name(self, info: Info, name: str = strawberry.argument(description="The name of the queue to retrieve")) -> Optional[QueueGQL]:
        log_info(f"🍓 GraphQL Query: queue_by_name (name='{name}')", icon_type='GRAPHQL')
        try:
            queue_db = await Queue.get_or_none(name=name)
            if queue_db:
                 # Map ORM model to GQL type
                 return QueueGQL(
                     id=strawberry.ID(str(queue_db.id)),
                     name=queue_db.name,
                     created_at=queue_db.created_at,
                     updated_at=queue_db.updated_at
                 )
            else:
                 log_warning(f"GraphQL: Queue '{name}' not found.", icon_type='GRAPHQL')
                 return None # Return null if not found
        except Exception as e:
             log_error(f"GraphQL queue_by_name error for '{name}': {e}", icon_type='GRAPHQL', exc_info=True)
             return None # Return null on error

    @strawberry.field(description="Retrieves a specific message by its unique ID")
    async def message_by_id(self, info: Info, id: strawberry.ID = strawberry.argument(description="The unique ID of the message")) -> Optional[MessageGQL]:
        log_info(f"🍓 GraphQL Query: message_by_id (id={id})", icon_type='GRAPHQL')
        try:
            message_db = await Message.get_or_none(id=int(id)).select_related('queue') # Fetch related queue for name
            if message_db and message_db.queue:
                 # Map ORM model to GQL type
                 return MessageGQL.from_orm(message_db, queue_name_str=message_db.queue.name)
            else:
                 log_warning(f"GraphQL: Message ID {id} not found or has no queue.", icon_type='GRAPHQL')
                 return None
        except (ValueError, DoesNotExist):
             log_warning(f"GraphQL: Message ID {id} not found or invalid.", icon_type='GRAPHQL')
             return None
        except Exception as e:
             log_error(f"GraphQL message_by_id error for ID {id}: {e}", icon_type='GRAPHQL', exc_info=True)
             return None


# --- Strawberry Mutation Root ---
@strawberry.type
class MutationGQL:
    @strawberry.mutation(description="Creates a new message queue")
    async def create_queue(self, info: Info, name: str = strawberry.argument(description="Unique name for the new queue")) -> QueueGQL:
         # Access context if needed for auth: user = info.context.get("current_user")
         log_info(f"🍓 GraphQL Mutation: create_queue (name='{name}')", icon_type='GRAPHQL')
         try:
             new_queue, created = await Queue.get_or_create(name=name)
             if not created:
                  raise Exception(f"Queue '{name}' already exists.") # Raise GQL-handled exception

             log_success(f"GQL: Queue '{name}' created (ID: {new_queue.id}).", icon_type='QUEUE')
             # Map ORM to GQL type
             return QueueGQL(
                 id=strawberry.ID(str(new_queue.id)),
                 name=new_queue.name,
                 created_at=new_queue.created_at,
                 updated_at=new_queue.updated_at
             )
         except Exception as e: # Catch DB errors or the explicit raise above
              log_error(f"GraphQL create_queue error: {e}", icon_type='GRAPHQL', exc_info=isinstance(e, IntegrityError)) # Less verbose trace for known conflict
              raise Exception(f"Failed to create queue '{name}': {e}") # Propagate as GraphQL error

    @strawberry.mutation(description="Deletes a queue and all its messages")
    async def delete_queue(self, info: Info, name: str = strawberry.argument(description="Name of the queue to delete")) -> bool:
        log_info(f"🍓 GraphQL Mutation: delete_queue (name='{name}')", icon_type='GRAPHQL')
        try:
            queue = await Queue.get_or_none(name=name)
            if not queue:
                 raise Exception(f"Queue '{name}' not found.")

            await queue.delete() # Cascade delete handled by ORM
            log_success(f"GQL: Queue '{name}' deleted successfully.", icon_type='QUEUE')
            return True
        except Exception as e:
             log_error(f"GraphQL delete_queue error for '{name}': {e}", icon_type='GRAPHQL', exc_info=True)
             raise Exception(f"Failed to delete queue '{name}': {e}")


    @strawberry.mutation(description="Publishes a message to a specified queue")
    async def publish_message(
        self, info: Info,
        queue_name: str = strawberry.argument(description="Name of the target queue"),
        content: str = strawberry.argument(description="Message content/payload")
    ) -> MessageGQL:
        # background_tasks = info.context.get("background_tasks") # Get from context if needed
        log_info(f"🍓 GraphQL Mutation: publish_message (queue='{queue_name}')", icon_type='GRAPHQL')
        try:
            queue = await Queue.get_or_none(name=queue_name)
            if not queue:
                 raise Exception(f"Queue '{queue_name}' not found.")

            new_message = await Message.create(queue=queue, content=content, status='pending')
            log_success(f"GQL: Message ID {new_message.id} published to queue '{queue_name}'.", icon_type='MSG')

            # Background task for SSE notification (cannot directly access FastAPI's background_tasks here easily)
            # Option 1: Don't notify SSE from GQL mutations
            # Option 2: Use a separate async task runner (e.g., Celery, ARQ) triggered here
            # Option 3: Pass BackgroundTasks through context (more complex setup)
            # For simplicity, omitting SSE notification from GQL mutation here.
            # await notify_sse(queue_name, new_message.id, "new_message") # Would need global redis_sse access

            return MessageGQL.from_orm(new_message, queue_name_str=queue_name)

        except Exception as e:
            log_error(f"GraphQL publish_message error to queue '{queue_name}': {e}", icon_type='GRAPHQL', exc_info=True)
            raise Exception(f"Failed to publish message: {e}")


# --- GraphQL Context Getter ---
async def get_graphql_context(
    request: Request, # Access request object
    response: Response, # Access response object
    background_tasks: BackgroundTasks, # Inject background tasks
    # Use HTTPBearer for token, allows optional authentication if needed later
    auth: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
) -> Dict:
    """Provides context for GraphQL resolvers, including authenticated user and background tasks."""
    context = {
        "request": request,
        "response": response,
        "background_tasks": background_tasks, # Make BT available if needed by mutations
        "current_user": None
    }
    if auth: # If Authorization header was present
        try:
            # Use the internal decode logic, expecting an access token for GQL access
            username = await _decode_token(auth.credentials, "access")
            context["current_user"] = username
        except HTTPException as auth_exc:
            # GQL should ideally raise its own errors, but we can log here
            log_warning(f"GraphQL authentication failed: {auth_exc.detail}", icon_type='AUTH')
            # Do not raise HTTPException here; let Strawberry handle lack of user if resolvers require it
            # Resolvers should check `info.context.get("current_user")` if auth is mandatory

    return context


# --- Initialize GraphQL Schema and Router ---
gql_schema = strawberry.Schema(query=QueryGQL, mutation=MutationGQL)
graphql_app = GraphQLRouter(
    gql_schema,
    context_getter=get_graphql_context, # Use custom context getter
    graphiql=None, # Deprecated: Use graphql_ide instead
    graphql_ide="apollo-sandbox" # Preferred: "apollo-sandbox", "graphiql"
)

app.include_router(
    graphql_app,
    prefix="/graphql",
    tags=["GraphQL"],
    # Authentication is handled within the context_getter/resolvers now
)
log_success("🍓 GraphQL endpoint /graphql configured.", icon_type='GRAPHQL')


# --- Global Exception Handlers ---
# Order handlers from most specific to least specific

@app.exception_handler(DoesNotExist)
async def tortoise_does_not_exist_handler(request: Request, exc: DoesNotExist):
    """Handles Tortoise DoesNotExist errors, returning 404."""
    model_name = str(exc).split(":")[0] # Attempt to get model name
    detail = f"Resource not found ({model_name})."
    log_warning(f"Resource Not Found (DB): {exc} ({request.method} {request.url.path})", icon_type='DB', extra={"client": request.client.host})
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": detail},
    )

@app.exception_handler(IntegrityError)
async def tortoise_integrity_error_handler(request: Request, exc: IntegrityError):
    """Handles Tortoise IntegrityError (e.g., unique constraint), returning 409."""
    detail = "Database conflict occurred."
    # Try to extract specific constraint violation message if available (driver-dependent)
    if hasattr(exc, 'args') and exc.args:
         detail += f" Details: {exc.args[0]}"
    log_warning(f"Database Integrity Conflict: {exc} ({request.method} {request.url.path})", icon_type='DB', extra={"client": request.client.host})
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"detail": detail},
    )

@app.exception_handler(ValidationError)
async def pydantic_validation_exception_handler(request: Request, exc: ValidationError):
    """Handles Pydantic validation errors, returning 422."""
    log_warning(f"Request Validation Error: {exc.errors()} ({request.method} {request.url.path})", icon_type='HTTP', extra={"client": request.client.host})
    # Provide structured error details
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Request validation failed", "errors": exc.errors()},
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handles FastAPI's standard HTTPExceptions."""
    log_level = log_warning if 400 <= exc.status_code < 500 else log_error
    icon = 'HTTP' if 400 <= exc.status_code < 500 else 'ERROR'
    log_level(
        f"HTTP Error Handled: Status={exc.status_code}, Detail='{exc.detail}' ({request.method} {request.url.path})",
        icon_type=icon,
        extra={"client": request.client.host if request.client else "N/A"}
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None), # Include headers like WWW-Authenticate
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Generic fallback handler for any unhandled exceptions, returning 500."""
    tb_str = "".join(traceback.format_exception(etype=type(exc), value=exc, tb=exc.__traceback__))
    log_critical(
        f"Unhandled Internal Server Error: {type(exc).__name__}: {exc} ({request.method} {request.url.path})",
        icon_type='CRITICAL',
        exc_info=False, # Traceback logged separately
        extra={
            "client": request.client.host if request.client else "N/A",
            "traceback_summary": tb_str.splitlines()[-3:], # Log last few lines of traceback
            "full_traceback": tb_str # Include full traceback in JSON log if needed
        }
    )
    # Update global error state
    async with stats_lock:
        app_stats["last_error"] = f"Unhandled {type(exc).__name__} @ {datetime.now(timezone.utc).isoformat()}"

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected internal server error occurred. Please check server logs."},
    )

# --- Main Execution Block ---
import os
import sys
# Assume the following are defined/imported elsewhere:
# - settings (with CERT_DIR, CERT_FILE, KEY_FILE attributes)
# - log_info, log_warning, log_critical, log_success functions
# - generate_self_signed_cert function

if __name__ == '__main__':
    log_info("🏁 Main execution block started...", icon_type='STARTUP')

    # --- 1. Check/Generate Self-Signed Certificates for HTTPS ---
    log_info("Checking for SSL certificate and key...", icon_type='SEC')
    try:
        # Ensure the certificate directory exists
        os.makedirs(settings.CERT_DIR, exist_ok=True)

        cert_exists = os.path.exists(settings.CERT_FILE)
        key_exists = os.path.exists(settings.KEY_FILE)

        # Check if both certificate and key file exist
        if cert_exists and key_exists:
            log_success(f"🛡️ SSL Certificate '{os.path.basename(settings.CERT_FILE)}' and Key '{os.path.basename(settings.KEY_FILE)}' found in '{settings.CERT_DIR}'.", icon_type='SEC')
        else:
            # If one or both are missing, attempt generation
            missing_files = []
            if not cert_exists: missing_files.append(os.path.basename(settings.CERT_FILE))
            if not key_exists: missing_files.append(os.path.basename(settings.KEY_FILE))
            log_warning(f"SSL {' / '.join(missing_files)} not found. Generating new self-signed ones for localhost...", icon_type='SEC')

            try:
                # Import 'ipaddress' only when needed for generation
                # This avoids an unnecessary import if certs already exist.
                import ipaddress # noqa: F401 -- Keep import here as it's conditional
                log_info("Attempting to generate self-signed certificates...", icon_type='GEN')

                if not generate_self_signed_cert(settings.CERT_FILE, settings.KEY_FILE, common_name="localhost"):
                    # The function itself should ideally log details, but we catch the failure indication
                    log_critical("Critical failure generating SSL certificates (function returned false). Aborting.", icon_type='CRITICAL')
                    sys.exit(1)
                else:
                    log_success("✅ Successfully generated self-signed SSL certificate and key.", icon_type='SEC')

            except ImportError:
                log_critical("The 'ipaddress' module is required to generate certificates with IP SAN. Install it (`pip install ipaddress`) or provide existing certs.", icon_type='CRITICAL')
                sys.exit(1)
            except Exception as cert_gen_e:
                # Catch any other unexpected error during the generation process
                log_critical(f"Unexpected error during certificate generation: {cert_gen_e}", icon_type='CRITICAL')
                sys.exit(1)

    except Exception as setup_e:
         # Catch potential errors during directory creation or initial path checks
         log_critical(f"Unexpected error during initial certificate setup check: {setup_e}", icon_type='CRITICAL')
         sys.exit(1)

    # --- Continue with the rest of the main execution ---
    log_info("Initial setup checks complete. Proceeding...", icon_type='SETUP')
    # ... (rest of your main script logic would go here) ...
    # For example:
    # server = setup_server()
    # server.run()

    # DB Init and Redis Init are handled by the lifespan manager

    # Log Configuration Summary
    log_info(f"=== Configuration Summary ===", icon_type='INFO')
    log_info(f"  Project: {settings.PROJECT_NAME} v{settings.VERSION}", icon_type='INFO')
    log_info(f"  Environment: {settings.APP_ENV}", icon_type='INFO')
    log_info(f"  Log Level: {settings.LOG_LEVEL_STR}", icon_type='LOGS')
    log_info(f"  JWT Secret: {'Set (Hidden)' if settings.JWT_SECRET_KEY != secrets.token_hex(32) else 'Using Generated Default'}", icon_type='AUTH')
    log_info(f"  DB Path: {settings.DB_PATH}", icon_type='DB')
    log_info(f"  Redis URL: {settings.REDIS_URL} (SSE DB: {settings.REDIS_SSE_DB}, Limiter DB: {settings.REDIS_RATE_LIMIT_DB})", icon_type='SSE')
    log_info(f"  Rate Limit: {settings.DEFAULT_RATE_LIMIT}", icon_type='RATELIMIT')
    log_info(f"  CORS Origins: {settings.ALLOWED_ORIGINS}", icon_type='HTTP')
    log_info(f"  Log Dir: {settings.LOG_DIR}", icon_type='LOGS')
    log_info(f"  Cert Dir: {settings.CERT_DIR}", icon_type='SEC')
    log_info(f"============================", icon_type='INFO')


    # Determine Uvicorn settings based on environment
    reload_enabled = settings.APP_ENV == "development"
    log_level_uvicorn = "debug" if reload_enabled else "info"

    log_info(f"🌐🚀 Starting Uvicorn server on https://0.0.0.0:{settings.API_PORT}", icon_type='STARTUP', extra={"reload": reload_enabled, "log_level": log_level_uvicorn})
    log_info(f"   Access API root at: https://localhost:{settings.API_PORT}/", icon_type='HTTP')
    log_info(f"   Swagger UI docs:  https://localhost:{settings.API_PORT}/docs", icon_type='HTTP')
    log_info(f"   ReDoc docs:       https://localhost:{settings.API_PORT}/redoc", icon_type='HTTP')
    log_info(f"   GraphQL endpoint: https://localhost:{settings.API_PORT}/graphql", icon_type='GRAPHQL')
    log_info("   Press Ctrl+C to stop the server.", icon_type='INFO')

    try:
        uvicorn.run(
            "__main__:app", # Point to the FastAPI app instance in this file
            host="0.0.0.0",
            port=settings.API_PORT,
            log_level=log_level_uvicorn,
            ssl_keyfile=settings.KEY_FILE,
            ssl_certfile=settings.CERT_FILE,
            reload=reload_enabled,
            # lifespan="on" # Uvicorn detects lifespan automatically
            use_colors=True # Enable Uvicorn's own color logs if desired
        )
    except KeyboardInterrupt:
        log_info("\n🚦 Server shutdown requested via Ctrl+C.", icon_type='SHUTDOWN')
    except Exception as e:
        # Catch potential startup errors (e.g., port binding)
        log_critical(f"Fatal: Failed to start or run Uvicorn server: {e}", exc_info=True)
        sys.exit(1)
    finally:
        log_info("🏁 Uvicorn server process finished.", icon_type='SHUTDOWN')