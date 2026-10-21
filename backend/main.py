"""
SKYLAR - Backend API
A comprehensive Cloudflare zone and security reporting application.
"""

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
import csv
import io
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, JSON, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone as dt_timezone
from passlib.context import CryptContext
import jwt
from jwt.exceptions import PyJWTError
import httpx
import asyncio
import os
import json
import re
import secrets
import ipaddress
import socket
import time
import threading
from cryptography.fernet import Fernet, InvalidToken
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from contextlib import asynccontextmanager

from exposure import rules as exposure_rules
from exposure import signatures as exposure_signatures
from exposure import enrich as exposure_enrich
from exposure import verify as exposure_verify
from exposure import workbook as exposure_workbook
import branding
from exposure.collector import ExposureCollector

# ==================== Configuration ====================

# Database URL - Supports PostgreSQL (recommended) or SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL:
    raise ValueError(
        "DATABASE_URL environment variable must be set!\n"
        "For local SQLite, use sqlite:///./data/skylar.db; "
        "for PostgreSQL, provide a connection URL with your configured credentials."
    )

# SECRET_KEY - REQUIRED! Will fail if not set
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError(
        "SECRET_KEY environment variable must be set!\n"
        "Generate a secure key with: python -c 'import secrets; print(secrets.token_urlsafe(32))'\n"
        "Then set it in your .env file: SECRET_KEY=<generated-key>"
    )

# JWT Configuration
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour (reduced from 24 hours for security)

# Compose passes the whole .env file through, so a documented-but-blank line
# like SYNC_INTERVAL_MINUTES= must read as "use the default", not crash.
def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    return value.strip() if value and value.strip() else default

def _env_int(name: str, default: int) -> int:
    return int(_env_str(name, str(default)))

def _env_float(name: str, default: float) -> float:
    return float(_env_str(name, str(default)))


# CORS Configuration - Specific origins only, no wildcards
ALLOWED_ORIGINS = [o.strip() for o in _env_str("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",") if o.strip()]

# Expose the interactive API docs (/docs, /redoc, /openapi.json). Off by
# default so a production instance doesn't publish its full API surface;
# set ENABLE_DOCS=true for local development.
ENABLE_DOCS = os.getenv("ENABLE_DOCS", "false").lower() in ("1", "true", "yes")

# How many hours of hourly analytics buckets to (re)fetch on every sync.
# Buckets are upserted on (zone_id, timestamp), so a deep lookback backfills
# gaps left by missed syncs instead of silently under-reporting history.
# 72h fits the shortest GraphQL retention tier (free plan); raise it for
# zones on plans with longer retention.
ANALYTICS_LOOKBACK_HOURS = _env_int("ANALYTICS_LOOKBACK_HOURS", 72)

# Automatic background sync interval in minutes; 0 disables the scheduler.
# Reachability checks can also run on a schedule but default to disabled
# because probing every hostname is more intrusive than an API sync.
SYNC_INTERVAL_MINUTES = _env_int("SYNC_INTERVAL_MINUTES", 60)
REACHABILITY_INTERVAL_MINUTES = _env_int("REACHABILITY_INTERVAL_MINUTES", 0)

# Reachability check rows older than this are pruned after each run so the
# table doesn't grow without bound; 0 disables pruning.
REACHABILITY_RETENTION_DAYS = _env_int("REACHABILITY_RETENTION_DAYS", 90)

# Exposure Analysis: where technology signature YAML files live, and how the
# opt-in active verify identifies itself and paces its GET probes.
EXPOSURE_SIGNATURES_DIR = _env_str("EXPOSURE_SIGNATURES_DIR", exposure_signatures.DEFAULT_SIGNATURES_DIR)
EXPOSURE_VERIFY_USER_AGENT = _env_str("EXPOSURE_VERIFY_USER_AGENT", exposure_verify.DEFAULT_USER_AGENT)
EXPOSURE_VERIFY_CONCURRENCY = max(1, _env_int("EXPOSURE_VERIFY_CONCURRENCY", 4))
EXPOSURE_VERIFY_DELAY_SECONDS = _env_float("EXPOSURE_VERIFY_DELAY_SECONDS", 0.25)

# Database setup
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
security = HTTPBearer()

# ==================== Sync Progress Tracker ====================

_sync_progress_lock = threading.Lock()
_sync_progress: Dict[str, Any] = {
    "active": False,
    "stage": None,
    "message": None,
    "zones_total": 0,
    "zones_processed": 0,
    "started_at": None,
    "completed_at": None,
    "result": None,  # "success" | "failed" | None
    "error": None,
    "config_name": None,
    "configs_processed": 0,
    "configs_total": 0,
}

def _update_sync_progress(**kwargs):
    with _sync_progress_lock:
        _sync_progress.update(kwargs)

def _get_sync_progress():
    with _sync_progress_lock:
        return dict(_sync_progress)

# ==================== Reachability Progress Tracker ====================

_reachability_progress_lock = threading.Lock()
_reachability_progress: Dict[str, Any] = {
    "active": False,
    "stage": None,
    "message": None,
    "records_total": 0,
    "records_checked": 0,
    "started_at": None,
    "completed_at": None,
    "result": None,  # "success" | "failed" | None
    "error": None,
}

def _update_reachability_progress(**kwargs):
    with _reachability_progress_lock:
        _reachability_progress.update(kwargs)

def _get_reachability_progress():
    with _reachability_progress_lock:
        return dict(_reachability_progress)

# ==================== Exposure Progress Tracker ====================

_exposure_progress_lock = threading.Lock()
_exposure_progress: Dict[str, Any] = {
    "active": False,
    "stage": None,
    "message": None,
    "zones_total": 0,
    "zones_processed": 0,
    "hosts_total": 0,
    "hosts_verified": 0,
    "run_id": None,
    "signature_name": None,
    "started_at": None,
    "completed_at": None,
    "result": None,  # "success" | "failed" | None
    "error": None,
}

def _update_exposure_progress(**kwargs):
    with _exposure_progress_lock:
        _exposure_progress.update(kwargs)

def _get_exposure_progress():
    with _exposure_progress_lock:
        return dict(_exposure_progress)

# ==================== Database Models ====================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)

class CloudflareConfig(Base):
    __tablename__ = "cloudflare_configs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    api_token = Column(String(500), nullable=False)  # Will store encrypted token
    account_id = Column(String(100))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("users.id"))

class Zone(Base):
    __tablename__ = "zones"

    id = Column(Integer, primary_key=True, index=True)
    zone_id = Column(String(100), unique=True, index=True, nullable=False)
    # Which CloudflareConfig this zone was synced from; nullable for rows
    # created before this column existed - the next sync claims them
    config_id = Column(Integer, ForeignKey("cloudflare_configs.id"), index=True)
    name = Column(String(255), nullable=False)
    status = Column(String(50))
    paused = Column(Boolean, default=False)
    type = Column(String(50))
    development_mode = Column(Integer, default=0)
    name_servers = Column(JSON)
    original_name_servers = Column(JSON)
    created_on = Column(DateTime)
    modified_on = Column(DateTime)
    activated_on = Column(DateTime)
    account_id = Column(String(100))
    account_name = Column(String(255))
    last_synced = Column(DateTime, default=datetime.utcnow)

class DNSRecord(Base):
    __tablename__ = "dns_records"

    id = Column(Integer, primary_key=True, index=True)
    record_id = Column(String(100), unique=True, index=True)
    zone_id = Column(String(100), ForeignKey("zones.zone_id"), index=True)
    name = Column(String(255), nullable=False)
    type = Column(String(20), nullable=False)
    content = Column(Text)
    proxied = Column(Boolean, default=False)
    proxiable = Column(Boolean, default=True)
    ttl = Column(Integer, default=1)
    priority = Column(Integer)
    created_on = Column(DateTime)
    modified_on = Column(DateTime)
    last_synced = Column(DateTime, default=datetime.utcnow)

class SecuritySetting(Base):
    __tablename__ = "security_settings"

    id = Column(Integer, primary_key=True, index=True)
    zone_id = Column(String(100), ForeignKey("zones.zone_id"), index=True)
    setting_name = Column(String(100), nullable=False)
    setting_value = Column(JSON)
    enabled = Column(Boolean, default=False)
    last_synced = Column(DateTime, default=datetime.utcnow)

class TrafficMetric(Base):
    __tablename__ = "traffic_metrics"
    # One row per (zone, hour bucket); timestamp is the bucket start in UTC.
    __table_args__ = (
        Index("uq_traffic_zone_ts", "zone_id", "timestamp", unique=True),
    )

    id = Column(Integer, primary_key=True, index=True)
    zone_id = Column(String(100), ForeignKey("zones.zone_id"), index=True)
    timestamp = Column(DateTime, nullable=False)
    requests_all = Column(Integer, default=0)
    requests_cached = Column(Integer, default=0)
    requests_uncached = Column(Integer, default=0)
    bandwidth_all = Column(Float, default=0)
    bandwidth_cached = Column(Float, default=0)
    bandwidth_uncached = Column(Float, default=0)
    threats_all = Column(Integer, default=0)
    pageviews_all = Column(Integer, default=0)
    uniques_all = Column(Integer, default=0)
    ssl_encrypted = Column(Integer, default=0)
    ssl_unencrypted = Column(Integer, default=0)
    http_status = Column(JSON)
    content_type = Column(JSON)
    country = Column(JSON)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(100), nullable=False)
    resource_type = Column(String(100))
    resource_id = Column(String(100))
    details = Column(JSON)
    ip_address = Column(String(45))
    timestamp = Column(DateTime, default=datetime.utcnow)

class ReachabilityCheck(Base):
    __tablename__ = "reachability_checks"

    id = Column(Integer, primary_key=True, index=True)
    dns_record_id = Column(String(100), ForeignKey("dns_records.record_id"), index=True)
    zone_id = Column(String(100), ForeignKey("zones.zone_id"), index=True)
    hostname = Column(String(255), nullable=False)
    resolved_ip = Column(String(45))  # IPv4 or IPv6 address
    http_status_code = Column(Integer)
    https_status_code = Column(Integer)
    http_response_time_ms = Column(Integer)
    https_response_time_ms = Column(Integer)
    http_error = Column(String(500))
    https_error = Column(String(500))
    http_redirect_location = Column(String(500))
    https_redirect_location = Column(String(500))
    checked_at = Column(DateTime, default=datetime.utcnow, index=True)

class ReportPreset(Base):
    __tablename__ = "report_presets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    report_id = Column(String(50), nullable=False)  # full/zones/dns/reachability/security/traffic/summary
    format = Column(String(10), default="csv")
    params = Column(JSON)  # report-specific options, e.g. {"hours": 168}
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

# Exposure Analysis (docs/exposure-analysis/SPEC.md): one run per analysis,
# findings per host per rule, enrichment + handoff fields per host, and the
# metadata-only record of every active-verify probe.
class ExposureRun(Base):
    __tablename__ = "exposure_runs"

    id = Column(Integer, primary_key=True, index=True)
    config_id = Column(Integer, ForeignKey("cloudflare_configs.id"), index=True)
    signature_name = Column(String(100), nullable=False, index=True)
    signature_version = Column(String(20))
    window_start = Column(DateTime)
    window_end = Column(DateTime)
    status = Column(String(20), default="running")  # running | success | failed
    verify_enabled = Column(Boolean, default=False)
    coverage_note = Column(Text)
    edge_coverage = Column(JSON)  # {zone_name: "enabled"|"disabled"|"unknown"}
    stats = Column(JSON)          # counts per verdict, queries issued, etc.
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime)
    error = Column(Text)
    created_by = Column(Integer, ForeignKey("users.id"))

class ExposureFinding(Base):
    __tablename__ = "exposure_findings"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("exposure_runs.id"), index=True, nullable=False)
    host = Column(String(255), index=True, nullable=False)
    rule_id = Column(String(20), nullable=False)
    verdict = Column(String(30), nullable=False)      # likely_affected | catch_all | misrouted | info
    confidence = Column(String(20), nullable=False)   # verified | inferred
    evidence = Column(JSON)
    detail = Column(Text)
    origin_status_trusted = Column(Boolean, default=True)

class ExposureHost(Base):
    __tablename__ = "exposure_hosts"
    __table_args__ = (
        Index("uq_exposure_host_run", "run_id", "host", unique=True),
    )

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("exposure_runs.id"), index=True, nullable=False)
    host = Column(String(255), index=True, nullable=False)
    zone_id = Column(String(100))
    zone_name = Column(String(255))
    verdict = Column(String(30))           # strongest verdict across the host's findings
    hosting_provider = Column(String(255))
    origin_ip = Column(String(45))
    detected_version = Column(String(50))
    version_status = Column(String(20))    # current | behind | eol | unknown
    resolver = Column(String(50))
    resolved_ip = Column(String(45))
    verify_error = Column(String(300))
    summary = Column(JSON)                 # passive stats (requests, distinct IPs, ...)
    # Handoff fields - user-editable, carried forward across runs by host
    owner = Column(String(255))
    contact = Column(String(255))
    decision = Column(String(20))          # patch | restrict | offline | n/a
    notes = Column(Text)

class ExposureProbe(Base):
    __tablename__ = "exposure_probes"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("exposure_runs.id"), index=True, nullable=False)
    host = Column(String(255), index=True, nullable=False)
    kind = Column(String(20))              # baseline | canary | suspect
    path = Column(String(500))
    status = Column(Integer, default=0)    # 0 = nothing received
    size = Column(Integer)
    content_type = Column(String(100))
    title = Column(String(200))
    sha256_prefix = Column(String(16))
    secret_match_count = Column(Integer)
    debug_marker_count = Column(Integer)
    location = Column(String(300))
    error = Column(String(200))
    elapsed_ms = Column(Integer)
    checked_at = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)

# ==================== Pydantic Models ====================

def validate_password_strength(v: str) -> str:
    """Enforce strong password requirements (shared by every password input)"""
    if len(v) < 12:
        raise ValueError('Password must be at least 12 characters')
    if not re.search(r'[A-Z]', v):
        raise ValueError('Password must contain at least one uppercase letter')
    if not re.search(r'[a-z]', v):
        raise ValueError('Password must contain at least one lowercase letter')
    if not re.search(r'\d', v):
        raise ValueError('Password must contain at least one digit')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
        raise ValueError('Password must contain at least one special character')
    # Check against common passwords
    common_passwords = ['password', '12345678', 'qwerty', 'admin123', 'password123']
    if v.lower() in common_passwords:
        raise ValueError('Password is too common')
    return v

class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(min_length=12)
    full_name: Optional[str] = Field(None, max_length=255)
    is_admin: bool = False

    @validator('password')
    def validate_password(cls, v):
        return validate_password_strength(v)

class SetupAdminRequest(BaseModel):
    """First-run setup: create the initial admin account (only while no users exist)"""
    email: EmailStr
    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(min_length=12)
    full_name: Optional[str] = Field(None, max_length=255)

    @validator('password')
    def validate_password(cls, v):
        return validate_password_strength(v)

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None

class AdminPasswordReset(BaseModel):
    new_password: str = Field(min_length=12)

    @validator('new_password')
    def validate_password(cls, v):
        return validate_password_strength(v)

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(min_length=12)

    @validator('new_password')
    def validate_password(cls, v):
        return validate_password_strength(v)

class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: Optional[str]
    is_active: bool
    is_admin: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginRequest(BaseModel):
    username: str
    password: str

class CloudflareConfigCreate(BaseModel):
    name: str
    api_token: str
    account_id: Optional[str] = None

class CloudflareConfigResponse(BaseModel):
    id: int
    name: str
    account_id: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class ZoneResponse(BaseModel):
    id: int
    zone_id: str
    name: str
    status: Optional[str]
    paused: bool
    type: Optional[str]
    development_mode: int
    name_servers: Optional[List[str]]
    created_on: Optional[datetime]
    modified_on: Optional[datetime]
    account_name: Optional[str]
    last_synced: datetime
    dns_records_count: Optional[int] = 0
    proxied_records_count: Optional[int] = 0

    class Config:
        from_attributes = True

class DNSRecordResponse(BaseModel):
    id: int
    record_id: str
    zone_id: str
    name: str
    type: str
    content: Optional[str]
    proxied: bool
    proxiable: bool
    ttl: int
    priority: Optional[int]
    created_on: Optional[datetime]
    modified_on: Optional[datetime]

    class Config:
        from_attributes = True

class DNSRecordWithZoneResponse(DNSRecordResponse):
    zone_name: Optional[str] = None

class PaginatedDNSRecordResponse(BaseModel):
    total: int
    page: int
    page_size: int
    data: List[DNSRecordWithZoneResponse]

class SecuritySettingResponse(BaseModel):
    id: int
    zone_id: str
    setting_name: str
    setting_value: Any
    enabled: bool
    last_synced: datetime

    class Config:
        from_attributes = True

class TrafficMetricResponse(BaseModel):
    id: int
    zone_id: str
    timestamp: datetime
    requests_all: int
    requests_cached: int
    requests_uncached: int
    bandwidth_all: float
    bandwidth_cached: float
    bandwidth_uncached: float
    threats_all: int
    pageviews_all: int
    uniques_all: int
    ssl_encrypted: int
    ssl_unencrypted: int
    http_status: Optional[Dict]
    content_type: Optional[Dict]
    country: Optional[Dict]

    class Config:
        from_attributes = True

class PaginatedTrafficMetricResponse(BaseModel):
    total: int
    page: int
    page_size: int
    data: List[TrafficMetricResponse]

class DashboardStats(BaseModel):
    total_zones: int
    active_zones: int
    total_dns_records: int
    proxied_records: int
    total_requests_24h: int
    total_bandwidth_24h: float
    total_threats_24h: int
    cache_hit_ratio: float
    security_features_enabled: int

class ReachabilityCheckResponse(BaseModel):
    id: int
    dns_record_id: str
    zone_id: str
    hostname: str
    resolved_ip: Optional[str]
    http_status_code: Optional[int]
    https_status_code: Optional[int]
    http_response_time_ms: Optional[int]
    https_response_time_ms: Optional[int]
    http_error: Optional[str]
    https_error: Optional[str]
    http_redirect_location: Optional[str] = None
    https_redirect_location: Optional[str] = None
    checked_at: datetime

    class Config:
        from_attributes = True

class PaginatedReachabilityResponse(BaseModel):
    total: int
    page: int
    page_size: int
    data: List[ReachabilityCheckResponse]

VALID_REPORT_IDS = ("full", "zones", "dns", "reachability", "security", "traffic", "summary")

class ReportPresetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    report_id: str
    format: str = Field("csv", pattern=r"^(csv|xlsx|pdf)$")
    params: Optional[Dict[str, Any]] = None

    @validator("report_id")
    def validate_report_id(cls, v):
        if v not in VALID_REPORT_IDS:
            raise ValueError(f"report_id must be one of {VALID_REPORT_IDS}")
        return v

class ReportPresetResponse(BaseModel):
    id: int
    name: str
    report_id: str
    format: str
    params: Optional[Dict[str, Any]]
    created_at: datetime

    class Config:
        from_attributes = True

class ExposureRunCreate(BaseModel):
    config_id: int
    signature_name: str = Field(..., min_length=1, max_length=100)
    window_days: int = Field(7, ge=1, le=30)
    verify: bool = False

class ExposureHostUpdate(BaseModel):
    owner: Optional[str] = Field(None, max_length=255)
    contact: Optional[str] = Field(None, max_length=255)
    decision: Optional[str] = Field(None, pattern=r"^(patch|restrict|offline|n/a)$")
    notes: Optional[str] = Field(None, max_length=4000)

class ExposureRunResponse(BaseModel):
    id: int
    config_id: Optional[int]
    signature_name: str
    signature_version: Optional[str]
    window_start: Optional[datetime]
    window_end: Optional[datetime]
    status: str
    verify_enabled: Optional[bool]
    coverage_note: Optional[str]
    edge_coverage: Optional[Dict[str, Any]]
    stats: Optional[Dict[str, Any]]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    error: Optional[str]

    class Config:
        from_attributes = True

class ExposureFindingResponse(BaseModel):
    id: int
    host: str
    rule_id: str
    verdict: str
    confidence: str
    evidence: Optional[Dict[str, Any]]
    detail: Optional[str]
    origin_status_trusted: Optional[bool]

    class Config:
        from_attributes = True

class ExposureHostResponse(BaseModel):
    id: int
    host: str
    zone_id: Optional[str]
    zone_name: Optional[str]
    verdict: Optional[str]
    hosting_provider: Optional[str]
    origin_ip: Optional[str]
    detected_version: Optional[str]
    version_status: Optional[str]
    resolver: Optional[str]
    resolved_ip: Optional[str]
    verify_error: Optional[str]
    summary: Optional[Dict[str, Any]]
    owner: Optional[str]
    contact: Optional[str]
    decision: Optional[str]
    notes: Optional[str]

    class Config:
        from_attributes = True

class ExposureProbeResponse(BaseModel):
    id: int
    host: str
    kind: Optional[str]
    path: Optional[str]
    status: Optional[int]
    size: Optional[int]
    content_type: Optional[str]
    title: Optional[str]
    sha256_prefix: Optional[str]
    secret_match_count: Optional[int]
    debug_marker_count: Optional[int]
    location: Optional[str]
    error: Optional[str]
    elapsed_ms: Optional[int]
    checked_at: Optional[datetime]

    class Config:
        from_attributes = True

# ==================== Security Helper Functions ====================

# The salt every install used before ENCRYPTION_SALT existed. It must never
# change: tokens stored under it are re-encrypted on startup once a real salt
# is configured (see reencrypt_legacy_tokens), and that needs the old key.
LEGACY_ENCRYPTION_SALT = b'cloudflare-reporter-salt-v1'

# Key derivation is expensive (100k PBKDF2 rounds); cache one Fernet per salt
_FERNET_CACHE: Dict[bytes, Fernet] = {}

def _fernet_for_salt(salt: bytes) -> Fernet:
    f = _FERNET_CACHE.get(salt)
    if f is None:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        f = Fernet(base64.urlsafe_b64encode(kdf.derive(SECRET_KEY.encode())))
        _FERNET_CACHE[salt] = f
    return f

def _configured_salt() -> Optional[bytes]:
    salt_env = (os.getenv("ENCRYPTION_SALT") or "").strip()
    return salt_env.encode() if salt_env else None

_SALT_WARNED = False

def get_encryption_key() -> Fernet:
    """Fernet for the configured ENCRYPTION_SALT, or the legacy default salt"""
    global _SALT_WARNED
    salt = _configured_salt()
    if salt is None:
        if not _SALT_WARNED:
            print("WARNING: ENCRYPTION_SALT not set. Using insecure default salt.")
            _SALT_WARNED = True
        salt = LEGACY_ENCRYPTION_SALT
    return _fernet_for_salt(salt)

def encrypt_token(token: str) -> str:
    """Encrypt a Cloudflare API token before storing in database"""
    return get_encryption_key().encrypt(token.encode()).decode()

def decrypt_token(encrypted_token: str) -> str:
    """Decrypt a stored token. Falls back to the legacy salt so an install
    that just configured ENCRYPTION_SALT keeps working until startup
    re-encrypts its rows."""
    try:
        return get_encryption_key().decrypt(encrypted_token.encode()).decode()
    except InvalidToken:
        if _configured_salt() is None:
            raise
        return _fernet_for_salt(LEGACY_ENCRYPTION_SALT).decrypt(encrypted_token.encode()).decode()

def reencrypt_legacy_tokens(db: Session) -> int:
    """Re-encrypt any config token still stored under the legacy salt with
    the configured ENCRYPTION_SALT. Returns the number of rows updated."""
    if _configured_salt() is None:
        return 0
    current = get_encryption_key()
    legacy = _fernet_for_salt(LEGACY_ENCRYPTION_SALT)
    updated = 0
    for config in db.query(CloudflareConfig).all():
        try:
            current.decrypt(config.api_token.encode())
            continue
        except InvalidToken:
            pass
        try:
            plaintext = legacy.decrypt(config.api_token.encode()).decode()
        except InvalidToken:
            print(f"WARNING: config '{config.name}' (id {config.id}) cannot be decrypted with the current "
                  f"or legacy salt; re-add its token in Settings.")
            continue
        config.api_token = current.encrypt(plaintext.encode()).decode()
        updated += 1
    if updated:
        db.commit()
    return updated

# ==================== Helper Functions ====================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except PyJWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        # Disabling a user must take effect immediately, not when their JWT expires
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    return user

async def get_admin_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

# ==================== Audit Logging ====================

def create_audit_log(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None
):
    """Create an audit log entry for tracking user actions"""
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
        timestamp=datetime.utcnow()
    )
    db.add(audit_log)
    db.commit()

# ==================== Cloudflare API Client ====================

def parse_analytics_response(response: Dict, zone_id: str = "") -> List[Dict]:
    """Parse a GraphQL analytics response into a list of hourly traffic buckets.

    Returns [] when the zone has no analytics access (authz error) or no data.
    Raises on any other GraphQL error so callers don't mistake failures for
    zero traffic.
    """
    if response.get("errors"):
        errors = response["errors"]
        for error in errors:
            if error.get("extensions", {}).get("code") == "authz":
                print(f"Zone {zone_id} does not have analytics access (authz error), returning empty data")
                return []
        print(f"GraphQL errors for zone {zone_id}: {errors}")
        raise Exception(f"GraphQL query failed: {errors}")

    data = response.get("data") or {}
    zones = (data.get("viewer") or {}).get("zones") or []
    if not zones:
        return []

    buckets = []
    for group in zones[0].get("httpRequests1hGroups") or []:
        bucket_datetime = (group.get("dimensions") or {}).get("datetime")
        if not bucket_datetime:
            continue
        buckets.append({
            "datetime": bucket_datetime,
            "sum": group.get("sum") or {},
            "uniq": group.get("uniq") or {},
        })
    return buckets


def analytics_window(hours: int, now: Optional[datetime] = None) -> Tuple[datetime, datetime]:
    """[start, end) covering the last `hours` hourly buckets, including the
    current partial hour.

    The start is aligned to the hour and the span never exceeds `hours`;
    Cloudflare rejects httpRequests1hGroups queries wider than the plan's
    retention (3d on free zones), and flooring a `now - hours` start
    overshoots that by up to 59m59s.
    """
    end_time = now or datetime.utcnow()
    current_hour = end_time.replace(minute=0, second=0, microsecond=0)
    start_time = current_hour - timedelta(hours=hours - 1)
    return start_time, end_time


class CloudflareClient:
    BASE_URL = "https://api.cloudflare.com/client/v4"

    def __init__(self, api_token: str):
        self.api_token = api_token
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }

    MAX_RETRIES = 3

    async def _send_with_retry(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response:
        """Send a request, retrying on 429 with the server's Retry-After hint"""
        for attempt in range(self.MAX_RETRIES + 1):
            response = await client.request(method, url, headers=self.headers, timeout=30.0, **kwargs)
            if response.status_code != 429 or attempt == self.MAX_RETRIES:
                return response
            retry_after = response.headers.get("retry-after")
            try:
                delay = min(float(retry_after), 60.0) if retry_after else 2.0 * (attempt + 1)
            except ValueError:
                delay = 2.0 * (attempt + 1)
            print(f"Cloudflare rate limit hit on {url}, retrying in {delay}s...")
            await asyncio.sleep(delay)
        return response

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        async with httpx.AsyncClient() as client:
            response = await self._send_with_retry(client, method, f"{self.BASE_URL}{endpoint}", **kwargs)
            response.raise_for_status()
            body = response.json()
            # Cloudflare can return HTTP 200 with success:false; treating that
            # as an empty result would silently truncate synced data
            if isinstance(body, dict) and body.get("success") is False:
                raise Exception(f"Cloudflare API error on {endpoint}: {body.get('errors')}")
            return body

    async def _graphql_request(self, query: str, variables: Dict = None) -> Dict:
        """Make a GraphQL API request"""
        async with httpx.AsyncClient() as client:
            payload = {
                "query": query,
                "variables": variables or {}
            }
            response = await self._send_with_retry(client, "POST", f"{self.BASE_URL}/graphql", json=payload)
            response.raise_for_status()
            return response.json()

    async def list_zones(self, page: int = 1, per_page: int = 50) -> Dict:
        return await self._request("GET", f"/zones?page={page}&per_page={per_page}")

    async def list_all_zones(self) -> List[Dict]:
        """Fetch all zones across all pages"""
        all_zones = []
        page = 1
        per_page = 50

        while True:
            response = await self.list_zones(page=page, per_page=per_page)
            zones = response.get("result", [])
            all_zones.extend(zones)

            # Check if there are more pages
            result_info = response.get("result_info", {})
            total_pages = result_info.get("total_pages", 1)

            if page >= total_pages:
                break

            page += 1

        return all_zones

    async def get_zone(self, zone_id: str) -> Dict:
        return await self._request("GET", f"/zones/{zone_id}")

    async def list_dns_records(self, zone_id: str, page: int = 1, per_page: int = 100) -> Dict:
        return await self._request("GET", f"/zones/{zone_id}/dns_records?page={page}&per_page={per_page}")

    async def list_all_dns_records(self, zone_id: str) -> List[Dict]:
        """Fetch all DNS records for a zone across all pages"""
        all_records = []
        page = 1
        per_page = 100

        while True:
            response = await self.list_dns_records(zone_id, page=page, per_page=per_page)
            records = response.get("result", [])
            all_records.extend(records)

            # Check if there are more pages
            result_info = response.get("result_info", {})
            total_pages = result_info.get("total_pages", 1)

            if page >= total_pages:
                break

            page += 1

        return all_records

    async def get_zone_settings(self, zone_id: str) -> Dict:
        return await self._request("GET", f"/zones/{zone_id}/settings")

    async def get_zone_analytics(self, zone_id: str, hours: int = 24) -> List[Dict]:
        """Fetch hourly traffic buckets for the last `hours` hours via the GraphQL API.

        Returns a list of {"datetime", "sum", "uniq"} dicts, one per hour bucket.
        """
        start_time, end_time = analytics_window(hours)

        start_iso = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Values are inlined as JSON literals because Cloudflare's GraphQL schema
        # uses custom scalar names (string/Time) for variable declarations.
        query = """
        query {
          viewer {
            zones(filter: { zoneTag: %s }) {
              httpRequests1hGroups(
                filter: { datetime_geq: %s, datetime_lt: %s }
                limit: %d
                orderBy: [datetime_ASC]
              ) {
                dimensions {
                  datetime
                }
                sum {
                  requests
                  cachedRequests
                  bytes
                  cachedBytes
                  threats
                  pageViews
                  encryptedRequests
                  countryMap {
                    clientCountryName
                    requests
                  }
                  responseStatusMap {
                    edgeResponseStatus
                    requests
                  }
                  contentTypeMap {
                    edgeResponseContentTypeName
                    requests
                  }
                }
                uniq {
                  uniques
                }
              }
            }
          }
        }
        """ % (json.dumps(zone_id), json.dumps(start_iso), json.dumps(end_iso), hours + 1)

        response = await self._graphql_request(query)
        return parse_analytics_response(response, zone_id)

    async def get_firewall_settings(self, zone_id: str) -> Dict:
        return await self._request("GET", f"/zones/{zone_id}/firewall/rules")

    async def get_waf_packages(self, zone_id: str) -> Dict:
        try:
            return await self._request("GET", f"/zones/{zone_id}/firewall/waf/packages")
        except:
            return {"result": []}

    async def verify_token(self) -> Dict:
        return await self._request("GET", "/user/tokens/verify")

    async def get_managed_waf_state(self, zone_id: str) -> str:
        """'enabled' when the zone's managed-WAF phase entrypoint has at least
        one enabled execute rule, 'disabled' when the phase is empty/absent,
        'unknown' when the token can't read rulesets (needs Zone WAF Read)."""
        try:
            body = await self._request("GET", f"/zones/{zone_id}/rulesets/phases/http_request_firewall_managed/entrypoint")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return "disabled"
            return "unknown"
        except Exception:
            return "unknown"
        rules = (body.get("result") or {}).get("rules") or []
        for rule in rules:
            if rule.get("action") == "execute" and rule.get("enabled", True):
                return "enabled"
        return "disabled"

# ==================== Sync Service ====================

SECURITY_SETTINGS = {
    "ssl", "always_use_https", "min_tls_version", "tls_1_3",
    "automatic_https_rewrites", "opportunistic_encryption",
    "security_level", "waf", "browser_check", "challenge_ttl",
    "email_obfuscation", "server_side_exclude", "hotlink_protection",
    "ip_geolocation", "websockets", "http2", "http3", "0rtt",
    "minify", "brotli", "rocket_loader", "mirage", "polish"
}
async def fetch_settings_safe(client, zone_id):
    try:
        return await client.get_zone_settings(zone_id)
    except Exception as e:
        print(f"Error fetching settings for zone {zone_id}: {e}")
        return None

async def fetch_analytics_safe(client, zone_id):
    """Fetch hourly analytics with the configured lookback so gaps between
    syncs are backfilled. If the zone's plan doesn't retain that much history
    the query fails, so retry once with 24h before giving up."""
    try:
        return await client.get_zone_analytics(zone_id, hours=ANALYTICS_LOOKBACK_HOURS)
    except Exception as e:
        if ANALYTICS_LOOKBACK_HOURS > 24:
            print(f"Analytics lookback of {ANALYTICS_LOOKBACK_HOURS}h failed for zone {zone_id} ({e}); retrying with 24h")
            try:
                return await client.get_zone_analytics(zone_id, hours=24)
            except Exception as retry_error:
                e = retry_error
        print(f"Error fetching analytics for zone {zone_id}: {e}")
        return None

async def fetch_zone_details(client, zone_data):
    zone_id = zone_data["id"]

    # Run API calls in parallel
    # This significantly reduces latency by overlapping network I/O
    dns_records, settings_response, analytics_response = await asyncio.gather(
        client.list_all_dns_records(zone_id),
        fetch_settings_safe(client, zone_id),
        fetch_analytics_safe(client, zone_id)
    )

    return zone_data, dns_records, settings_response, analytics_response

def parse_cf_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse a Cloudflare ISO-8601 timestamp into a naive UTC datetime,
    matching the convention (datetime.utcnow) used everywhere else so
    stored values compare consistently."""
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(dt_timezone.utc).replace(tzinfo=None)
    return parsed

def is_security_setting_enabled(name: str, value) -> bool:
    """Classify a Cloudflare zone setting value as enabled/disabled.

    Handles string enums ("off"/"essentially_off" are off), dict values like
    minify (enabled when any sub-setting is on), and numeric settings like
    challenge_ttl (a value, not a toggle - always counted as configured).
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return any(v == "on" for v in value.values())
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        return value not in ("", "off", "essentially_off")
    return True

def save_zone_data(
    db: Session,
    zone_data: dict,
    dns_records: list,
    settings_response: dict,
    analytics_response: dict,
    config_id: Optional[int] = None,
    existing_zones: Dict[str, Zone] = None,
    existing_dns_records: Dict[str, DNSRecord] = None,
    existing_settings: Dict[tuple, SecuritySetting] = None,
    existing_metrics: Dict[tuple, TrafficMetric] = None
):
    """Save fetched zone data to database"""
    # Zone Logic
    if existing_zones is not None:
        existing_zone = existing_zones.get(zone_data["id"])
    else:
        existing_zone = db.query(Zone).filter(Zone.zone_id == zone_data["id"]).first()

    zone_values = {
        "zone_id": zone_data["id"],
        "name": zone_data["name"],
        "status": zone_data.get("status"),
        "paused": zone_data.get("paused", False),
        "type": zone_data.get("type"),
        "development_mode": zone_data.get("development_mode", 0),
        "name_servers": zone_data.get("name_servers", []),
        "original_name_servers": zone_data.get("original_name_servers", []),
        "created_on": parse_cf_datetime(zone_data.get("created_on")),
        "modified_on": parse_cf_datetime(zone_data.get("modified_on")),
        "activated_on": parse_cf_datetime(zone_data.get("activated_on")),
        "account_id": zone_data.get("account", {}).get("id"),
        "account_name": zone_data.get("account", {}).get("name"),
        "config_id": config_id,
        "last_synced": datetime.utcnow()
    }

    if existing_zone:
        for key, value in zone_values.items():
            setattr(existing_zone, key, value)
    else:
        new_zone = Zone(**zone_values)
        db.add(new_zone)
        # If we have a cache, update it so subsequent lookups (if any) find it
        if existing_zones is not None:
            existing_zones[zone_data["id"]] = new_zone

    # Flush to database to ensure zone exists before adding child records
    # This is critical for foreign key integrity - DNS records, settings, and metrics
    # all reference this zone via zone_id, so the zone must exist in the database
    # before we add those records.
    db.flush()

    # DNS Records Logic
    for dns_data in dns_records:
        if existing_dns_records is not None:
            existing_dns = existing_dns_records.get(dns_data["id"])
        else:
            existing_dns = db.query(DNSRecord).filter(DNSRecord.record_id == dns_data["id"]).first()

        dns_values = {
            "record_id": dns_data["id"],
            "zone_id": zone_data["id"],
            "name": dns_data["name"],
            "type": dns_data["type"],
            "content": dns_data.get("content"),
            "proxied": dns_data.get("proxied", False),
            "proxiable": dns_data.get("proxiable", True),
            "ttl": dns_data.get("ttl", 1),
            "priority": dns_data.get("priority"),
            "created_on": parse_cf_datetime(dns_data.get("created_on")),
            "modified_on": parse_cf_datetime(dns_data.get("modified_on")),
            "last_synced": datetime.utcnow()
        }

        if existing_dns:
            for key, value in dns_values.items():
                setattr(existing_dns, key, value)
        else:
            new_dns = DNSRecord(**dns_values)
            db.add(new_dns)
            if existing_dns_records is not None:
                existing_dns_records[dns_data["id"]] = new_dns

    # Security Settings Logic
    if settings_response:
        try:
            settings = settings_response.get("result", [])

            security_settings = [
                "ssl", "always_use_https", "min_tls_version", "tls_1_3",
                "automatic_https_rewrites", "opportunistic_encryption",
                "security_level", "waf", "browser_check", "challenge_ttl",
                "email_obfuscation", "server_side_exclude", "hotlink_protection",
                "ip_geolocation", "websockets", "http2", "http3", "0rtt",
                "minify", "brotli", "rocket_loader", "mirage", "polish"
            ]

            for setting in settings:
                if setting["id"] in security_settings:
                    if existing_settings is not None:
                        existing_setting = existing_settings.get((zone_data["id"], setting["id"]))
                    else:
                        existing_setting = db.query(SecuritySetting).filter(
                            SecuritySetting.zone_id == zone_data["id"],
                            SecuritySetting.setting_name == setting["id"]
                        ).first()

                    setting_values = {
                        "zone_id": zone_data["id"],
                        "setting_name": setting["id"],
                        "setting_value": setting.get("value"),
                        "enabled": is_security_setting_enabled(setting["id"], setting.get("value")),
                        "last_synced": datetime.utcnow()
                    }

                    if existing_setting:
                        for key, value in setting_values.items():
                            setattr(existing_setting, key, value)
                    else:
                        new_setting = SecuritySetting(**setting_values)
                        db.add(new_setting)
                        if existing_settings is not None:
                            existing_settings[(zone_data["id"], setting["id"])] = new_setting
        except Exception as e:
             print(f"Error processing security settings for zone {zone_data['id']}: {e}")

    # Analytics Logic - one row per hourly bucket, upserted on (zone_id, timestamp)
    # so re-syncing the same window is idempotent instead of double-counting.
    if analytics_response:
        try:
            for bucket in analytics_response:
                bucket_ts = parse_cf_datetime(bucket["datetime"])
                sum_data = bucket.get("sum", {})
                uniq_data = bucket.get("uniq", {})

                requests_all = sum_data.get("requests", 0) or 0
                requests_cached = sum_data.get("cachedRequests", 0) or 0
                bandwidth_all = sum_data.get("bytes", 0) or 0
                bandwidth_cached = sum_data.get("cachedBytes", 0) or 0
                ssl_encrypted = sum_data.get("encryptedRequests", 0) or 0

                # Breakdown maps arrive as lists of {dimension, requests};
                # store them as {dimension: requests} for cheap re-aggregation
                http_status = {
                    str(e.get("edgeResponseStatus")): e.get("requests", 0) or 0
                    for e in sum_data.get("responseStatusMap") or []
                    if e.get("edgeResponseStatus") is not None
                }
                content_type = {
                    (e.get("edgeResponseContentTypeName") or "unknown"): e.get("requests", 0) or 0
                    for e in sum_data.get("contentTypeMap") or []
                }
                country = {
                    (e.get("clientCountryName") or "unknown"): e.get("requests", 0) or 0
                    for e in sum_data.get("countryMap") or []
                }

                metric_values = {
                    "requests_all": requests_all,
                    "requests_cached": requests_cached,
                    "requests_uncached": requests_all - requests_cached,
                    "bandwidth_all": bandwidth_all,
                    "bandwidth_cached": bandwidth_cached,
                    "bandwidth_uncached": bandwidth_all - bandwidth_cached,
                    "threats_all": sum_data.get("threats", 0) or 0,
                    "pageviews_all": sum_data.get("pageViews", 0) or 0,
                    "uniques_all": uniq_data.get("uniques", 0) or 0,
                    "ssl_encrypted": ssl_encrypted,
                    "ssl_unencrypted": requests_all - ssl_encrypted,
                    "http_status": http_status,
                    "content_type": content_type,
                    "country": country,
                }

                key = (zone_data["id"], bucket_ts)
                existing_metric = existing_metrics.get(key) if existing_metrics is not None else None
                if existing_metric is None:
                    # The prefetch cache only covers the expected look-back
                    # window; verify against the DB before inserting so a
                    # bucket outside that window can't violate the unique index
                    existing_metric = db.query(TrafficMetric).filter(
                        TrafficMetric.zone_id == zone_data["id"],
                        TrafficMetric.timestamp == bucket_ts
                    ).first()
                    if existing_metric is not None and existing_metrics is not None:
                        existing_metrics[key] = existing_metric

                if existing_metric:
                    for k, v in metric_values.items():
                        setattr(existing_metric, k, v)
                else:
                    new_metric = TrafficMetric(
                        zone_id=zone_data["id"],
                        timestamp=bucket_ts,
                        **metric_values
                    )
                    db.add(new_metric)
                    if existing_metrics is not None:
                        existing_metrics[key] = new_metric
        except Exception as e:
            print(f"Error processing analytics for zone {zone_data['id']}: {e}")

async def sync_cloudflare_data(db: Session, config: CloudflareConfig):
    """Synchronize all Cloudflare data for a configuration"""
    # Decrypt the API token before using it
    decrypted_token = decrypt_token(config.api_token)
    client = CloudflareClient(decrypted_token)

    try:
        _update_sync_progress(stage="fetching_zones", message="Fetching zones from Cloudflare...")

        # Sync zones - fetch ALL zones across all pages
        zones = await client.list_all_zones()

        _update_sync_progress(
            stage="processing",
            message=f"Processing {len(zones)} zones...",
            zones_total=len(zones),
            zones_processed=0,
        )

        # Optimization: Fetch all existing records upfront to avoid N+1 queries
        # This converts O(N) database queries into O(1) bulk queries.
        # Zones are scoped to this config (plus unclaimed legacy rows and zones
        # that moved here from another config) so multi-config installs don't
        # cross-contaminate each other's data.
        fetched_zone_ids = {z["id"] for z in zones}
        zone_scope_filter = (Zone.config_id == config.id) | (Zone.config_id.is_(None))
        if fetched_zone_ids:
            zone_scope_filter = zone_scope_filter | Zone.zone_id.in_(fetched_zone_ids)
        existing_zones = {z.zone_id: z for z in db.query(Zone).filter(zone_scope_filter).all()}
        existing_dns_records = {r.record_id: r for r in db.query(DNSRecord).all()}
        existing_settings = {(s.zone_id, s.setting_name): s for s in db.query(SecuritySetting).all()}

        # Scalar snapshots for the stale-data sweep. The sweep runs after
        # per-batch commits have expired these ORM instances (and after the
        # zone sweep may have deleted their rows), so it must not read
        # attributes off them - a refresh against a deleted row raises.
        prefetched_zone_configs = {z.zone_id: z.config_id for z in existing_zones.values()}
        prefetched_record_zones = {r.record_id: r.zone_id for r in existing_dns_records.values()}
        prefetched_setting_ids = {(s.zone_id, s.setting_name): s.id for s in existing_settings.values()}
        # Metric rows within the analytics look-back window, keyed by hour bucket
        # so save_zone_data can upsert instead of inserting duplicates
        metrics_window_start = datetime.utcnow() - timedelta(hours=ANALYTICS_LOOKBACK_HOURS + 1)
        existing_metrics = {
            (m.zone_id, m.timestamp): m
            for m in db.query(TrafficMetric).filter(TrafficMetric.timestamp >= metrics_window_start).all()
        }

        # Track what Cloudflare actually returned so anything absent can be
        # deleted afterwards instead of lingering forever
        fetched_record_ids = set()
        fetched_setting_keys = set()
        zones_with_settings = set()

        # Process in chunks to manage memory and concurrency
        BATCH_SIZE = 5
        processed_count = 0
        for i in range(0, len(zones), BATCH_SIZE):
            batch = zones[i:i + BATCH_SIZE]

            # Fetch data for batch in parallel
            # This separates the I/O bound API calls from the DB operations
            tasks = [fetch_zone_details(client, zone) for zone in batch]
            results = await asyncio.gather(*tasks)

            # Save data to database (synchronous)
            for zone_data, dns_records, settings_response, analytics_response in results:
                save_zone_data(
                    db,
                    zone_data,
                    dns_records,
                    settings_response,
                    analytics_response,
                    config_id=config.id,
                    existing_zones=existing_zones,
                    existing_dns_records=existing_dns_records,
                    existing_settings=existing_settings,
                    existing_metrics=existing_metrics
                )
                fetched_record_ids.update(r["id"] for r in dns_records)
                if settings_response:
                    zones_with_settings.add(zone_data["id"])
                    for setting in settings_response.get("result", []):
                        if setting["id"] in SECURITY_SETTINGS:
                            fetched_setting_keys.add((zone_data["id"], setting["id"]))
                processed_count += 1
                _update_sync_progress(
                    zones_processed=processed_count,
                    message=f"Processing zone {processed_count} of {len(zones)}...",
                )

            # Commit per batch so a mid-sync failure keeps the zones already
            # processed (upserts are idempotent, the next sync self-corrects)
            db.commit()

        _update_sync_progress(stage="cleaning", message="Removing stale records...")

        # Delete-by-absence: this point is only reached when every zone fetched
        # successfully, so anything we knew about that Cloudflare no longer
        # returned has been deleted upstream and must be removed locally too.

        # Zones (and their children) deleted in Cloudflare. Only zones owned by
        # this config or unclaimed legacy rows are candidates - other configs'
        # zones were never loaded into existing_zones.
        stale_zone_ids = [
            zone_id for zone_id, zone_config_id in prefetched_zone_configs.items()
            if zone_id not in fetched_zone_ids and zone_config_id in (None, config.id)
        ]
        if stale_zone_ids:
            print(f"Removing {len(stale_zone_ids)} zones no longer present in Cloudflare")
            for child_model in (DNSRecord, SecuritySetting, TrafficMetric, ReachabilityCheck):
                db.query(child_model).filter(child_model.zone_id.in_(stale_zone_ids)).delete(synchronize_session=False)
            db.query(Zone).filter(Zone.zone_id.in_(stale_zone_ids)).delete(synchronize_session=False)

        # DNS records deleted from zones that still exist
        stale_record_ids = [
            record_id for record_id, record_zone_id in prefetched_record_zones.items()
            if record_zone_id in fetched_zone_ids and record_id not in fetched_record_ids
        ]
        if stale_record_ids:
            print(f"Removing {len(stale_record_ids)} DNS records no longer present in Cloudflare")
            db.query(ReachabilityCheck).filter(ReachabilityCheck.dns_record_id.in_(stale_record_ids)).delete(synchronize_session=False)
            db.query(DNSRecord).filter(DNSRecord.record_id.in_(stale_record_ids)).delete(synchronize_session=False)

        # Security settings that disappeared - only for zones whose settings
        # fetch succeeded, otherwise a transient error would wipe them
        stale_setting_ids = [
            setting_id for (zone_id, setting_name), setting_id in prefetched_setting_ids.items()
            if zone_id in zones_with_settings
            and (zone_id, setting_name) not in fetched_setting_keys
            and setting_id is not None
        ]
        if stale_setting_ids:
            db.query(SecuritySetting).filter(SecuritySetting.id.in_(stale_setting_ids)).delete(synchronize_session=False)

        _update_sync_progress(stage="committing", message="Saving to database...")

        print(f"Sync complete: processed {len(zones)} zones, committing to database...")
        db.commit()
        print("Database commit successful!")
        return True
    except Exception as e:
        print(f"Sync failed, rolling back: {e}")
        db.rollback()
        raise e

# ==================== Reachability Check Service ====================

def _is_ip_blocked(ip_obj) -> bool:
    """True for addresses a reachability probe must never touch (SSRF guard)"""
    return (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            or ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified)

SSRF_BLOCKED_MESSAGE = "Access to private or local network resources is blocked."

def _ssrf_check(ips: List[str]) -> Optional[str]:
    """The single outbound-probe gate shared by Reachability and Exposure
    active verify. A single disallowed address blocks the whole host so a
    name can't mix public and internal records to slip through."""
    try:
        if any(_is_ip_blocked(ipaddress.ip_address(i)) for i in ips):
            return SSRF_BLOCKED_MESSAGE
    except ValueError:
        return SSRF_BLOCKED_MESSAGE
    return None

async def check_hostname_reachability(hostname: str, timeout: float = 10.0) -> dict:
    """Check HTTP and HTTPS reachability for a hostname and return resolved IP"""
    result = {
        "resolved_ip": None,
        "http_status_code": None,
        "https_status_code": None,
        "http_response_time_ms": None,
        "https_response_time_ms": None,
        "http_error": None,
        "https_error": None,
        "http_redirect_location": None,
        "https_redirect_location": None
    }

    # SSRF Protection: Resolve and validate ALL addresses (A and AAAA)
    try:
        loop = asyncio.get_running_loop()
        addrinfo = await loop.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        ips = []
        for _family, _type, _proto, _canon, sockaddr in addrinfo:
            if sockaddr[0] not in ips:
                ips.append(sockaddr[0])
        if not ips:
            raise socket.gaierror(socket.EAI_NONAME, "no addresses")
    except socket.gaierror:
        error_msg = "Could not resolve hostname."
        result["http_error"] = error_msg
        result["https_error"] = error_msg
        return result
    except Exception:
        # Catch other resolution errors but don't leak details
        error_msg = "DNS resolution failed."
        result["http_error"] = error_msg
        result["https_error"] = error_msg
        return result

    # Prefer IPv4 when the host is dual-stack, otherwise use the IPv6 address
    ip = next((i for i in ips if ipaddress.ip_address(i).version == 4), ips[0])
    result["resolved_ip"] = ip  # Store the resolved IP for display

    blocked_reason = _ssrf_check(ips)
    if blocked_reason:
        result["http_error"] = blocked_reason
        result["https_error"] = blocked_reason
        return result

    # Both probes connect to the validated IP (IPv6 literals need brackets);
    # connecting by hostname would re-resolve DNS and bypass the check above
    host_for_url = f"[{ip}]" if ":" in ip else ip

    # follow_redirects stays False: following from a pinned IP would either
    # unpin the connection or allow redirect-to-internal. 3xx responses are
    # recorded as reachable with their Location target instead.
    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout, verify=True) as client:

        async def check_http():
            try:
                start = time.perf_counter()
                # Use the resolved IP but set the Host header to the original hostname
                response = await client.get(f"http://{host_for_url}", headers={"Host": hostname})
                elapsed = (time.perf_counter() - start) * 1000
                result["http_status_code"] = response.status_code
                result["http_response_time_ms"] = int(elapsed)
                if 300 <= response.status_code < 400:
                    result["http_redirect_location"] = response.headers.get("location", "")[:500] or None
            except httpx.TimeoutException:
                result["http_error"] = "Connection timed out"
            except httpx.ConnectError:
                result["http_error"] = "Connection failed"
            except httpx.RequestError as e:
                result["http_error"] = f"Request failed: {type(e).__name__}"
            except Exception as e:
                result["http_error"] = f"Check failed: {type(e).__name__}"

        async def check_https():
            try:
                start = time.perf_counter()
                # Connect to the pinned IP while presenting the hostname for SNI;
                # the server certificate is validated against sni_hostname
                response = await client.get(
                    f"https://{host_for_url}",
                    headers={"Host": hostname},
                    extensions={"sni_hostname": hostname}
                )
                elapsed = (time.perf_counter() - start) * 1000
                result["https_status_code"] = response.status_code
                result["https_response_time_ms"] = int(elapsed)
                if 300 <= response.status_code < 400:
                    result["https_redirect_location"] = response.headers.get("location", "")[:500] or None
            except httpx.TimeoutException:
                result["https_error"] = "Connection timed out"
            except httpx.ConnectError:
                result["https_error"] = "Connection failed or SSL error"
            except httpx.RequestError as e:
                result["https_error"] = f"Request failed: {type(e).__name__}"
            except Exception as e:
                result["https_error"] = f"Check failed: {type(e).__name__}"

        # Execute HTTP and HTTPS checks concurrently to minimize total execution time
        await asyncio.gather(check_http(), check_https())

    return result

# ==================== Exposure Analysis Service ====================

EXPOSURE_VERDICT_RANK = exposure_rules.VERDICT_RANK
EXPOSURE_VERIFY_MAX_HOSTS = max(1, _env_int("EXPOSURE_VERIFY_MAX_HOSTS", 300))

def _strongest_verdict(verdicts) -> Optional[str]:
    best = None
    for v in verdicts:
        if best is None or EXPOSURE_VERDICT_RANK.get(v, -1) > EXPOSURE_VERDICT_RANK.get(best, -1):
            best = v
    return best

def _carry_forward_handoff(db: Session, host: str, before_run_id: int) -> Dict[str, Optional[str]]:
    """owner/contact/decision/notes survive across runs keyed by host (CONTEXT #14)"""
    prior = (db.query(ExposureHost)
             .filter(ExposureHost.host == host, ExposureHost.run_id != before_run_id)
             .order_by(ExposureHost.run_id.desc()).first())
    if not prior:
        return {}
    return {"owner": prior.owner, "contact": prior.contact, "decision": prior.decision, "notes": prior.notes}

def _load_signature_or_404(name: str) -> exposure_signatures.Signature:
    sig = exposure_signatures.get_signature(name, EXPOSURE_SIGNATURES_DIR)
    if not sig:
        raise HTTPException(status_code=404, detail=f"Signature '{name}' not found")
    return sig

def _exposure_verify_candidates(result, findings_by_host: Dict[str, List[exposure_rules.Finding]]) -> List[str]:
    """Hosts worth an active look, strongest verdict first, then by origin 2xx volume."""
    def rank(host):
        verdicts = [f.verdict for f in findings_by_host.get(host, [])]
        strongest = _strongest_verdict(verdicts)
        summary = result.hosts.get(host)
        return (-(EXPOSURE_VERDICT_RANK.get(strongest, -1)), -(summary.origin_2xx if summary else 0), host)
    candidates = {h for h, fs in findings_by_host.items() if any(f.rule_id != "EXP-006" for f in fs)}
    candidates |= {h for h, s in result.hosts.items() if s.origin_2xx > 0}
    return sorted(candidates, key=rank)[:EXPOSURE_VERIFY_MAX_HOSTS]

async def run_exposure_analysis(db: Session, run: ExposureRun, config: CloudflareConfig,
                                signature: exposure_signatures.Signature, verify_enabled: bool):
    """Stages 1-4 for one run. Writes findings/hosts/probes and finalizes the run row."""
    client = CloudflareClient(decrypt_token(config.api_token))
    zones = db.query(Zone).filter(Zone.config_id == config.id).all()
    if not zones:
        raise Exception("No zones synced for this configuration - run a sync first")
    notes: List[str] = []

    # ---- Stage 1: collect aggregated groups
    _update_exposure_progress(stage="collecting", message="Fetching Cloudflare IP ranges...", zones_total=len(zones))
    cf_ranges, note = await exposure_enrich.get_cloudflare_ranges()
    if note:
        notes.append(note)
    collector = ExposureCollector(client._graphql_request, signature, cf_ranges)
    for idx, zone in enumerate(zones):
        _update_exposure_progress(stage="collecting", message=f"Querying {zone.name}...", zones_processed=idx)
        await collector.collect_zone(zone.zone_id, zone.name, run.window_start, run.window_end,
                                     progress=lambda msg: _update_exposure_progress(message=msg))
    _update_exposure_progress(zones_processed=len(zones))
    if len(collector.zone_errors) == len(zones):
        raise Exception("Every zone failed to query: " + "; ".join(
            f"{z}: {e}" for z, e in list(collector.zone_errors.items())[:3]))
    groups = collector.groups()
    host_stats = collector.host_stats()

    # ---- Stage 2: classify
    _update_exposure_progress(stage="classifying", message="Classifying hosts...")
    zone_ids = [z.zone_id for z in zones]
    zone_name_by_id = {z.zone_id: z.name for z in zones}
    dns_rows = db.query(DNSRecord).filter(DNSRecord.zone_id.in_(zone_ids), DNSRecord.type.in_(["A", "AAAA"])).all()
    dns_records = [{"host": r.name, "type": r.type, "content": r.content, "proxied": r.proxied, "zone_id": r.zone_id}
                   for r in dns_rows]
    dns_zone_by_host = {r["host"].lower(): r["zone_id"] for r in dns_records}

    self_ips = sorted({row["source_ip"] for row in groups if row.get("kind") == "self_call" and row.get("source_ip")})
    enrichment, note = await exposure_enrich.lookup_hosting(self_ips)
    if note:
        notes.append(note)

    result = exposure_rules.classify(groups, signature, dns_records, cf_ranges, host_stats, enrichment)
    findings: List[exposure_rules.Finding] = list(result.findings)

    # EXP-006 edge coverage (optional scope; 'unknown' when the token can't read rulesets)
    _update_exposure_progress(stage="classifying", message="Checking managed WAF coverage...")
    edge_coverage: Dict[str, str] = {}
    for zone in zones:
        edge_coverage[zone.name] = await client.get_managed_waf_state(zone.zone_id)
        finding = exposure_rules.exp006_edge_coverage(zone.name, edge_coverage[zone.name])
        if finding:
            findings.append(finding)
    if edge_coverage and all(v == "unknown" for v in edge_coverage.values()):
        notes.append("Managed WAF state unreadable for every zone; grant the token Zone WAF Read for EXP-006.")

    feed_data, note = await exposure_enrich.fetch_version_feed(signature.version_spec.version_feed)
    if note:
        notes.append(note)
    feed = exposure_rules.parse_version_feed(feed_data) if feed_data else None

    findings_by_host: Dict[str, List[exposure_rules.Finding]] = {}
    for f in findings:
        findings_by_host.setdefault(f.host, []).append(f)

    # ---- Stage 3: active verify (opt-in)
    verify_results: Dict[str, Dict[str, Any]] = {}
    if verify_enabled:
        candidates = _exposure_verify_candidates(result, findings_by_host)
        _update_exposure_progress(stage="verifying", message=f"Probing {len(candidates)} host(s)...",
                                  hosts_total=len(candidates), hosts_verified=0)
        sem = asyncio.Semaphore(EXPOSURE_VERIFY_CONCURRENCY)
        done = 0

        async def verify_one(host: str):
            nonlocal done
            async with sem:
                try:
                    verify_results[host] = await exposure_verify.verify_host(
                        host, signature, _ssrf_check, user_agent=EXPOSURE_VERIFY_USER_AGENT,
                        delay_between=EXPOSURE_VERIFY_DELAY_SECONDS)
                except Exception as e:
                    verify_results[host] = {"host": host, "resolve_error": f"verify failed: {type(e).__name__}",
                                            "probes": [], "resolver": None, "resolved_ip": None, "blocked": False,
                                            "version_header": None}
                done += 1
                _update_exposure_progress(hosts_verified=done, message=f"Probed {done} of {len(candidates)} host(s)...")

        await asyncio.gather(*(verify_one(h) for h in candidates))
        notes.append(f"Active verify probed {len(candidates)} host(s) from this server's egress "
                     f"(User-Agent '{EXPOSURE_VERIFY_USER_AGENT[:40]}'); resolver and blocked/unresolved "
                     "states are recorded per host so a filtered vantage point is not mistaken for 'clean'.")

        for host, vr in verify_results.items():
            if vr.get("resolve_error") or vr.get("blocked"):
                continue
            detected, status, vfinding = exposure_rules.exp005_version_currency(host, vr.get("version_header"), signature, feed)
            if vfinding:
                findings.append(vfinding)
                findings_by_host.setdefault(host, []).append(vfinding)
            if detected:
                for f in findings_by_host.get(host, []):
                    if f.rule_id == "EXP-001" and f.verdict == exposure_rules.VERDICT_LIKELY:
                        f.confidence = exposure_rules.CONF_VERIFIED
            for extra in exposure_rules.active_findings(host, vr.get("probes") or [], signature):
                findings.append(extra)
                findings_by_host.setdefault(host, []).append(extra)

    # ---- Stage 4: persist
    _update_exposure_progress(stage="saving", message="Saving findings...")
    for f in findings:
        db.add(ExposureFinding(run_id=run.id, host=f.host, rule_id=f.rule_id, verdict=f.verdict,
                               confidence=f.confidence, evidence=f.evidence, detail=f.detail,
                               origin_status_trusted=f.origin_status_trusted))

    all_hosts = set(result.hosts) | set(findings_by_host) | set(verify_results)
    all_hosts.discard("")
    # Zone-level coverage findings (EXP-006) are not hosts
    all_hosts = {h for h in all_hosts
                 if not (h in edge_coverage and h not in result.hosts
                         and all(f.rule_id == "EXP-006" for f in findings_by_host.get(h, [])))}
    for host in sorted(all_hosts):
        host_findings = findings_by_host.get(host, [])
        summary = result.hosts.get(host)
        zone_id, zone_name = collector.host_zone(host)
        if not zone_id:
            zone_id = dns_zone_by_host.get(host)
            zone_name = zone_name_by_id.get(zone_id) if zone_id else None
        hosting = result.hosting.get(host, {})
        vr = verify_results.get(host, {})
        detected_version, version_status = None, None
        for f in host_findings:
            if f.rule_id == "EXP-005":
                detected_version = f.evidence.get("detected_version")
                version_status = f.evidence.get("version_status")
        db.add(ExposureHost(
            run_id=run.id, host=host, zone_id=zone_id, zone_name=zone_name,
            verdict=_strongest_verdict(f.verdict for f in host_findings) if host_findings else None,
            hosting_provider=hosting.get("hosting_provider"), origin_ip=hosting.get("origin_ip"),
            detected_version=detected_version, version_status=version_status,
            resolver=vr.get("resolver"), resolved_ip=vr.get("resolved_ip"),
            verify_error=(vr.get("resolve_error") or "")[:300] or None,
            summary=summary.to_dict() if summary else None,
            **_carry_forward_handoff(db, host, run.id),
        ))
        for p in vr.get("probes") or []:
            db.add(ExposureProbe(
                run_id=run.id, host=host, kind=p.get("kind"), path=(p.get("path") or "")[:500],
                status=p.get("status") or 0, size=p.get("size"), content_type=p.get("content_type"),
                title=p.get("title"), sha256_prefix=p.get("sha256_prefix"),
                secret_match_count=p.get("secret_match_count"), debug_marker_count=p.get("debug_marker_count"),
                location=p.get("location"), error=(p.get("error") or "")[:200] or None, elapsed_ms=p.get("elapsed_ms"),
            ))

    verdict_counts: Dict[str, int] = {}
    for host in all_hosts:
        v = _strongest_verdict(f.verdict for f in findings_by_host.get(host, []))
        if v:
            verdict_counts[v] = verdict_counts.get(v, 0) + 1
    run.coverage_note = collector.coverage_note() + ((" " + " ".join(notes)) if notes else "")
    run.edge_coverage = edge_coverage
    run.stats = {
        "zones": len(zones), "zones_skipped": len(collector.zone_errors), "graphql_queries": collector.queries,
        "groups": len(groups), "hosts": len(all_hosts), "findings": len(findings), "verdicts": verdict_counts,
        "verified_hosts": len(verify_results),
    }
    run.status = "success"
    run.finished_at = datetime.utcnow()
    db.commit()

def run_exposure_in_background(run_id: int, user_id: Optional[int], ip_address: Optional[str]):
    """Background task with its own DB session and event loop, mirroring run_sync_in_background."""
    from sqlalchemy.orm import sessionmaker

    SessionLocal_bg = sessionmaker(bind=engine)
    db = SessionLocal_bg()
    run = None
    try:
        run = db.query(ExposureRun).filter(ExposureRun.id == run_id).first()
        if not run:
            _update_exposure_progress(active=False, stage="failed", result="failed", error="Run not found",
                                      completed_at=datetime.utcnow().isoformat())
            return
        config = db.query(CloudflareConfig).filter(CloudflareConfig.id == run.config_id).first()
        signature = exposure_signatures.get_signature(run.signature_name, EXPOSURE_SIGNATURES_DIR)
        if not config or not signature:
            raise Exception("Configuration or signature disappeared before the run started")

        _update_exposure_progress(
            active=True, stage="starting", message=f"Starting {signature.title}...",
            zones_total=0, zones_processed=0, hosts_total=0, hosts_verified=0,
            run_id=run.id, signature_name=signature.name,
            started_at=datetime.utcnow().isoformat(), completed_at=None, result=None, error=None,
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_exposure_analysis(db, run, config, signature, bool(run.verify_enabled)))
        finally:
            loop.close()

        _update_exposure_progress(
            active=False, stage="complete", message="Exposure analysis complete",
            completed_at=datetime.utcnow().isoformat(), result="success",
        )
        create_audit_log(
            db=db, action="EXPOSURE_RUN_SUCCESS", user_id=user_id, resource_type="exposure",
            resource_id=str(run.id),
            details={"signature": run.signature_name, "stats": run.stats, "verify": bool(run.verify_enabled)},
            ip_address=ip_address,
        )
        print(f"✅ Exposure run {run_id} completed")
    except Exception as e:
        db.rollback()
        if run is not None:
            run.status = "failed"
            run.error = str(e)[:1000]
            run.finished_at = datetime.utcnow()
            db.commit()
        _update_exposure_progress(
            active=False, stage="failed", message=f"Exposure analysis failed: {str(e)[:100]}",
            completed_at=datetime.utcnow().isoformat(), result="failed", error=str(e)[:200],
        )
        create_audit_log(
            db=db, action="EXPOSURE_RUN_FAILED", user_id=user_id, resource_type="exposure",
            resource_id=str(run_id), details={"error": str(e)[:200]}, ip_address=ip_address,
        )
        print(f"❌ Exposure run {run_id} failed: {e}")
    finally:
        db.close()

# ==================== Background Scheduler ====================

_scheduler_lock = threading.Lock()
_scheduler_state: Dict[str, Any] = {
    "sync_interval_minutes": SYNC_INTERVAL_MINUTES,
    "reachability_interval_minutes": REACHABILITY_INTERVAL_MINUTES,
    "next_sync_at": None,
    "next_reachability_at": None,
}

def _update_scheduler_state(**kwargs):
    with _scheduler_lock:
        _scheduler_state.update(kwargs)

def _get_scheduler_state():
    with _scheduler_lock:
        return dict(_scheduler_state)

def _active_config_ids() -> List[int]:
    db = SessionLocal()
    try:
        return [c.id for c in db.query(CloudflareConfig).filter(CloudflareConfig.is_active == True).all()]
    finally:
        db.close()

async def scheduled_sync_loop():
    """Periodically sync all active configs so traffic history accrues without
    manual clicks. Reuses the existing background-sync path (audit logs,
    progress tracker, stats-cache invalidation) in a worker thread and skips a
    cycle when a manual sync is already in flight."""
    interval = SYNC_INTERVAL_MINUTES * 60
    while True:
        _update_scheduler_state(next_sync_at=(datetime.utcnow() + timedelta(seconds=interval)).isoformat())
        await asyncio.sleep(interval)
        try:
            if _get_sync_progress()["active"]:
                print("Scheduler: a sync is already running, skipping this cycle")
                continue
            config_ids = await asyncio.to_thread(_active_config_ids)
            if config_ids:
                print(f"Scheduler: starting scheduled sync of {len(config_ids)} config(s)")
                await asyncio.to_thread(run_sync_all_in_background, config_ids, None, "scheduler")
        except Exception as e:
            print(f"Scheduler: scheduled sync failed: {e}")

async def scheduled_reachability_loop():
    """Periodically run reachability checks for every A/AAAA/CNAME record so
    response-time history builds up for trend charts."""
    interval = REACHABILITY_INTERVAL_MINUTES * 60
    while True:
        _update_scheduler_state(next_reachability_at=(datetime.utcnow() + timedelta(seconds=interval)).isoformat())
        await asyncio.sleep(interval)
        try:
            if _get_reachability_progress()["active"]:
                print("Scheduler: a reachability check is already running, skipping this cycle")
                continue
            print("Scheduler: starting scheduled reachability checks")
            await asyncio.to_thread(run_reachability_in_background, None, None, "scheduler")
        except Exception as e:
            print(f"Scheduler: scheduled reachability check failed: {e}")

# ==================== App Lifespan ====================

def run_migrations():
    """Run any pending database migrations"""
    from sqlalchemy import text, inspect
    db = SessionLocal()
    try:
        # Check if resolved_ip column exists using SQLAlchemy inspector (works with any DB)
        inspector = inspect(engine)
        columns = [col['name'] for col in inspector.get_columns('reachability_checks')]

        if 'resolved_ip' not in columns:
            print("Running migration: Adding resolved_ip column to reachability_checks...")
            db.execute(text("ALTER TABLE reachability_checks ADD COLUMN resolved_ip VARCHAR(45)"))
            db.commit()
            print("Migration complete: resolved_ip column added")
        else:
            print("Migration check: resolved_ip column already exists")

        # Traffic metrics changed from per-sync snapshots to hourly buckets with a
        # unique (zone_id, timestamp) index. Pre-existing rows each held a single
        # arbitrary 1-minute sample mislabeled as a 24h total, so they are
        # numerically meaningless and must be removed rather than migrated.
        traffic_indexes = [ix["name"] for ix in inspector.get_indexes("traffic_metrics")]
        if "uq_traffic_zone_ts" not in traffic_indexes:
            print("Running migration: converting traffic_metrics to hourly buckets. "
                  "Deleting existing rows (old snapshot data was inaccurate); "
                  "history rebuilds from the next sync.")
            db.execute(text("DELETE FROM traffic_metrics"))
            db.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_traffic_zone_ts ON traffic_metrics (zone_id, timestamp)"))
            db.commit()
            print("Migration complete: traffic_metrics hourly bucket index added")

        zone_columns = [col['name'] for col in inspector.get_columns('zones')]
        if 'config_id' not in zone_columns:
            print("Running migration: Adding config_id column to zones...")
            db.execute(text("ALTER TABLE zones ADD COLUMN config_id INTEGER"))
            # With a single config all existing zones must belong to it; with
            # several we can't tell, so leave NULL and let the next sync claim them
            configs = db.query(CloudflareConfig).all()
            if len(configs) == 1:
                db.execute(text("UPDATE zones SET config_id = :cid"), {"cid": configs[0].id})
            db.commit()
            print("Migration complete: config_id column added to zones")

        reach_columns = [col['name'] for col in inspector.get_columns('reachability_checks')]
        for redirect_col in ("http_redirect_location", "https_redirect_location"):
            if redirect_col not in reach_columns:
                print(f"Running migration: Adding {redirect_col} column to reachability_checks...")
                db.execute(text(f"ALTER TABLE reachability_checks ADD COLUMN {redirect_col} VARCHAR(500)"))
                db.commit()
    except Exception as e:
        print(f"Migration error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run database migrations
    run_migrations()

    # Startup: on a fresh database, the web UI walks the user through creating
    # the first admin account (see /api/setup/*) - no console-printed password
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            print("=" * 80)
            print("No users exist yet.")
            print("Open the web UI to create your admin account (first-run setup).")
            print("=" * 80)
        migrated = reencrypt_legacy_tokens(db)
        if migrated:
            print(f"Re-encrypted {migrated} stored API token(s) with the configured ENCRYPTION_SALT")
    finally:
        db.close()

    # Start background schedulers (interval of 0 disables each one)
    scheduler_tasks = []
    if SYNC_INTERVAL_MINUTES > 0:
        scheduler_tasks.append(asyncio.create_task(scheduled_sync_loop()))
        print(f"Scheduler: automatic sync every {SYNC_INTERVAL_MINUTES} minutes")
    if REACHABILITY_INTERVAL_MINUTES > 0:
        scheduler_tasks.append(asyncio.create_task(scheduled_reachability_loop()))
        print(f"Scheduler: automatic reachability checks every {REACHABILITY_INTERVAL_MINUTES} minutes")

    yield

    for task in scheduler_tasks:
        task.cancel()

# ==================== FastAPI App ====================

app = FastAPI(
    title="SKYLAR API",
    description="Reporting and exposure analysis for Cloudflare",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Allow Swagger UI resources
    if request.url.path.startswith(("/docs", "/redoc")):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' https://fastapi.tiangolo.com"
    else:
        response.headers["Content-Security-Policy"] = "default-src 'self'"

    return response

# CORS middleware - Specific origins only (no wildcards for security)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # Specific origins only, no wildcards
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # Explicit methods
    allow_headers=["Content-Type", "Authorization"],  # Explicit headers
    max_age=600,  # Cache preflight for 10 minutes
)

# ==================== First-Run Setup Routes ====================

@app.get("/api/setup/status")
async def get_setup_status(db: Session = Depends(get_db)):
    """Whether first-run setup (initial admin creation) is still needed.
    Unauthenticated by design: the login screen uses it to decide what to show,
    and it only reveals that the instance is uninitialized."""
    return {"needs_setup": db.query(User).count() == 0}

@app.post("/api/setup/admin", response_model=Token)
@limiter.limit("5/minute")
async def create_first_admin(
    request: Request,
    payload: SetupAdminRequest,
    db: Session = Depends(get_db)
):
    """Create the initial admin account. Only works while no users exist;
    afterwards it is permanently disabled."""
    if db.query(User).count() > 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Setup has already been completed"
        )

    admin = User(
        email=payload.email,
        username=payload.username,
        hashed_password=get_password_hash(payload.password),
        full_name=payload.full_name,
        is_admin=True,
        is_active=True,
        last_login=datetime.utcnow()
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)

    create_audit_log(
        db=db,
        action="SETUP_ADMIN_CREATED",
        user_id=admin.id,
        resource_type="user",
        resource_id=str(admin.id),
        details={"username": admin.username},
        ip_address=request.client.host if request.client else None
    )

    # Log the new admin straight in so the UI lands on the dashboard
    access_token = create_access_token(data={"sub": admin.username})
    return {"access_token": access_token, "token_type": "bearer"}

# ==================== Auth Routes ====================

@app.post("/api/auth/login", response_model=Token)
@limiter.limit("5/minute")  # Maximum 5 login attempts per minute per IP
async def login(request: Request, login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login_data.username).first()

    # Always verify password even if user doesn't exist (prevents timing attacks)
    if user:
        password_valid = verify_password(login_data.password, user.hashed_password)
    else:
        # Perform dummy hash check to maintain constant timing
        dummy_hash = get_password_hash(secrets.token_urlsafe(16))
        verify_password(login_data.password, dummy_hash)
        password_valid = False

    ip_address = request.client.host if request.client else None

    if not user or not password_valid:
        # Log failed login attempt
        create_audit_log(
            db=db,
            action="LOGIN_FAILED",
            user_id=user.id if user else None,
            resource_type="user",
            resource_id=str(user.id) if user else None,
            details={"username": login_data.username, "reason": "invalid_credentials"},
            ip_address=ip_address
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    if not user.is_active:
        # Log disabled account access attempt
        create_audit_log(
            db=db,
            action="LOGIN_FAILED",
            user_id=user.id,
            resource_type="user",
            resource_id=str(user.id),
            details={"username": user.username, "reason": "account_disabled"},
            ip_address=ip_address
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )

    user.last_login = datetime.utcnow()
    db.commit()

    # Log successful login
    create_audit_log(
        db=db,
        action="LOGIN_SUCCESS",
        user_id=user.id,
        resource_type="user",
        resource_id=str(user.id),
        details={"username": user.username},
        ip_address=ip_address
    )

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/auth/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/api/auth/change-password")
async def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Passwords arrive in the JSON body (never query parameters, which land in
    # access logs) and new_password goes through the shared strength validator
    if not verify_password(payload.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid current password")

    current_user.hashed_password = get_password_hash(payload.new_password)
    db.commit()

    create_audit_log(
        db=db,
        action="PASSWORD_CHANGED",
        user_id=current_user.id,
        resource_type="user",
        resource_id=str(current_user.id),
        details={"username": current_user.username},
        ip_address=request.client.host if request.client else None
    )
    return {"message": "Password updated successfully"}

# ==================== User Management Routes (Admin) ====================

@app.get("/api/users", response_model=List[UserResponse])
async def list_users(
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    return db.query(User).all()

@app.post("/api/users", response_model=UserResponse)
async def create_user(
    request: Request,
    user_data: UserCreate,
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    existing = db.query(User).filter(
        (User.email == user_data.email) | (User.username == user_data.username)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="User with this email or username already exists")

    user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        is_admin=user_data.is_admin
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    create_audit_log(
        db=db,
        action="USER_CREATED",
        user_id=admin.id,
        resource_type="user",
        resource_id=str(user.id),
        details={"created_user": user.username, "is_admin": user.is_admin},
        ip_address=request.client.host if request.client else None
    )

    return user

@app.put("/api/users/{user_id}", response_model=UserResponse)
async def update_user(
    request: Request,
    user_id: int,
    user_data: UserUpdate,
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    changes = user_data.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(user, key, value)

    db.commit()
    db.refresh(user)

    create_audit_log(
        db=db,
        action="USER_UPDATED",
        user_id=admin.id,
        resource_type="user",
        resource_id=str(user.id),
        details={"updated_user": user.username, "changes": list(changes.keys())},
        ip_address=request.client.host if request.client else None
    )

    return user

@app.post("/api/users/{user_id}/reset-password")
async def admin_reset_password(
    request: Request,
    user_id: int,
    password_data: AdminPasswordReset,
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.hashed_password = get_password_hash(password_data.new_password)
    db.commit()

    create_audit_log(
        db=db,
        action="PASSWORD_RESET",
        user_id=admin.id,
        resource_type="user",
        resource_id=str(user.id),
        details={"reset_user": user.username},
        ip_address=request.client.host if request.client else None
    )

    return {"message": "Password reset successfully"}

@app.delete("/api/users/{user_id}")
async def delete_user(
    request: Request,
    user_id: int,
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    deleted_username = user.username

    # Nullify foreign key references before deleting
    db.query(AuditLog).filter(AuditLog.user_id == user_id).update({"user_id": None})
    db.query(CloudflareConfig).filter(CloudflareConfig.created_by == user_id).update({"created_by": None})

    db.delete(user)
    db.commit()

    create_audit_log(
        db=db,
        action="USER_DELETED",
        user_id=admin.id,
        resource_type="user",
        resource_id=str(user_id),
        details={"deleted_user": deleted_username},
        ip_address=request.client.host if request.client else None
    )

    return {"message": "User deleted successfully"}

# ==================== Cloudflare Config Routes ====================

@app.get("/api/configs", response_model=List[CloudflareConfigResponse])
async def list_configs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(CloudflareConfig).all()

@app.post("/api/configs", response_model=CloudflareConfigResponse)
async def create_config(
    request: Request,
    config_data: CloudflareConfigCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    api_token = config_data.api_token.strip()

    # The Global API Key (37 hex chars) only works with X-Auth-Email/X-Auth-Key
    # headers; this app authenticates with Bearer API Tokens exclusively.
    if re.fullmatch(r"[0-9a-f]{37}", api_token):
        raise HTTPException(
            status_code=400,
            detail="This looks like your Global API Key, which is not supported. "
                   "Create a scoped API Token instead (Cloudflare Dashboard → My Profile → API Tokens → Create Token)."
        )

    # Verify the token works. Error details go to the server log only, so the
    # response can't leak anything about the upstream call.
    client = CloudflareClient(api_token)
    try:
        result = await client.verify_token()
    except httpx.HTTPStatusError as e:
        print(f"Cloudflare token verification rejected: HTTP {e.response.status_code} {e.response.text[:300]}")
        raise HTTPException(
            status_code=400,
            detail="Cloudflare rejected this API token. Make sure you pasted a scoped API Token "
                   "(not the Global API Key) and that it is active and not IP-restricted."
        )
    except Exception as e:
        print(f"Cloudflare token verification failed: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=400,
            detail="Could not reach the Cloudflare API to verify the token. Check the backend's network access and try again."
        )

    token_status = (result.get("result") or {}).get("status")
    if token_status and token_status != "active":
        print(f"Cloudflare token verification returned status {token_status!r}")
        raise HTTPException(
            status_code=400,
            detail=f"Cloudflare reports this API token is {token_status}. Edit or recreate it in the Cloudflare dashboard."
        )

    # Encrypt the API token before storing in database
    config = CloudflareConfig(
        name=config_data.name,
        api_token=encrypt_token(api_token),  # ENCRYPTED
        account_id=config_data.account_id,
        created_by=current_user.id
    )
    db.add(config)
    db.commit()
    db.refresh(config)

    create_audit_log(
        db=db,
        action="CONFIG_CREATED",
        user_id=current_user.id,
        resource_type="config",
        resource_id=str(config.id),
        details={"config_name": config.name},
        ip_address=request.client.host if request.client else None
    )

    return config

@app.delete("/api/configs/{config_id}")
async def delete_config(
    request: Request,
    config_id: int,
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    config = db.query(CloudflareConfig).filter(CloudflareConfig.id == config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Config not found")

    config_name = config.name
    db.delete(config)
    db.commit()

    create_audit_log(
        db=db,
        action="CONFIG_DELETED",
        user_id=admin.id,
        resource_type="config",
        resource_id=str(config_id),
        details={"config_name": config_name},
        ip_address=request.client.host if request.client else None
    )

    return {"message": "Config deleted successfully"}

def run_sync_in_background(config_id: int, user_id: int, ip_address: str,
                           configs_processed: int = 0, configs_total: int = 1):
    """Background task to run sync without blocking API requests"""
    import asyncio
    from sqlalchemy.orm import sessionmaker

    # Create new database session for background task
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    # Resolved before the main try block so the failure path can reference it
    # even when the failure happens before/while loading the config
    config_name = None

    try:
        config = db.query(CloudflareConfig).filter(CloudflareConfig.id == config_id).first()
        if not config:
            return
        config_name = config.name

        _update_sync_progress(
            active=True,
            stage="starting",
            message="Starting sync...",
            zones_total=0,
            zones_processed=0,
            started_at=datetime.utcnow().isoformat(),
            completed_at=None,
            result=None,
            error=None,
            config_name=config_name,
            configs_processed=configs_processed,
            configs_total=configs_total,
        )

        # Run async sync in this thread's event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(sync_cloudflare_data(db, config))
        finally:
            loop.close()

        _update_sync_progress(
            active=False,
            stage="complete",
            message="Sync completed successfully",
            completed_at=datetime.utcnow().isoformat(),
            result="success",
            configs_processed=configs_processed + 1,
        )

        create_audit_log(
            db=db,
            action="SYNC_SUCCESS",
            user_id=user_id,
            resource_type="config",
            resource_id=str(config_id),
            details={"config_name": config_name, "status": "success"},
            ip_address=ip_address
        )
        invalidate_stats_cache()
        print(f"✅ Background sync completed successfully for config {config_id}")
    except Exception as e:
        db.rollback()

        _update_sync_progress(
            active=False,
            stage="failed",
            message=f"Sync failed: {str(e)[:100]}",
            completed_at=datetime.utcnow().isoformat(),
            result="failed",
            error=str(e)[:200],
            configs_processed=configs_processed + 1,
        )

        create_audit_log(
            db=db,
            action="SYNC_FAILED",
            user_id=user_id,
            resource_type="config",
            resource_id=str(config_id),
            details={"config_name": config_name, "status": "failed", "error": str(e)},
            ip_address=ip_address
        )
        print(f"❌ Background sync failed for config {config_id}: {e}")
    finally:
        db.close()

def run_sync_all_in_background(config_ids: List[int], user_id: int, ip_address: str):
    """Sync each config sequentially so the shared progress tracker stays coherent
    and the Cloudflare API isn't hit by several parallel syncs. A failed config
    is logged (SYNC_FAILED) and the loop continues with the next one."""
    total = len(config_ids)
    for idx, config_id in enumerate(config_ids):
        run_sync_in_background(config_id, user_id, ip_address,
                               configs_processed=idx, configs_total=total)

@app.post("/api/configs/{config_id}/sync")
async def sync_config(
    request: Request,
    config_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    config = db.query(CloudflareConfig).filter(CloudflareConfig.id == config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Config not found")

    if _get_sync_progress()["active"]:
        raise HTTPException(status_code=409, detail="A sync is already running")

    ip_address = request.client.host if request.client else None

    # Queue sync to run in background instead of blocking the request
    background_tasks.add_task(run_sync_in_background, config_id, current_user.id, ip_address)

    return {"message": "Sync started in background. This may take a few minutes to complete."}

@app.get("/api/sync/status")
async def get_sync_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get the status of the last sync operation"""
    # Get the most recent sync audit log
    last_sync = db.query(AuditLog).filter(
        AuditLog.action.in_(["SYNC_SUCCESS", "SYNC_FAILED"])
    ).order_by(AuditLog.timestamp.desc()).first()

    if not last_sync:
        return {
            "last_sync": None,
            "status": "never",
            "message": "No sync has been performed yet",
            "scheduler": _get_scheduler_state()
        }

    return {
        "last_sync": last_sync.timestamp.isoformat(),
        "status": "success" if last_sync.action == "SYNC_SUCCESS" else "failed",
        "details": last_sync.details,
        "scheduler": _get_scheduler_state()
    }

@app.get("/api/sync/progress")
async def get_sync_progress(
    current_user: User = Depends(get_current_user),
):
    """Get real-time sync progress for the sidebar status bar"""
    return _get_sync_progress()

@app.post("/api/sync-all")
async def sync_all_configs(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if _get_sync_progress()["active"]:
        raise HTTPException(status_code=409, detail="A sync is already running")

    ip_address = request.client.host if request.client else None
    configs = db.query(CloudflareConfig).filter(CloudflareConfig.is_active == True).all()

    # One background task that walks the configs sequentially - parallel tasks
    # would clobber the shared progress tracker and hammer the Cloudflare API
    config_ids = [config.id for config in configs]
    background_tasks.add_task(run_sync_all_in_background, config_ids, current_user.id, ip_address)

    return {"message": f"Sync started in background for {len(configs)} configurations. This may take a few minutes to complete."}

# ==================== Zone Routes ====================

@app.get("/api/zones", response_model=List[ZoneResponse])
def list_zones(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Fetch all zones with their DNS record counts.
    Optimized to perform aggregation in a single query to avoid N+1 performance issues.
    """
    from sqlalchemy import func, case

    zones = db.query(Zone).all()

    # Optimized fetching of counts to avoid N+1 query problem
    dns_counts = db.query(
        DNSRecord.zone_id,
        func.count(DNSRecord.id).label('total_count'),
        func.sum(case((DNSRecord.proxied == True, 1), else_=0)).label('proxied_count')
    ).group_by(DNSRecord.zone_id).all()

    # Create a map for fast lookup
    counts_map = {
        row.zone_id: {'total': row.total_count, 'proxied': row.proxied_count or 0}
        for row in dns_counts
    }

    result = []
    for zone in zones:
        counts = counts_map.get(zone.zone_id, {'total': 0, 'proxied': 0})
        zone_dict = {
            "id": zone.id,
            "zone_id": zone.zone_id,
            "name": zone.name,
            "status": zone.status,
            "paused": zone.paused,
            "type": zone.type,
            "development_mode": zone.development_mode,
            "name_servers": zone.name_servers,
            "created_on": zone.created_on,
            "modified_on": zone.modified_on,
            "account_name": zone.account_name,
            "last_synced": zone.last_synced,
            "dns_records_count": counts['total'],
            "proxied_records_count": counts['proxied']
        }
        result.append(ZoneResponse(**zone_dict))
    return result

@app.get("/api/zones/{zone_id}")
async def get_zone(
    zone_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    zone = db.query(Zone).filter(Zone.zone_id == zone_id).first()
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")

    dns_records = db.query(DNSRecord).filter(DNSRecord.zone_id == zone_id).all()
    security_settings = db.query(SecuritySetting).filter(SecuritySetting.zone_id == zone_id).all()
    metrics = db.query(TrafficMetric).filter(
        TrafficMetric.zone_id == zone_id
    ).order_by(TrafficMetric.timestamp.desc()).limit(24).all()

    return {
        "zone": zone,
        "dns_records": dns_records,
        "security_settings": security_settings,
        "metrics": metrics
    }

# ==================== DNS Records Routes ====================

@app.get("/api/dns-records", response_model=PaginatedDNSRecordResponse)
def list_dns_records(
    zone_id: Optional[str] = None,
    record_type: Optional[str] = None,
    proxied: Optional[bool] = None,
    q: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    sort_by: str = Query("name"),
    sort_order: str = Query("asc"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Paginated, filterable, sortable DNS records with the zone name joined
    in - filtering and sorting happen in the database so the full dataset
    never has to travel to the browser."""
    from sqlalchemy import or_, func

    query = db.query(DNSRecord, Zone.name.label("zone_name")).outerjoin(
        Zone, DNSRecord.zone_id == Zone.zone_id
    )

    if zone_id:
        query = query.filter(DNSRecord.zone_id == zone_id)
    if record_type:
        query = query.filter(DNSRecord.type == record_type)
    if proxied is not None:
        query = query.filter(DNSRecord.proxied == proxied)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(DNSRecord.name.ilike(like), DNSRecord.content.ilike(like)))

    # Whitelisted sort columns; lower() keeps text ordering case-insensitive
    sort_map = {
        "name": func.lower(DNSRecord.name),
        "type": DNSRecord.type,
        "content": func.lower(DNSRecord.content),
        "ttl": DNSRecord.ttl,
        "proxied": DNSRecord.proxied,
        "zone_name": func.lower(Zone.name),
        "modified_on": DNSRecord.modified_on,
    }
    sort_column = sort_map.get(sort_by, sort_map["name"])
    query = query.order_by(sort_column.desc() if sort_order == "desc" else sort_column.asc(),
                           DNSRecord.id.asc())

    total = query.count()
    rows = query.offset((page - 1) * page_size).limit(page_size).all()

    data = []
    for record, zone_name in rows:
        item = DNSRecordWithZoneResponse.model_validate(record)
        item.zone_name = zone_name
        data.append(item)

    return {"total": total, "page": page, "page_size": page_size, "data": data}

@app.get("/api/dns-records/types")
async def get_dns_record_types(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from sqlalchemy import func
    results = db.query(
        DNSRecord.type,
        func.count(DNSRecord.id).label("count")
    ).group_by(DNSRecord.type).all()

    return {r.type: r.count for r in results}

# ==================== Security Settings Routes ====================

@app.get("/api/security-settings", response_model=List[SecuritySettingResponse])
async def list_security_settings(
    zone_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(SecuritySetting)
    if zone_id:
        query = query.filter(SecuritySetting.zone_id == zone_id)
    return query.all()

@app.get("/api/security-settings/summary")
async def get_security_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from sqlalchemy import func

    zones = db.query(Zone).all()

    # Fetch all security settings in one query to avoid N+1 problem
    all_settings = db.query(SecuritySetting).all()

    # Group settings by zone_id in Python
    settings_by_zone = {}
    for setting in all_settings:
        if setting.zone_id not in settings_by_zone:
            settings_by_zone[setting.zone_id] = []
        settings_by_zone[setting.zone_id].append(setting)

    summary = {}

    for zone in zones:
        settings = settings_by_zone.get(zone.zone_id, [])
        enabled_count = sum(1 for s in settings if s.enabled)
        total_count = len(settings)

        summary[zone.zone_id] = {
            "zone_name": zone.name,
            "enabled_features": enabled_count,
            "total_features": total_count,
            "settings": {s.setting_name: {"value": s.setting_value, "enabled": s.enabled} for s in settings}
        }

    return summary

# ==================== Metrics Routes ====================

def _list_metrics_query(zone_id: Optional[str], hours: int, page: int, page_size: int) -> Dict[str, Any]:
    """
    Synchronous function to query metrics with pagination.
    This is run in a separate thread to avoid blocking the asyncio event loop.
    """
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        query = db.query(TrafficMetric).filter(TrafficMetric.timestamp >= cutoff)

        if zone_id:
            query = query.filter(TrafficMetric.zone_id == zone_id)

        total = query.count()

        data = query.order_by(TrafficMetric.timestamp.desc(), TrafficMetric.id.desc())\
                    .offset((page - 1) * page_size)\
                    .limit(page_size)\
                    .all()

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "data": data
        }
    finally:
        db.close()


@app.get("/api/metrics", response_model=PaginatedTrafficMetricResponse)
async def list_metrics(
    zone_id: Optional[str] = None,
    hours: int = Query(24, ge=1, le=2160),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    current_user: User = Depends(get_current_user)
):
    result = await asyncio.to_thread(
        _list_metrics_query,
        zone_id=zone_id,
        hours=hours,
        page=page,
        page_size=page_size
    )
    return result

@app.get("/api/metrics/aggregate")
async def get_aggregate_metrics(
    zone_id: Optional[str] = None,
    hours: int = Query(24, ge=1, le=2160),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from sqlalchemy import func

    cutoff = datetime.utcnow() - timedelta(hours=hours)

    sums_query = db.query(
        func.sum(TrafficMetric.requests_all).label("total_requests"),
        func.sum(TrafficMetric.requests_cached).label("total_cached"),
        func.sum(TrafficMetric.requests_uncached).label("total_uncached"),
        func.sum(TrafficMetric.bandwidth_all).label("total_bandwidth"),
        func.sum(TrafficMetric.bandwidth_cached).label("bandwidth_cached"),
        func.sum(TrafficMetric.threats_all).label("total_threats"),
        func.sum(TrafficMetric.pageviews_all).label("total_pageviews")
    ).filter(TrafficMetric.timestamp >= cutoff)
    if zone_id:
        sums_query = sums_query.filter(TrafficMetric.zone_id == zone_id)
    result = sums_query.first()

    # Uniques are per-hour distinct counts and cannot be summed across hours;
    # approximate with each zone's peak hourly value, summed across zones.
    uniques_query = db.query(
        func.max(TrafficMetric.uniques_all).label("peak_uniques")
    ).filter(TrafficMetric.timestamp >= cutoff)
    if zone_id:
        uniques_query = uniques_query.filter(TrafficMetric.zone_id == zone_id)
    uniques_per_zone = uniques_query.group_by(TrafficMetric.zone_id).subquery()
    total_uniques = db.query(func.sum(uniques_per_zone.c.peak_uniques)).scalar() or 0

    total_requests = result.total_requests or 0
    total_cached = result.total_cached or 0

    return {
        "total_requests": total_requests,
        "total_cached": total_cached,
        "total_uncached": result.total_uncached or 0,
        "total_bandwidth": result.total_bandwidth or 0,
        "bandwidth_cached": result.bandwidth_cached or 0,
        "total_threats": result.total_threats or 0,
        "total_pageviews": result.total_pageviews or 0,
        "total_uniques": total_uniques,
        "uniques_approximate": True,
        "cache_ratio": (total_cached / total_requests * 100) if total_requests > 0 else 0
    }

@app.get("/api/metrics/breakdown")
async def get_metrics_breakdown(
    zone_id: Optional[str] = None,
    hours: int = Query(24, ge=1, le=2160),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Merge the per-bucket JSON breakdowns (status codes, content types,
    countries) across the window. JSON aggregation is DB-specific, so the
    merge happens in Python; the row count is bounded (one per zone-hour)."""
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    query = db.query(
        TrafficMetric.http_status,
        TrafficMetric.content_type,
        TrafficMetric.country
    ).filter(TrafficMetric.timestamp >= cutoff)
    if zone_id:
        query = query.filter(TrafficMetric.zone_id == zone_id)

    http_status: Dict[str, int] = {}
    content_type: Dict[str, int] = {}
    country: Dict[str, int] = {}
    for row_status, row_content, row_country in query.all():
        for target, source in ((http_status, row_status), (content_type, row_content), (country, row_country)):
            if source:
                for key, value in source.items():
                    target[key] = target.get(key, 0) + (value or 0)

    return {
        "http_status": http_status,
        "content_type": content_type,
        "country": country,
    }

# ==================== Dashboard Routes ====================

# Cache for dashboard stats
STATS_CACHE = {
    "data": None,
    "timestamp": None
}
STATS_CACHE_TTL = 300  # 5 minutes
STATS_CACHE_LOCK = asyncio.Lock()

def invalidate_stats_cache():
    """Drop cached dashboard stats so fresh data shows right after a sync
    or reachability run instead of after the TTL expires."""
    STATS_CACHE["data"] = None
    STATS_CACHE["timestamp"] = None

@app.get("/api/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from sqlalchemy import func, case

    # Check cache first without lock for performance
    if STATS_CACHE["timestamp"] and \
       (datetime.utcnow() - STATS_CACHE["timestamp"]).total_seconds() < STATS_CACHE_TTL:
        return STATS_CACHE["data"]

    # Use a lock to prevent cache stampede
    async with STATS_CACHE_LOCK:
        # Double-check cache inside the lock in case another request populated it while waiting
        if STATS_CACHE["timestamp"] and \
           (datetime.utcnow() - STATS_CACHE["timestamp"]).total_seconds() < STATS_CACHE_TTL:
            return STATS_CACHE["data"]

        # Optimized: Combine Zone counts into a single query
        zone_stats = db.query(
            func.count(Zone.id),
            func.sum(case((Zone.status == "active", 1), else_=0))
        ).first()
        total_zones = zone_stats[0] or 0
        active_zones = zone_stats[1] or 0

        # Optimized: Combine DNS Record counts into a single query
        dns_stats = db.query(
            func.count(DNSRecord.id),
            func.sum(case((DNSRecord.proxied == True, 1), else_=0))
        ).first()
        total_dns_records = dns_stats[0] or 0
        proxied_records = dns_stats[1] or 0

        cutoff = datetime.utcnow() - timedelta(hours=24)
        metrics_24h = db.query(
            func.sum(TrafficMetric.requests_all).label("requests"),
            func.sum(TrafficMetric.requests_cached).label("cached"),
            func.sum(TrafficMetric.bandwidth_all).label("bandwidth"),
            func.sum(TrafficMetric.threats_all).label("threats")
        ).filter(TrafficMetric.timestamp >= cutoff).first()

        total_requests = metrics_24h.requests or 0
        total_cached = metrics_24h.cached or 0

        security_enabled = db.query(SecuritySetting).filter(SecuritySetting.enabled == True).count()

        stats = DashboardStats(
            total_zones=total_zones,
            active_zones=active_zones,
            total_dns_records=total_dns_records,
            proxied_records=proxied_records,
            total_requests_24h=total_requests,
            total_bandwidth_24h=metrics_24h.bandwidth or 0,
            total_threats_24h=metrics_24h.threats or 0,
            cache_hit_ratio=(total_cached / total_requests * 100) if total_requests > 0 else 0,
            security_features_enabled=security_enabled
        )

        # Update cache
        STATS_CACHE["data"] = stats
        STATS_CACHE["timestamp"] = datetime.utcnow()

        return stats

# ==================== Audit Log Routes ====================

@app.get("/api/audit-logs")
async def list_audit_logs(
    limit: int = 50,
    offset: int = 0,
    action: Optional[str] = None,
    user_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    q: Optional[str] = None,
    sort_by: Optional[str] = "timestamp",
    sort_order: Optional[str] = "desc",
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """List audit logs with filtering and pagination"""
    from sqlalchemy import cast, or_, String as SAString

    query = db.query(AuditLog)

    if q:
        # Free-text search across the whole dataset (the frontend previously
        # filtered only the page it had loaded)
        like = f"%{q}%"
        matching_user_ids = [u.id for u in db.query(User).filter(User.username.ilike(like)).all()]
        conditions = [
            AuditLog.action.ilike(like),
            AuditLog.resource_type.ilike(like),
            AuditLog.resource_id.ilike(like),
            AuditLog.ip_address.ilike(like),
            cast(AuditLog.details, SAString).ilike(like),
        ]
        if matching_user_ids:
            conditions.append(AuditLog.user_id.in_(matching_user_ids))
        query = query.filter(or_(*conditions))

    if action:
        query = query.filter(AuditLog.action == action)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if start_date:
        try:
            start = datetime.fromisoformat(start_date)
            query = query.filter(AuditLog.timestamp >= start)
        except ValueError:
            pass
    if end_date:
        try:
            end = datetime.fromisoformat(end_date)
            # A bare date means "through the end of that day"; a full
            # datetime is used as-is (exclusive upper bound)
            if len(end_date) == 10:
                end += timedelta(days=1)
            query = query.filter(AuditLog.timestamp < end)
        except ValueError:
            pass

    # Sorting
    sort_column = getattr(AuditLog, sort_by, AuditLog.timestamp)
    if sort_order == "asc":
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    total = query.count()
    logs = query.offset(offset).limit(limit).all()

    # Get usernames for the logs
    user_ids = list(set(log.user_id for log in logs if log.user_id))
    users = {u.id: u.username for u in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}

    return {
        "total": total,
        "logs": [
            {
                "id": log.id,
                "user_id": log.user_id,
                "username": users.get(log.user_id, "System"),
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "details": log.details,
                "ip_address": log.ip_address,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None
            }
            for log in logs
        ]
    }

@app.get("/api/audit-logs/actions")
async def get_audit_log_actions(
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Get list of unique action types for filtering"""
    from sqlalchemy import func
    results = db.query(AuditLog.action, func.count(AuditLog.id).label("count")).group_by(AuditLog.action).all()
    return {r.action: r.count for r in results}

# ==================== Reachability Routes ====================

@app.get("/api/reachability/progress")
async def get_reachability_progress(
    current_user: User = Depends(get_current_user),
):
    """Get real-time reachability check progress for the sidebar status bar"""
    return _get_reachability_progress()

def run_reachability_in_background(zone_id: Optional[str], user_id: int, ip_address: Optional[str]):
    """Run reachability checks (all zones, or one zone) in a background task
    with its own DB session and event loop, mirroring run_sync_in_background."""
    from sqlalchemy.orm import sessionmaker

    SessionLocal_bg = sessionmaker(bind=engine)
    db = SessionLocal_bg()
    zone_name = None

    try:
        # Wildcard records (*.example.com) are not directly resolvable
        # hostnames; probing them always fails DNS and pollutes the results
        # with phantom errors, so they are excluded.
        query = db.query(DNSRecord).filter(
            DNSRecord.type.in_(["A", "AAAA", "CNAME"]),
            ~DNSRecord.name.startswith("*"),
        )
        if zone_id:
            zone = db.query(Zone).filter(Zone.zone_id == zone_id).first()
            zone_name = zone.name if zone else zone_id
            query = query.filter(DNSRecord.zone_id == zone_id)
        all_records = query.all()
        total_records = len(all_records)
        scope_label = f"records in {zone_name}" if zone_id else "records"

        _update_reachability_progress(
            active=True,
            stage="starting",
            message=f"Starting checks for {total_records} {scope_label}...",
            records_total=total_records,
            records_checked=0,
            started_at=datetime.utcnow().isoformat(),
            completed_at=None,
            result=None,
            error=None,
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            total_checked = 0
            BATCH_SIZE = 20

            async def check_batch(records):
                return await asyncio.gather(*[check_hostname_reachability(r.name) for r in records])

            for i in range(0, total_records, BATCH_SIZE):
                batch = all_records[i:i + BATCH_SIZE]
                batch_results = loop.run_until_complete(check_batch(batch))

                reachability_checks = [
                    ReachabilityCheck(
                        dns_record_id=rec.record_id,
                        zone_id=rec.zone_id,
                        hostname=rec.name,
                        **result
                    )
                    for rec, result in zip(batch, batch_results)
                ]

                # Commit per batch to free memory and persist partial progress
                db.add_all(reachability_checks)
                db.commit()
                total_checked += len(batch)

                _update_reachability_progress(
                    stage="checking",
                    message=f"Checked {total_checked} of {total_records} {scope_label}...",
                    records_checked=total_checked,
                )
        finally:
            loop.close()

        _update_reachability_progress(
            active=False,
            stage="complete",
            message=f"Checked {total_checked} {scope_label}",
            records_checked=total_checked,
            completed_at=datetime.utcnow().isoformat(),
            result="success",
        )

        # Retention: response-time history is kept for trend charts, but not
        # forever - prune rows past the cutoff now that this run is persisted
        if REACHABILITY_RETENTION_DAYS > 0:
            retention_cutoff = datetime.utcnow() - timedelta(days=REACHABILITY_RETENTION_DAYS)
            pruned = db.query(ReachabilityCheck).filter(
                ReachabilityCheck.checked_at < retention_cutoff
            ).delete(synchronize_session=False)
            db.commit()
            if pruned:
                print(f"Pruned {pruned} reachability checks older than {REACHABILITY_RETENTION_DAYS} days")

        details = {"records_checked": total_checked, "scope": "zone" if zone_id else "all"}
        if zone_name:
            details["zone_name"] = zone_name
        create_audit_log(
            db=db,
            action="REACHABILITY_CHECK_SUCCESS",
            user_id=user_id,
            resource_type="reachability",
            resource_id=zone_id,
            details=details,
            ip_address=ip_address
        )
    except Exception as e:
        db.rollback()

        _update_reachability_progress(
            active=False,
            stage="failed",
            message=f"Reachability check failed: {str(e)[:100]}",
            completed_at=datetime.utcnow().isoformat(),
            result="failed",
            error=str(e)[:200],
        )

        details = {"scope": "zone" if zone_id else "all", "error": str(e)[:200]}
        if zone_name:
            details["zone_name"] = zone_name
        create_audit_log(
            db=db,
            action="REACHABILITY_CHECK_FAILED",
            user_id=user_id,
            resource_type="reachability",
            resource_id=zone_id,
            details=details,
            ip_address=ip_address
        )
        print(f"❌ Background reachability check failed: {e}")
    finally:
        db.close()

@app.post("/api/reachability/check-all")
async def run_reachability_checks(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
):
    """Queue reachability checks for all A, AAAA, CNAME records"""
    if _get_reachability_progress()["active"]:
        raise HTTPException(status_code=409, detail="A reachability check is already running")

    ip_address = request.client.host if request.client else None
    background_tasks.add_task(run_reachability_in_background, None, current_user.id, ip_address)

    return {"message": "Reachability check started in background. Track progress via /api/reachability/progress."}

@app.post("/api/reachability/check-zone/{zone_id}")
async def run_zone_reachability_check(
    zone_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Queue reachability checks for a specific zone"""
    zone = db.query(Zone).filter(Zone.zone_id == zone_id).first()
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")

    if _get_reachability_progress()["active"]:
        raise HTTPException(status_code=409, detail="A reachability check is already running")

    ip_address = request.client.host if request.client else None
    background_tasks.add_task(run_reachability_in_background, zone_id, current_user.id, ip_address)

    return {"message": f"Reachability check for zone {zone.name} started in background."}

@app.get("/api/reachability", response_model=PaginatedReachabilityResponse)
async def list_reachability_checks(
    zone_id: Optional[str] = None,
    hours: int = Query(24, ge=1, le=2160),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get recent reachability check results"""
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    query = db.query(ReachabilityCheck).filter(ReachabilityCheck.checked_at >= cutoff)

    if zone_id:
        query = query.filter(ReachabilityCheck.zone_id == zone_id)

    total = query.count()

    checks = query.order_by(ReachabilityCheck.checked_at.desc())\
                  .offset((page - 1) * page_size)\
                  .limit(page_size)\
                  .all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "data": checks
    }

@app.get("/api/reachability/latest")
async def get_latest_reachability(
    zone_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get the most recent check for each DNS record"""
    from sqlalchemy import func

    subquery = db.query(
        ReachabilityCheck.dns_record_id,
        func.max(ReachabilityCheck.checked_at).label("max_checked_at")
    ).group_by(ReachabilityCheck.dns_record_id).subquery()

    query = db.query(ReachabilityCheck).join(
        subquery,
        (ReachabilityCheck.dns_record_id == subquery.c.dns_record_id) &
        (ReachabilityCheck.checked_at == subquery.c.max_checked_at)
    )

    if zone_id:
        query = query.filter(ReachabilityCheck.zone_id == zone_id)

    results = query.all()

    # Get zone names for each result
    zone_map = {z.zone_id: z.name for z in db.query(Zone).all()}

    return [
        {
            "id": r.id,
            "dns_record_id": r.dns_record_id,
            "zone_id": r.zone_id,
            "zone_name": zone_map.get(r.zone_id, "Unknown"),
            "hostname": r.hostname,
            "resolved_ip": r.resolved_ip,
            "http_status_code": r.http_status_code,
            "https_status_code": r.https_status_code,
            "http_response_time_ms": r.http_response_time_ms,
            "https_response_time_ms": r.https_response_time_ms,
            "http_error": r.http_error,
            "https_error": r.https_error,
            "http_redirect_location": r.http_redirect_location,
            "https_redirect_location": r.https_redirect_location,
            "checked_at": r.checked_at
        }
        for r in results
    ]

@app.get("/api/reachability/history")
async def get_reachability_history(
    dns_record_id: str,
    hours: int = Query(168, ge=1, le=2160),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Check history for one DNS record, oldest first, for trend charts"""
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    checks = db.query(ReachabilityCheck).filter(
        ReachabilityCheck.dns_record_id == dns_record_id,
        ReachabilityCheck.checked_at >= cutoff
    ).order_by(ReachabilityCheck.checked_at.asc()).all()

    return [
        {
            "id": c.id,
            "checked_at": c.checked_at,
            "resolved_ip": c.resolved_ip,
            "http_status_code": c.http_status_code,
            "https_status_code": c.https_status_code,
            "http_response_time_ms": c.http_response_time_ms,
            "https_response_time_ms": c.https_response_time_ms,
            "http_error": c.http_error,
            "https_error": c.https_error,
        }
        for c in checks
    ]

# ==================== Export/Reports Routes ====================

_sanitize_cell = exposure_workbook.sanitize_cell

def _fill_sheet(ws, headers: List[str], rows: List[List[Any]]):
    """Styled header row + sanitized, banded data rows with filters and print setup"""
    exposure_workbook.write_table(ws, headers, rows)
    exposure_workbook.finish_sheet(ws, tab_color=exposure_workbook.BRAND_BLUE)

def _tabular_response(headers: List[str], rows: List[List[Any]], filename_base: str, format: str) -> StreamingResponse:
    """Serialize a header row + data rows as CSV (default) or XLSX"""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    if format == "xlsx":
        from openpyxl import Workbook

        wb = Workbook()
        ws = wb.active
        ws.title = "Report"
        _fill_sheet(ws, headers, rows)

        buf = io.BytesIO()
        wb.save(buf)
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename_base}_{timestamp}.xlsx"}
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    for row in rows:
        writer.writerow([_sanitize_cell(v) for v in row])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename_base}_{timestamp}.csv"}
    )

ExportFormat = Query("csv", pattern=r"^(csv|xlsx)$")

@app.get("/api/export/full")
async def export_full_report(
    format: str = ExportFormat,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Export comprehensive report with all zones, DNS records, reachability, and security"""
    from sqlalchemy import func

    # Get all zones
    zones = db.query(Zone).all()
    zone_map = {z.zone_id: z for z in zones}

    # Get all DNS records
    dns_records = db.query(DNSRecord).all()

    # Get latest reachability for each DNS record
    reachability_subquery = db.query(
        ReachabilityCheck.dns_record_id,
        func.max(ReachabilityCheck.checked_at).label("max_checked_at")
    ).group_by(ReachabilityCheck.dns_record_id).subquery()

    reachability_results = db.query(ReachabilityCheck).join(
        reachability_subquery,
        (ReachabilityCheck.dns_record_id == reachability_subquery.c.dns_record_id) &
        (ReachabilityCheck.checked_at == reachability_subquery.c.max_checked_at)
    ).all()
    reachability_map = {r.dns_record_id: r for r in reachability_results}

    # Get security settings per zone
    security_settings = db.query(SecuritySetting).all()
    security_map = {}
    for s in security_settings:
        if s.zone_id not in security_map:
            security_map[s.zone_id] = {}
        security_map[s.zone_id][s.setting_name] = s.enabled

    headers = [
        "Zone Name", "Zone ID", "Zone Status", "Zone Type", "Account Name",
        "DNS Record Name", "DNS Record Type", "DNS Content/IP", "Proxied", "TTL",
        "Resolved IP", "HTTP Status", "HTTP Response Time (ms)", "HTTP Error",
        "HTTPS Status", "HTTPS Response Time (ms)", "HTTPS Error",
        "Reachability Checked At",
        "SSL", "Always HTTPS", "Min TLS", "TLS 1.3", "WAF", "Security Level",
        "Browser Check", "Email Obfuscation", "Hotlink Protection"
    ]

    def build_row(zone, record, reach, sec):
        return [
            zone.name if zone else "",
            zone.zone_id if zone else (record.zone_id if record else ""),
            zone.status if zone else "",
            zone.type if zone else "",
            zone.account_name if zone else "",
            record.name if record else "",
            record.type if record else "",
            record.content if record else "",
            ("Yes" if record.proxied else "No") if record else "",
            ("Auto" if record.ttl == 1 else record.ttl) if record else "",
            reach.resolved_ip if reach else "",
            reach.http_status_code if reach else "",
            reach.http_response_time_ms if reach else "",
            reach.http_error if reach else "",
            reach.https_status_code if reach else "",
            reach.https_response_time_ms if reach else "",
            reach.https_error if reach else "",
            reach.checked_at.isoformat() if reach and reach.checked_at else "",
            "Yes" if sec.get("ssl") else "No",
            "Yes" if sec.get("always_use_https") else "No",
            sec.get("min_tls_version", ""),
            "Yes" if sec.get("tls_1_3") else "No",
            "Yes" if sec.get("waf") else "No",
            sec.get("security_level", ""),
            "Yes" if sec.get("browser_check") else "No",
            "Yes" if sec.get("email_obfuscation") else "No",
            "Yes" if sec.get("hotlink_protection") else "No"
        ]

    rows = []
    zones_with_records = set()
    for record in dns_records:
        zones_with_records.add(record.zone_id)
        rows.append(build_row(
            zone_map.get(record.zone_id), record,
            reachability_map.get(record.record_id),
            security_map.get(record.zone_id, {})
        ))
    # Zones with no DNS records still belong in a "full" report
    for zone in zones:
        if zone.zone_id not in zones_with_records:
            rows.append(build_row(zone, None, None, security_map.get(zone.zone_id, {})))

    return _tabular_response(headers, rows, "cloudflare_full_report", format)

@app.get("/api/export/zones")
async def export_zones(
    format: str = ExportFormat,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Export all zones"""
    zones = db.query(Zone).all()

    headers = [
        "Zone Name", "Zone ID", "Status", "Type", "Paused", "Development Mode",
        "Account ID", "Account Name", "Name Servers",
        "Created On", "Modified On", "Activated On", "Last Synced"
    ]
    rows = [
        [
            z.name, z.zone_id, z.status, z.type,
            "Yes" if z.paused else "No",
            z.development_mode,
            z.account_id, z.account_name,
            ", ".join(z.name_servers) if z.name_servers else "",
            z.created_on.isoformat() if z.created_on else "",
            z.modified_on.isoformat() if z.modified_on else "",
            z.activated_on.isoformat() if z.activated_on else "",
            z.last_synced.isoformat() if z.last_synced else ""
        ]
        for z in zones
    ]
    return _tabular_response(headers, rows, "cloudflare_zones", format)

@app.get("/api/export/dns-records")
async def export_dns_records(
    format: str = ExportFormat,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Export all DNS records"""
    records = db.query(DNSRecord).all()
    zones = db.query(Zone).all()
    zone_map = {z.zone_id: z.name for z in zones}

    headers = [
        "Zone Name", "Zone ID", "Record ID", "Name", "Type", "Content",
        "Proxied", "Proxiable", "TTL", "Priority", "Created On", "Modified On"
    ]
    rows = [
        [
            zone_map.get(r.zone_id, ""),
            r.zone_id, r.record_id, r.name, r.type, r.content,
            "Yes" if r.proxied else "No",
            "Yes" if r.proxiable else "No",
            "Auto" if r.ttl == 1 else r.ttl,
            r.priority or "",
            r.created_on.isoformat() if r.created_on else "",
            r.modified_on.isoformat() if r.modified_on else ""
        ]
        for r in records
    ]
    return _tabular_response(headers, rows, "cloudflare_dns_records", format)

@app.get("/api/export/reachability")
async def export_reachability(
    format: str = ExportFormat,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Export reachability data"""
    from sqlalchemy import func

    # Get latest reachability for each DNS record
    subquery = db.query(
        ReachabilityCheck.dns_record_id,
        func.max(ReachabilityCheck.checked_at).label("max_checked_at")
    ).group_by(ReachabilityCheck.dns_record_id).subquery()

    results = db.query(ReachabilityCheck).join(
        subquery,
        (ReachabilityCheck.dns_record_id == subquery.c.dns_record_id) &
        (ReachabilityCheck.checked_at == subquery.c.max_checked_at)
    ).all()

    zones = db.query(Zone).all()
    zone_map = {z.zone_id: z.name for z in zones}

    headers = [
        "Zone Name", "Zone ID", "Hostname", "Resolved IP", "DNS Record ID",
        "HTTP Status", "HTTP Response Time (ms)", "HTTP Error", "HTTP Redirects To",
        "HTTPS Status", "HTTPS Response Time (ms)", "HTTPS Error", "HTTPS Redirects To",
        "Checked At"
    ]
    rows = [
        [
            zone_map.get(r.zone_id, ""),
            r.zone_id, r.hostname, r.resolved_ip or "", r.dns_record_id,
            r.http_status_code or "",
            r.http_response_time_ms or "",
            r.http_error or "",
            r.http_redirect_location or "",
            r.https_status_code or "",
            r.https_response_time_ms or "",
            r.https_error or "",
            r.https_redirect_location or "",
            r.checked_at.isoformat() if r.checked_at else ""
        ]
        for r in results
    ]
    return _tabular_response(headers, rows, "cloudflare_reachability", format)

@app.get("/api/export/security")
async def export_security_settings(
    format: str = ExportFormat,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Export security settings"""
    settings = db.query(SecuritySetting).all()
    zones = db.query(Zone).all()
    zone_map = {z.zone_id: z.name for z in zones}

    headers = ["Zone Name", "Zone ID", "Setting Name", "Setting Value", "Enabled", "Last Synced"]
    rows = [
        [
            zone_map.get(s.zone_id, ""),
            s.zone_id,
            s.setting_name,
            json.dumps(s.setting_value) if s.setting_value else "",
            "Yes" if s.enabled else "No",
            s.last_synced.isoformat() if s.last_synced else ""
        ]
        for s in settings
    ]
    return _tabular_response(headers, rows, "cloudflare_security", format)

@app.get("/api/export/traffic")
async def export_traffic_metrics(
    hours: int = Query(24, ge=1, le=2160),
    format: str = ExportFormat,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Export traffic metrics"""
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    metrics = db.query(TrafficMetric).filter(TrafficMetric.timestamp >= cutoff).all()
    zones = db.query(Zone).all()
    zone_map = {z.zone_id: z.name for z in zones}

    headers = [
        "Zone Name", "Zone ID", "Timestamp",
        "Requests (All)", "Requests (Cached)", "Requests (Uncached)",
        "Bandwidth (All)", "Bandwidth (Cached)", "Bandwidth (Uncached)",
        "Threats", "Pageviews", "Unique Visitors",
        "SSL Encrypted", "SSL Unencrypted"
    ]
    rows = [
        [
            zone_map.get(m.zone_id, ""),
            m.zone_id,
            m.timestamp.isoformat() if m.timestamp else "",
            m.requests_all, m.requests_cached, m.requests_uncached,
            m.bandwidth_all, m.bandwidth_cached, m.bandwidth_uncached,
            m.threats_all, m.pageviews_all, m.uniques_all,
            m.ssl_encrypted, m.ssl_unencrypted
        ]
        for m in metrics
    ]
    return _tabular_response(headers, rows, "cloudflare_traffic", format)

def _format_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} EB"

@app.get("/api/export/summary")
async def export_summary_pdf(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """One-page PDF summary: zones, traffic, security coverage, reachability"""
    from sqlalchemy import func, case
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    zones = db.query(Zone).order_by(Zone.name).all()

    dns_counts = {
        row.zone_id: (row.total, row.proxied or 0)
        for row in db.query(
            DNSRecord.zone_id,
            func.count(DNSRecord.id).label("total"),
            func.sum(case((DNSRecord.proxied == True, 1), else_=0)).label("proxied")
        ).group_by(DNSRecord.zone_id).all()
    }
    sec_counts = {
        row.zone_id: (row.enabled or 0, row.total)
        for row in db.query(
            SecuritySetting.zone_id,
            func.sum(case((SecuritySetting.enabled == True, 1), else_=0)).label("enabled"),
            func.count(SecuritySetting.id).label("total")
        ).group_by(SecuritySetting.zone_id).all()
    }

    cutoff = datetime.utcnow() - timedelta(hours=24)
    traffic = db.query(
        func.sum(TrafficMetric.requests_all),
        func.sum(TrafficMetric.requests_cached),
        func.sum(TrafficMetric.bandwidth_all),
        func.sum(TrafficMetric.threats_all)
    ).filter(TrafficMetric.timestamp >= cutoff).first()
    total_requests = traffic[0] or 0
    total_cached = traffic[1] or 0

    # Latest reachability status per record
    subquery = db.query(
        ReachabilityCheck.dns_record_id,
        func.max(ReachabilityCheck.checked_at).label("max_checked_at")
    ).group_by(ReachabilityCheck.dns_record_id).subquery()
    latest_checks = db.query(ReachabilityCheck).join(
        subquery,
        (ReachabilityCheck.dns_record_id == subquery.c.dns_record_id) &
        (ReachabilityCheck.checked_at == subquery.c.max_checked_at)
    ).all()
    reach_ok = sum(1 for c in latest_checks
                   if (c.http_status_code and 200 <= c.http_status_code < 300)
                   or (c.https_status_code and 200 <= c.https_status_code < 300))
    reach_error = sum(1 for c in latest_checks
                      if not ((c.http_status_code and c.http_status_code < 400 and not c.http_error)
                              or (c.https_status_code and c.https_status_code < 400 and not c.https_error)))

    from reportlab.platypus import Image as RLImage

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch,
                            title=f"{branding.PRODUCT} summary report", author=branding.PRODUCT)
    styles = getSampleStyleSheet()
    text = colors.HexColor("#" + exposure_workbook.TEXT)
    heading = ParagraphStyle("heading", parent=styles["Heading2"], textColor=text, spaceBefore=4)
    meta = ParagraphStyle("meta", parent=styles["Normal"], fontSize=9,
                          textColor=colors.HexColor("#" + exposure_workbook.TEXT_TERTIARY))

    # Wordmark + tagline as an image (see docs/UI_CONVENTIONS.md); text fallback without Pillow
    logo_png = branding.wordmark_png(size=96)
    if logo_png:
        logo = RLImage(io.BytesIO(logo_png))
        scale = 42 / logo.imageHeight
        logo.drawWidth, logo.drawHeight = logo.imageWidth * scale, 42
        logo.hAlign = "LEFT"
        header = [logo]
    else:
        header = [Paragraph(f'<font color="{branding.ORANGE}"><b>SKY</b></font><font color="{branding.BLUE}"><b>LAR</b></font>', styles["Title"])]
    elements = header + [
        Spacer(1, 6),
        Paragraph("Summary report", styles["Heading1"]),
        Paragraph(f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC", meta),
        Spacer(1, 14),
        Paragraph("Overview", heading),
    ]

    table_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#" + exposure_workbook.SURFACE)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (0, 1), (-1, -1), text),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#" + exposure_workbook.BORDER)),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#" + exposure_workbook.BAND)]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ])

    overview_rows = [
        ["Zones", "Active", "DNS Records", "Proxied", "Requests (24h)", "Bandwidth (24h)", "Threats (24h)", "Cache Ratio"],
        [
            str(len(zones)),
            str(sum(1 for z in zones if z.status == "active")),
            str(sum(c[0] for c in dns_counts.values())),
            str(sum(c[1] for c in dns_counts.values())),
            f"{total_requests:,}",
            _format_bytes(traffic[2] or 0),
            f"{traffic[3] or 0:,}",
            f"{(total_cached / total_requests * 100):.1f}%" if total_requests else "n/a",
        ],
    ]
    overview = Table(overview_rows, hAlign="LEFT")
    overview.setStyle(table_style)
    elements.extend([overview, Spacer(1, 14), Paragraph("Zones", heading)])

    zone_rows = [["Zone", "Status", "Type", "DNS Records", "Proxied", "Security Enabled"]]
    for z in zones:
        records_total, records_proxied = dns_counts.get(z.zone_id, (0, 0))
        sec_enabled, sec_total = sec_counts.get(z.zone_id, (0, 0))
        zone_rows.append([
            z.name, z.status or "", z.type or "",
            str(records_total), str(records_proxied),
            f"{sec_enabled}/{sec_total}" if sec_total else "n/a",
        ])
    zone_table = Table(zone_rows, hAlign="LEFT", repeatRows=1)
    zone_table.setStyle(table_style)
    elements.append(zone_table)

    if latest_checks:
        elements.extend([
            Spacer(1, 14),
            Paragraph("Reachability (latest checks)", heading),
        ])
        reach_rows = [
            ["Hostnames Checked", "Reachable (2xx)", "Unreachable / Error"],
            [str(len(latest_checks)), str(reach_ok), str(reach_error)],
        ]
        reach_table = Table(reach_rows, hAlign="LEFT")
        reach_table.setStyle(table_style)
        elements.append(reach_table)

    doc.build(elements)
    buf.seek(0)
    filename = f"skylar_summary_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# ==================== Report Preset Routes ====================

@app.get("/api/report-presets", response_model=List[ReportPresetResponse])
async def list_report_presets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(ReportPreset).order_by(ReportPreset.name).all()

@app.post("/api/report-presets", response_model=ReportPresetResponse)
async def create_report_preset(
    request: Request,
    preset_data: ReportPresetCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    preset = ReportPreset(
        name=preset_data.name,
        report_id=preset_data.report_id,
        format=preset_data.format,
        params=preset_data.params,
        created_by=current_user.id
    )
    db.add(preset)
    db.commit()
    db.refresh(preset)

    create_audit_log(
        db=db,
        action="PRESET_CREATED",
        user_id=current_user.id,
        resource_type="report",
        resource_id=str(preset.id),
        details={"name": preset.name, "report_id": preset.report_id, "format": preset.format},
        ip_address=request.client.host if request.client else None
    )
    return preset

@app.delete("/api/report-presets/{preset_id}")
async def delete_report_preset(
    request: Request,
    preset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    preset = db.query(ReportPreset).filter(ReportPreset.id == preset_id).first()
    if not preset:
        raise HTTPException(status_code=404, detail="Preset not found")

    preset_name = preset.name
    db.delete(preset)
    db.commit()

    create_audit_log(
        db=db,
        action="PRESET_DELETED",
        user_id=current_user.id,
        resource_type="report",
        resource_id=str(preset_id),
        details={"name": preset_name},
        ip_address=request.client.host if request.client else None
    )
    return {"message": "Preset deleted successfully"}

# ==================== Exposure Analysis Routes ====================

@app.get("/api/exposure/signatures")
async def list_exposure_signatures(current_user: User = Depends(get_current_user)):
    sigs = exposure_signatures.list_signatures(EXPOSURE_SIGNATURES_DIR)
    return [s.to_dict() for s in sigs.values()]

@app.get("/api/exposure/runs/progress")
async def get_exposure_progress(current_user: User = Depends(get_current_user)):
    """Real-time progress for the running exposure analysis (same shape as sync)"""
    return _get_exposure_progress()

@app.post("/api/exposure/runs", response_model=ExposureRunResponse, status_code=202)
async def start_exposure_run(
    request: Request,
    payload: ExposureRunCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    config = db.query(CloudflareConfig).filter(CloudflareConfig.id == payload.config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Config not found")
    signature = _load_signature_or_404(payload.signature_name)

    if _get_exposure_progress()["active"]:
        raise HTTPException(status_code=409, detail="An exposure analysis is already running")

    window_end = datetime.utcnow().replace(second=0, microsecond=0)
    run = ExposureRun(
        config_id=config.id, signature_name=signature.name, signature_version=signature.version,
        window_start=window_end - timedelta(days=payload.window_days), window_end=window_end,
        status="running", verify_enabled=payload.verify, created_by=current_user.id,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    ip_address = request.client.host if request.client else None
    create_audit_log(
        db=db, action="EXPOSURE_RUN_STARTED", user_id=current_user.id, resource_type="exposure",
        resource_id=str(run.id),
        details={"config_name": config.name, "signature": signature.name, "window_days": payload.window_days,
                 "verify": payload.verify},
        ip_address=ip_address,
    )
    # Mark active before returning so a second click can't start a parallel run
    _update_exposure_progress(active=True, stage="queued", message="Queued...", run_id=run.id,
                              signature_name=signature.name, result=None, error=None, completed_at=None)
    background_tasks.add_task(run_exposure_in_background, run.id, current_user.id, ip_address)
    return run

@app.get("/api/exposure/runs", response_model=List[ExposureRunResponse])
async def list_exposure_runs(
    signature_name: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(ExposureRun)
    if signature_name:
        query = query.filter(ExposureRun.signature_name == signature_name)
    return query.order_by(ExposureRun.id.desc()).limit(limit).all()

def _get_run_or_404(db: Session, run_id: int) -> ExposureRun:
    run = db.query(ExposureRun).filter(ExposureRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run

@app.get("/api/exposure/runs/{run_id}")
async def get_exposure_run(
    run_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    run = _get_run_or_404(db, run_id)
    findings = db.query(ExposureFinding).filter(ExposureFinding.run_id == run_id).order_by(ExposureFinding.host, ExposureFinding.rule_id).all()
    hosts = db.query(ExposureHost).filter(ExposureHost.run_id == run_id).order_by(ExposureHost.host).all()
    probes = db.query(ExposureProbe).filter(ExposureProbe.run_id == run_id).order_by(ExposureProbe.host, ExposureProbe.id).all()
    signature = exposure_signatures.get_signature(run.signature_name, EXPOSURE_SIGNATURES_DIR)
    return {
        "run": ExposureRunResponse.model_validate(run),
        "signature": signature.to_dict() if signature else None,
        "findings": [ExposureFindingResponse.model_validate(f) for f in findings],
        "hosts": [ExposureHostResponse.model_validate(h) for h in hosts],
        "probes": [ExposureProbeResponse.model_validate(p) for p in probes],
    }

@app.delete("/api/exposure/runs/{run_id}")
async def delete_exposure_run(
    request: Request,
    run_id: int,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    run = _get_run_or_404(db, run_id)
    if run.status == "running" and _get_exposure_progress()["active"]:
        raise HTTPException(status_code=409, detail="Run is still in progress")
    for model in (ExposureProbe, ExposureFinding, ExposureHost):
        db.query(model).filter(model.run_id == run_id).delete(synchronize_session=False)
    db.delete(run)
    db.commit()
    create_audit_log(db=db, action="EXPOSURE_RUN_DELETED", user_id=current_user.id, resource_type="exposure",
                     resource_id=str(run_id), details={"signature": run.signature_name},
                     ip_address=request.client.host if request.client else None)
    return {"message": "Run deleted"}

@app.patch("/api/exposure/hosts/{run_id}/{host}", response_model=ExposureHostResponse)
async def update_exposure_host(
    request: Request,
    run_id: int,
    host: str,
    payload: ExposureHostUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    row = db.query(ExposureHost).filter(ExposureHost.run_id == run_id, ExposureHost.host == host.lower()).first()
    if not row:
        raise HTTPException(status_code=404, detail="Host not found in this run")
    changes = {}
    for field_name, value in payload.model_dump(exclude_unset=True).items():
        if getattr(row, field_name) != value:
            changes[field_name] = value
            setattr(row, field_name, value)
    db.commit()
    db.refresh(row)
    if changes:
        create_audit_log(db=db, action="EXPOSURE_HOST_UPDATED", user_id=current_user.id, resource_type="exposure",
                         resource_id=str(run_id), details={"host": host, "changes": changes},
                         ip_address=request.client.host if request.client else None)
    return row

def _exposure_diff(db: Session, run: ExposureRun, other: ExposureRun) -> Dict[str, Any]:
    """Compare `run` (newer) against `other` (older): hosts/verdicts/versions/decisions."""
    def host_map(r):
        return {h.host: h for h in db.query(ExposureHost).filter(ExposureHost.run_id == r.id).all()}
    def misrouted_hosts(r):
        return {f.host for f in db.query(ExposureFinding).filter(
            ExposureFinding.run_id == r.id, ExposureFinding.rule_id == "EXP-003").all()}

    new_hosts, old_hosts = host_map(run), host_map(other)
    new_mis, old_mis = misrouted_hosts(run), misrouted_hosts(other)
    verdict_changes, version_changes = [], []
    for host in sorted(set(new_hosts) & set(old_hosts)):
        a, b = old_hosts[host], new_hosts[host]
        if (a.verdict or None) != (b.verdict or None):
            verdict_changes.append({"host": host, "from": a.verdict, "to": b.verdict})
        if (a.detected_version, a.version_status) != (b.detected_version, b.version_status) and (a.detected_version or b.detected_version):
            version_changes.append({"host": host, "from": a.detected_version, "from_status": a.version_status,
                                    "to": b.detected_version, "to_status": b.version_status})
    return {
        "run_id": run.id, "other_run_id": other.id,
        "new_hosts": [{"host": h, "verdict": new_hosts[h].verdict} for h in sorted(set(new_hosts) - set(old_hosts))],
        "removed_hosts": [{"host": h, "verdict": old_hosts[h].verdict} for h in sorted(set(old_hosts) - set(new_hosts))],
        "verdict_changes": verdict_changes,
        "version_changes": version_changes,
        "misrouted_appeared": sorted(new_mis - old_mis),
        "misrouted_resolved": sorted(old_mis - new_mis),
        "decisions_open": [{"host": h.host, "verdict": h.verdict, "owner": h.owner}
                           for h in new_hosts.values()
                           if h.verdict in (exposure_rules.VERDICT_LIKELY, exposure_rules.VERDICT_MISROUTED) and not h.decision],
    }

@app.get("/api/exposure/runs/{run_id}/diff/{other_id}")
async def diff_exposure_runs(
    run_id: int,
    other_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    run = _get_run_or_404(db, run_id)
    other = _get_run_or_404(db, other_id)
    if run.signature_name != other.signature_name:
        raise HTTPException(status_code=400, detail="Runs use different signatures")
    return _exposure_diff(db, run, other)

@app.get("/api/exposure/runs/{run_id}/export.xlsx")
async def export_exposure_workbook(
    run_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Handoff workbook: Summary, Action Items, Evidence, Cleared, Intel Gaps, Mitigations"""
    run = _get_run_or_404(db, run_id)
    findings = db.query(ExposureFinding).filter(ExposureFinding.run_id == run_id).order_by(ExposureFinding.host).all()
    hosts = db.query(ExposureHost).filter(ExposureHost.run_id == run_id).order_by(ExposureHost.host).all()
    probes = db.query(ExposureProbe).filter(ExposureProbe.run_id == run_id).order_by(ExposureProbe.host, ExposureProbe.id).all()
    signature = exposure_signatures.get_signature(run.signature_name, EXPOSURE_SIGNATURES_DIR)
    wb = exposure_workbook.build_exposure_workbook(run, hosts, findings, probes, signature)

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename=exposure_{run.signature_name}_run{run.id}_{timestamp}.xlsx"}
    )

# ==================== Health Check ====================

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "message": "SKYLAR backend is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
