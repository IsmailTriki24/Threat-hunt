"""Canonical event model (schema v1), loosely modelled on ECS with a few SOC-oriented additions
(`auth`, `registry`, explicit `severity`, `labels`). Bump SCHEMA_VERSION on breaking changes and keep
readers tolerant of older versions."""

import hashlib
import ipaddress
import json
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, field_validator

SCHEMA_VERSION = 1
MAX_RAW_BYTES = 64 * 1024

S64 = Annotated[str, StringConstraints(max_length=64, strip_whitespace=True)]
S256 = Annotated[str, StringConstraints(max_length=256, strip_whitespace=True)]
S1024 = Annotated[str, StringConstraints(max_length=1024)]
S8192 = Annotated[str, StringConstraints(max_length=8192)]


def _ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


IP = Annotated[str, AfterValidator(_ip)]
HexHash = Annotated[str, StringConstraints(pattern=r"^[A-Fa-f0-9]+$", max_length=64)]
Port = Annotated[int, Field(ge=0, le=65535)]


class EventType(StrEnum):
    PROCESS_CREATION = "process_creation"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    FILE_EVENT = "file_event"
    AUTHENTICATION = "authentication"
    REGISTRY_EVENT = "registry_event"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE_INSTALL = "service_install"
    ALERT = "alert"
    OTHER = "other"


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Hashes(_Part):
    md5: HexHash | None = None
    sha1: HexHash | None = None
    sha256: HexHash | None = None

    @field_validator("md5")
    @classmethod
    def _md5(cls, v: str | None) -> str | None:
        if v is not None and len(v) != 32:
            raise ValueError("md5 must be 32 hex characters")
        return v

    @field_validator("sha1")
    @classmethod
    def _sha1(cls, v: str | None) -> str | None:
        if v is not None and len(v) != 40:
            raise ValueError("sha1 must be 40 hex characters")
        return v

    @field_validator("sha256")
    @classmethod
    def _sha256(cls, v: str | None) -> str | None:
        if v is not None and len(v) != 64:
            raise ValueError("sha256 must be 64 hex characters")
        return v


class Host(_Part):
    id: S256 | None = None
    hostname: S256 | None = None
    ip: list[IP] = Field(default_factory=list, max_length=16)
    os: S64 | None = None


class User(_Part):
    id: S256 | None = None
    name: S256 | None = None
    domain: S256 | None = None


class ParentProcess(_Part):
    name: S256 | None = None
    pid: int | None = Field(default=None, ge=0)
    command_line: S8192 | None = None


class Process(_Part):
    name: S256 | None = None
    pid: int | None = Field(default=None, ge=0)
    executable: S1024 | None = None
    command_line: S8192 | None = None
    hash: Hashes | None = None
    parent: ParentProcess | None = None


class Network(_Part):
    protocol: S64 | None = None
    direction: S64 | None = None
    src_ip: IP | None = None
    src_port: Port | None = None
    dst_ip: IP | None = None
    dst_port: Port | None = None
    dst_domain: S256 | None = None
    bytes: int | None = Field(default=None, ge=0)


class Dns(_Part):
    question: S256 | None = None
    query_type: S64 | None = None
    answers: list[S256] = Field(default_factory=list, max_length=32)


class File(_Part):
    name: S256 | None = None
    path: S1024 | None = None
    hash: Hashes | None = None


class Auth(_Part):
    logon_type: S64 | None = None
    method: S64 | None = None
    source_ip: IP | None = None


class Registry(_Part):
    key: S1024 | None = None
    value: S1024 | None = None


class EventIn(_Part):
    """What a connector/normalizer produces. Contains no tenant: that is stamped server-side."""

    timestamp: datetime
    source: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_.-]{1,64}$")]
    event_type: EventType
    action: S64 | None = None
    outcome: Outcome = Outcome.UNKNOWN
    severity: int = Field(default=0, ge=0, le=100)
    original_id: S256 | None = None
    message: S1024 | None = None

    host: Host | None = None
    user: User | None = None
    process: Process | None = None
    network: Network | None = None
    dns: Dns | None = None
    file: File | None = None
    auth: Auth | None = None
    registry: Registry | None = None

    tags: list[S64] = Field(default_factory=list, max_length=20)
    labels: dict[S64, S256] = Field(default_factory=dict, max_length=20)
    raw: dict[str, Any] | None = None

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        v = v.replace(tzinfo=UTC) if v.tzinfo is None else v.astimezone(UTC)
        if v > datetime.now(UTC) + timedelta(days=1):
            raise ValueError("timestamp is in the future")
        if v.year < 2000:
            raise ValueError("timestamp is implausibly old")
        return v

    @field_validator("raw")
    @classmethod
    def _raw_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None and len(json.dumps(v, default=str)) > MAX_RAW_BYTES:
            raise ValueError(f"raw exceeds {MAX_RAW_BYTES} bytes")
        return v


class Event(EventIn):
    id: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]
    tenant_id: uuid.UUID
    schema_version: int = SCHEMA_VERSION
    ingested_at: datetime

    @classmethod
    def from_input(cls, event: EventIn, tenant_id: uuid.UUID) -> "Event":
        # Deterministic id for sources that give a stable native id => re-ingestion is idempotent.
        if event.original_id:
            digest = hashlib.sha256(f"{tenant_id}|{event.source}|{event.original_id}".encode())
            event_id = digest.hexdigest()[:32]
        else:
            event_id = uuid.uuid4().hex
        return cls(**event.model_dump(), id=event_id, tenant_id=tenant_id, ingested_at=datetime.now(UTC))

    def to_document(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)
