"""
identity/config.py

Purpose:
  Central configuration module for the Identity subsystem of Repeater Chain.
  - Provides strongly typed dataclasses for all identity-related settings.
  - Supports loading from JSON/YAML-like dict, environment variables, and secure runtime secrets.
  - Validation, serialization, snapshotting, and secret rotation helpers.
  - Pluggable secret backend interface (Env / File / Vault / HSM).
  - Designed by a senior engineer: explicit, testable, auditable, and easy to integrate.

Important notes:
  - This module avoids non-standard dependencies. It uses stdlib only.
  - For production, plug a real secret manager by implementing SecretBackend.
  - Comments kept concise and focused on essential behaviors.
"""

from __future__ import annotations
import os
import json
import time
import secrets
import threading
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, Callable, Tuple
from pathlib import Path

# -------------------------
# Constants & defaults
# -------------------------
DEFAULT_ARGON2_OPSLIMIT = 4_000  # example interactive-ish, tune per env
DEFAULT_ARGON2_MEMLIMIT_MB = 64  # in megabytes (for example)
DEFAULT_SALT_BYTES = 16
DEFAULT_PEPPER_BYTES = 32
DEFAULT_CHECKSUM_LEN = 16
DEFAULT_VERSION = "1.0"
CONFIG_SNAPSHOT_DIR = Path(os.getenv("REPEATER_CONFIG_SNAPSHOT_DIR", "/tmp/repeater_config_snapshots"))

# -------------------------
# Secret backend interface
# -------------------------
class SecretBackend:
    """
    Minimal interface for secret storage / retrieval.
    Implementations must be thread-safe.
    """

    def get_secret(self, key: str) -> Optional[bytes]:
        """Return secret bytes for key or None if not found."""
        raise NotImplementedError

    def set_secret(self, key: str, value: bytes, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store secret bytes for key. Caller decides persistence details."""
        raise NotImplementedError

    def rotate_secret(self, key: str, generator: Callable[[], bytes]) -> Tuple[bytes, bytes]:
        """
        Atomic rotate: generate new secret using generator(), store it and return (old, new).
        Default implementation uses get/set; backends may override for atomicity.
        """
        old = self.get_secret(key)
        new = generator()
        self.set_secret(key, new)
        return (old, new)

# Simple environment-based secret backend (useful for dev)
class EnvSecretBackend(SecretBackend):
    """Secret backend backed by environment variables (insecure, dev only)."""

    def __init__(self, prefix: str = "REPEATER_ID_"):
        self.prefix = prefix

    def _k(self, key: str) -> str:
        return f"{self.prefix}{key}"

    def get_secret(self, key: str) -> Optional[bytes]:
        val = os.getenv(self._k(key))
        return val.encode() if val is not None else None

    def set_secret(self, key: str, value: bytes, metadata: Optional[Dict[str, Any]] = None) -> None:
        os.environ[self._k(key)] = value.decode() if isinstance(value, bytes) else str(value)

# File-based secret backend (simple encrypted file not implemented — store raw, dev-only)
class FileSecretBackend(SecretBackend):
    """Secret backend that stores secrets as files under a directory (dev/test only)."""

    def __init__(self, base_dir: str = "/tmp/repeater_secrets"):
        self.base = Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.base / key

    def get_secret(self, key: str) -> Optional[bytes]:
        p = self._path(key)
        if not p.exists(): return None
        return p.read_bytes()

    def set_secret(self, key: str, value: bytes, metadata: Optional[Dict[str, Any]] = None) -> None:
        p = self._path(key)
        p.write_bytes(value if isinstance(value, (bytes, bytearray)) else str(value).encode())

# -------------------------
# Utility helpers
# -------------------------
def now_iso() -> str:
    """Return current UTC ISO timestamp (compact)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def secure_random_bytes(n: int) -> bytes:
    """Return cryptographically secure random bytes."""
    return secrets.token_bytes(n)

def hex_encode(b: Optional[bytes]) -> Optional[str]:
    return None if b is None else b.hex()

def hex_decode(s: Optional[str]) -> Optional[bytes]:
    return None if s is None else bytes.fromhex(s)

def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to avoid timing leaks."""
    return hashlib.sha256(a).digest() == hashlib.sha256(b).digest()

# -------------------------
# Dataclasses for config
# -------------------------
@dataclass
class KDFConfig:
    """Key derivation / password hardening parameters."""
    algorithm: str = "argon2id"
    opslimit: int = DEFAULT_ARGON2_OPSLIMIT
    memlimit_mb: int = DEFAULT_ARGON2_MEMLIMIT_MB
    salt_bytes: int = DEFAULT_SALT_BYTES

    def validate(self) -> None:
        if self.algorithm.lower() not in ("argon2id",):
            raise ValueError("unsupported KDF algorithm")
        if self.opslimit <= 0 or self.memlimit_mb <= 0:
            raise ValueError("invalid KDF resource parameters")
        if not (8 <= self.salt_bytes <= 64):
            raise ValueError("salt_bytes must be between 8 and 64")

@dataclass
class PasswordAuthConfig:
    """Password-based identity settings."""
    enabled: bool = True
    require_strong_passwords: bool = True
    min_length: int = 10
    kdf: KDFConfig = field(default_factory=KDFConfig)
    pepper_key_name: str = "PEPPER"  # secret backend key name

    def validate(self) -> None:
        if self.min_length < 6:
            raise ValueError("min_length too small")
        self.kdf.validate()

@dataclass
class OIDCConfig:
    """OpenID Connect settings for external login."""
    enabled: bool = False
    client_id: Optional[str] = None
    client_secret_key_name: Optional[str] = None  # fetched from secret backend
    issuer: Optional[str] = None
    scopes: Tuple[str, ...] = ("openid", "email", "profile")

    def validate(self) -> None:
        if self.enabled:
            if not (self.client_id and self.client_secret_key_name and self.issuer):
                raise ValueError("oidc enabled but missing mandatory fields")

@dataclass
class StorageConfig:
    """Where to persist identity metadata (public keys, salts, etc.)."""
    backend: str = "sqlite"  # options: sqlite, postgres, remote_kv
    uri: Optional[str] = None
    table_prefix: str = "identity_"

    def validate(self) -> None:
        if self.backend == "sqlite" and not self.uri:
            # default sqlite file
            self.uri = os.getenv("REPEATER_ID_SQLITE", "sqlite:///var/lib/repeater/identity.db")
        if self.backend not in ("sqlite", "postgres", "remote_kv"):
            raise ValueError("unsupported storage backend")

@dataclass
class RotationPolicy:
    """Key rotation / secret rotation policy."""
    enabled: bool = True
    rotate_every_days: int = 90
    last_rotated_iso: Optional[str] = None

    def needs_rotation(self) -> bool:
        if not self.enabled:
            return False
        if not self.last_rotated_iso:
            return True
        try:
            last = time.strptime(self.last_rotated_iso, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return True
        elapsed = time.time() - time.mktime(last)
        return elapsed >= (self.rotate_every_days * 86400)

@dataclass
class LoggingConfig:
    level: str = "INFO"
    audit_log_enabled: bool = True
    audit_log_path: Optional[str] = None

    def validate(self) -> None:
        if self.level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
            raise ValueError("invalid logging level")

@dataclass
class IdentityConfig:
    """Top-level config for identity subsystem."""
    version: str = DEFAULT_VERSION
    created_at: str = field(default_factory=now_iso)
    password_auth: PasswordAuthConfig = field(default_factory=PasswordAuthConfig)
    oidc: OIDCConfig = field(default_factory=OIDCConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    rotation: RotationPolicy = field(default_factory=RotationPolicy)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    feature_flags: Dict[str, bool] = field(default_factory=lambda: {"password_admin_bypass": False})

    # runtime fields (not serialized in same way as config, derived)
    _secret_backend: SecretBackend = field(default_factory=lambda: EnvSecretBackend(), repr=False, compare=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    # -------------------------
    # Load / merge / validation
    # -------------------------
    def validate(self) -> None:
        """Validate all sub-configs."""
        self.password_auth.validate()
        self.oidc.validate()
        self.storage.validate()
        self.logging.validate()
        # additional invariants
        if self.password_auth.enabled and not self._secret_backend.get_secret(self.password_auth.pepper_key_name):
            # pepper missing is not fatal here, but warn in logs (consumer may choose to require it)
            pass  # leave to caller for action

    def to_dict(self, include_runtime: bool = False) -> Dict[str, Any]:
        """Serialize config to dict; exclude runtime internals by default."""
        base = asdict(self)
        # remove non-serializable / runtime fields
        base.pop("_secret_backend", None)
        base.pop("_lock", None)
        if not include_runtime:
            # do not include secrets or backend implementations
            return base
        return base

    @classmethod
    def from_dict(cls, data: Dict[str, Any], secret_backend: Optional[SecretBackend] = None) -> "IdentityConfig":
        """Create config from a nested dictionary (usually parsed JSON/YAML)."""
        # Defensive copy
        d = dict(data)
        # build substructures carefully
        pw = d.get("password_auth", {})
        kdf = pw.get("kdf", {})
        password_auth = PasswordAuthConfig(
            enabled=pw.get("enabled", True),
            require_strong_passwords=pw.get("require_strong_passwords", True),
            min_length=pw.get("min_length", 10),
            kdf=KDFConfig(
                algorithm=kdf.get("algorithm", "argon2id"),
                opslimit=int(kdf.get("opslimit", DEFAULT_ARGON2_OPSLIMIT)),
                memlimit_mb=int(kdf.get("memlimit_mb", DEFAULT_ARGON2_MEMLIMIT_MB)),
                salt_bytes=int(kdf.get("salt_bytes", DEFAULT_SALT_BYTES))
            ),
            pepper_key_name=pw.get("pepper_key_name", "PEPPER")
        )
        oidc = d.get("oidc", {})
        oidc_cfg = OIDCConfig(
            enabled=bool(oidc.get("enabled", False)),
            client_id=oidc.get("client_id"),
            client_secret_key_name=oidc.get("client_secret_key_name"),
            issuer=oidc.get("issuer"),
            scopes=tuple(oidc.get("scopes", ("openid", "email", "profile")))
        )
        storage = d.get("storage", {})
        storage_cfg = StorageConfig(
            backend=storage.get("backend", "sqlite"),
            uri=storage.get("uri"),
            table_prefix=storage.get("table_prefix", "identity_")
        )
        rotation = d.get("rotation", {})
        rotation_cfg = RotationPolicy(
            enabled=rotation.get("enabled", True),
            rotate_every_days=int(rotation.get("rotate_every_days", 90)),
            last_rotated_iso=rotation.get("last_rotated_iso")
        )
        logging = d.get("logging", {})
        logging_cfg = LoggingConfig(
            level=logging.get("level", "INFO"),
            audit_log_enabled=logging.get("audit_log_enabled", True),
            audit_log_path=logging.get("audit_log_path")
        )
        feature_flags = d.get("feature_flags", {"password_admin_bypass": False})
        conf = cls(
            version=d.get("version", DEFAULT_VERSION),
            created_at=d.get("created_at", now_iso()),
            password_auth=password_auth,
            oidc=oidc_cfg,
            storage=storage_cfg,
            rotation=rotation_cfg,
            logging=logging_cfg,
            feature_flags=feature_flags
        )
        if secret_backend:
            conf.set_secret_backend(secret_backend)
        return conf

    # -------------------------
    # Secret operations
    # -------------------------
    def set_secret_backend(self, backend: SecretBackend) -> None:
        """Set a pluggable secret backend instance (thread-safe)."""
        with self._lock:
            self._secret_backend = backend

    def fetch_pepper(self) -> Optional[bytes]:
        """Fetch pepper from secret backend using configured key name."""
        return self._secret_backend.get_secret(self.password_auth.pepper_key_name)

    def ensure_pepper(self, generate_if_missing: bool = True) -> bytes:
        """
        Ensure pepper exists; generate and store if missing and allowed.
        Returns pepper bytes.
        """
        with self._lock:
            pepper = self.fetch_pepper()
            if pepper:
                return pepper
            if not generate_if_missing:
                raise RuntimeError("pepper missing")
            new_pepper = secure_random_bytes(DEFAULT_PEPPER_BYTES)
            self._secret_backend.set_secret(self.password_auth.pepper_key_name, new_pepper)
            # update rotation metadata
            self.rotation.last_rotated_iso = now_iso()
            return new_pepper

    def rotate_pepper(self, generator: Optional[Callable[[], bytes]] = None) -> Tuple[Optional[bytes], bytes]:
        """
        Rotate pepper via secret backend. Returns (old_pepper, new_pepper).
        Default generator uses secure_random_bytes(DEFAULT_PEPPER_BYTES).
        """
        if generator is None:
            generator = lambda: secure_random_bytes(DEFAULT_PEPPER_BYTES)
        with self._lock:
            old, new = self._secret_backend.rotate_secret(self.password_auth.pepper_key_name, generator)
            self.rotation.last_rotated_iso = now_iso()
            return (old, new)

    # -------------------------
    # Persistence / snapshot
    # -------------------------
    def snapshot(self, tag: Optional[str] = None) -> Path:
        """Write a config snapshot JSON to snapshot directory (non-secret fields only)."""
        CONFIG_SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
        ts = now_iso().replace(":", "-")
        tag_part = f"-{tag}" if tag else ""
        fname = CONFIG_SNAPSHOT_DIR / f"identity-config-{ts}{tag_part}.json"
        # export without runtime secret backend
        data = self.to_dict(include_runtime=False)
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        return fname

    # -------------------------
    # Hot reload helper (file watching is external; call reload_from_file to apply)
    # -------------------------
    def reload_from_file(self, path: str) -> None:
        """Reload configuration from a JSON file and merge with current config. Secrets preserved."""
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        # build new object and validate
        new_conf = IdentityConfig.from_dict(payload, secret_backend=self._secret_backend)
        new_conf.validate()
        # merge non-runtime fields under lock
        with self._lock:
            # simple merge strategy: replace top-level fields
            self.version = new_conf.version
            self.created_at = new_conf.created_at
            self.password_auth = new_conf.password_auth
            self.oidc = new_conf.oidc
            self.storage = new_conf.storage
            self.rotation = new_conf.rotation
            self.logging = new_conf.logging
            self.feature_flags = new_conf.feature_flags

    # -------------------------
    # Convenience / runtime checks
    # -------------------------
    def check_and_rotate_if_needed(self) -> bool:
        """Check rotation policy; rotate pepper if required. Returns True if rotated."""
        if self.rotation.needs_rotation():
            self.rotate_pepper()
            return True
        return False

# -------------------------
# Example usage (demo)
# -------------------------
if __name__ == "__main__":
    # Demo / smoke test for dev only
    conf_dict = {
        "version": "1.0",
        "password_auth": {
            "enabled": True,
            "require_strong_passwords": True,
            "min_length": 12,
            "kdf": {
                "algorithm": "argon2id",
                "opslimit": 4000,
                "memlimit_mb": 64,
                "salt_bytes": 16
            },
            "pepper_key_name": "PEPPER"
        },
        "storage": {"backend": "sqlite"},
        "rotation": {"rotate_every_days": 30},
        "logging": {"level": "DEBUG"}
    }

    # use file-backed secret backend for demo
    secret_backend = FileSecretBackend("/tmp/repeater_demo_secrets")
    cfg = IdentityConfig.from_dict(conf_dict, secret_backend=secret_backend)
    try:
        cfg.validate()
    except Exception as e:
        print("CONFIG VALIDATION ERROR:", e)
        raise

    # ensure pepper exists (will create one)
    p = cfg.ensure_pepper()
    print("PEPPER (hex):", p.hex())

    # snapshot config (no secrets included in snapshot)
    snap = cfg.snapshot(tag="demo")
    print("Snapshot written:", snap)

    # simulate rotation if needed
    rotated = cfg.check_and_rotate_if_needed()
    print("Rotated now?:", rotated)

    # show serialized non-secret view
    print(json.dumps(cfg.to_dict(), indent=2, sort_keys=True))
