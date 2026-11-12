"""
services/auth_service.py
-------------------------
Authentication and token management service for multi-developer support.
Uses standard library cryptographic hashing (PBKDF2-HMAC-SHA256) and
HMAC-SHA256 URL-safe signed session tokens.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any

# Use environment variable or a local secret
SECRET_KEY = os.getenv(
    "AUTH_SECRET_KEY",
    "iac-risk-composer-secret-key-2026-secure-multi-tenant-auth",
)
PBKDF2_ITERATIONS = 100_000


def hash_password(password: str) -> tuple[str, str]:
    """
    Hash a password using PBKDF2 with SHA-256 and a random 16-byte salt.
    Returns (hash_hex, salt_hex).
    """
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return key.hex(), salt


def verify_password(password: str, hash_hex: str, salt_hex: str) -> bool:
    """Verify a plain-text password against a stored PBKDF2 hash and salt."""
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_hex.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return hmac.compare_digest(key.hex(), hash_hex)


def generate_token(
    user_id: str,
    username: str,
    email: str,
    expires_in_days: int = 14,
) -> str:
    """Generate a tamper-proof URL-safe HMAC-SHA256 signed bearer token."""
    now = int(time.time())
    payload = {
        "sub": user_id,
        "username": username,
        "email": email,
        "iat": now,
        "exp": now + (expires_in_days * 86400),
    }
    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = (
        base64.urlsafe_b64encode(payload_json.encode("utf-8"))
        .decode("utf-8")
        .rstrip("=")
    )
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload_b64}.{signature}"


def verify_token(token: str) -> dict[str, Any] | None:
    """
    Verify an HMAC-SHA256 signed token.
    Returns payload dictionary if valid and not expired, else None.
    """
    if not token or "." not in token:
        return None

    parts = token.split(".")
    if len(parts) != 2:
        return None

    payload_b64, signature = parts
    expected_sig = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        return None

    try:
        padding = "=" * (-len(payload_b64) % 4)
        payload_raw = base64.urlsafe_b64decode(
            (payload_b64 + padding).encode("utf-8")
        ).decode("utf-8")
        data = json.loads(payload_raw)
        if not isinstance(data, dict):
            return None

        exp = data.get("exp")
        if exp and time.time() > exp:
            return None  # expired

        return data
    except Exception:
        return None
