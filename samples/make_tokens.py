"""Generate the bundled test-vector tokens with genuine HMAC signatures.

Run from the project root with the package on the path:

    PYTHONPATH=src python samples/make_tokens.py

This writes samples/tokens.txt. The signing secret is a published test vector
from RFC 7515 appendix A.1 (the octets of the ASCII string below), so the
signatures are real and reproducible, not placeholders. Times are fixed relative
to the auditor's default reference time so the audit output is deterministic.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

# Published test secret. This is the ASCII form used across JWT tutorials and
# is safe to commit precisely because it is public. Never use it in production.
SECRET = b"your-256-bit-secret"

# Must match tokenscope.cli.DEFAULT_NOW (2026-01-01T00:00:00Z).
NOW = 1767225600
HOUR = 3600
DAY = 86400


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_hs256(header: dict, payload: dict, secret: bytes) -> str:
    h = b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signing_input = (h + "." + p).encode("ascii")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return h + "." + p + "." + b64url(sig)


def unsecured(header: dict, payload: dict) -> str:
    h = b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    return h + "." + p + "."


def build() -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []

    # 1. Good token: HS256, kid present, all required claims, lifetime exactly
    #    at the policy maximum (iat to exp is one hour).
    good = sign_hs256(
        {"alg": "HS256", "typ": "JWT", "kid": "key-2026-01"},
        {
            "iss": "https://issuer.example",
            "sub": "user-1001",
            "aud": "api.example",
            "iat": NOW - 60,
            "nbf": NOW - 60,
            "exp": NOW + HOUR - 60,
        },
        SECRET,
    )
    tokens.append(("good HS256 token, all claims, kid present", good))

    # 2. alg none: unsecured token, signature ignored.
    none_tok = unsecured(
        {"alg": "none", "typ": "JWT"},
        {
            "iss": "https://issuer.example",
            "sub": "user-1002",
            "aud": "api.example",
            "iat": NOW - 60,
            "exp": NOW + HOUR - 60,
        },
    )
    tokens.append(("alg none unsecured token", none_tok))

    # 3. Expired: exp well before now.
    expired = sign_hs256(
        {"alg": "HS256", "typ": "JWT", "kid": "key-2026-01"},
        {
            "iss": "https://issuer.example",
            "sub": "user-1003",
            "aud": "api.example",
            "iat": NOW - 2 * HOUR,
            "exp": NOW - HOUR,
        },
        SECRET,
    )
    tokens.append(("expired HS256 token", expired))

    # 4. Missing aud: otherwise valid.
    no_aud = sign_hs256(
        {"alg": "HS256", "typ": "JWT", "kid": "key-2026-01"},
        {
            "iss": "https://issuer.example",
            "sub": "user-1004",
            "iat": NOW - 60,
            "exp": NOW + HOUR - 60,
        },
        SECRET,
    )
    tokens.append(("HS256 token missing aud claim", no_aud))

    # 5. Excessive lifetime: thirty day span, over the one hour policy maximum.
    long_life = sign_hs256(
        {"alg": "HS256", "typ": "JWT", "kid": "key-2026-01"},
        {
            "iss": "https://issuer.example",
            "sub": "user-1005",
            "aud": "api.example",
            "iat": NOW - 60,
            "exp": NOW + 30 * DAY,
        },
        SECRET,
    )
    tokens.append(("HS256 token with thirty day lifetime", long_life))

    # 6. Corrupt payload: valid header and signature-shaped tail, but the
    #    payload segment carries bytes that are not valid JSON once decoded.
    header = b64url(
        json.dumps(
            {"alg": "HS256", "typ": "JWT", "kid": "key-2026-01"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    # Encode a truncated, non-JSON payload so decoding succeeds but parsing fails.
