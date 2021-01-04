"""Unit tests for tokenscope, stdlib unittest only.

The tests build their own genuine tokens with hmac and hashlib so that the
suite does not depend on the committed fixture file, and cover base64url edge
cases, decode behaviour, claim findings, HMAC verification, and the CLI exit
codes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import unittest
from contextlib import redirect_stdout

from tokenscope import b64url, claims, decode, report, verify
from tokenscope.cli import DEFAULT_NOW, main
from tokenscope.policy import DEFAULT_POLICY, Policy

SECRET = b"your-256-bit-secret"
NOW = DEFAULT_NOW


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(header: dict, payload: dict, secret: bytes | None = None) -> str:
    h = _b64(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
