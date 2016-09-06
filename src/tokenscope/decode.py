"""Decode JWT and JWS compact serialization into header and payload.

The one rule of this module is that it never trusts what it decodes. It splits
the compact serialization on '.', base64url-decodes the first two segments, and
parses them as JSON. Everything it finds is data to be audited, not a fact to
act on. The signature segment is kept as raw text and never used to make a trust
decision here; verification lives in verify.py and is only attempted when the
caller supplies a secret.

A JWT has three segments (header.payload.signature). A JWS with detached or
absent signature, or an unsecured token with `alg: none`, may present an empty
third segment. Both shapes are decoded and reported honestly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from . import b64url


@dataclass
class DecodedToken:
    """Everything recovered from one compact token, plus decode problems.

