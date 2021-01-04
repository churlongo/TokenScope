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
    p = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signing_input = (h + "." + p).encode("ascii")
    if secret is None:
        return h + "." + p + "."
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return h + "." + p + "." + _b64(sig)


class B64UrlTests(unittest.TestCase):
    def test_roundtrip_without_padding(self):
        encoded = _b64(b"hello world")
        result = b64url.decode_segment(encoded)
        self.assertTrue(result.ok)
        self.assertEqual(result.data, b"hello world")

    def test_padding_added_is_reported(self):
        # 'hell' is 4 bytes, encoding to 6 base64url chars needing two pad chars.
        encoded = _b64(b"hell")
        result = b64url.decode_segment(encoded)
        self.assertTrue(result.ok)
        self.assertEqual(result.padding_added, 2)

    def test_standard_base64_char_rejected(self):
        result = b64url.decode_segment("ab+d")
        self.assertFalse(result.ok)
        self.assertIn("standard base64", result.error)

    def test_invalid_length_rejected(self):
        result = b64url.decode_segment("abcde")  # 5 chars, 1 mod 4
        self.assertFalse(result.ok)
        self.assertIn("never valid", result.error)

    def test_stray_char_rejected(self):
        result = b64url.decode_segment("ab$d")
        self.assertFalse(result.ok)
        self.assertIn("alphabet", result.error)

    def test_empty_segment(self):
        result = b64url.decode_segment("")
        self.assertFalse(result.ok)


class DecodeTests(unittest.TestCase):
    def test_good_token_decodes(self):
        tok = make_token({"alg": "HS256"}, {"sub": "a"}, SECRET)
        d = decode.decode_token(tok)
        self.assertTrue(d.ok)
        self.assertEqual(d.segments, 3)
        self.assertEqual(d.header["alg"], "HS256")
        self.assertEqual(d.payload["sub"], "a")

    def test_too_few_segments(self):
        d = decode.decode_token("onlyonesegment")
        self.assertFalse(d.ok)
