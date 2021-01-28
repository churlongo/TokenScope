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
        self.assertTrue(any("at least 2" in e for e in d.errors))

    def test_corrupt_payload_json(self):
        header = _b64(json.dumps({"alg": "HS256"}).encode())
        payload = _b64(b"{not json")
        d = decode.decode_token(header + "." + payload + ".sig")
        self.assertFalse(d.ok)
        self.assertTrue(any("not valid JSON" in e for e in d.errors))

    def test_payload_not_object(self):
        header = _b64(json.dumps({"alg": "HS256"}).encode())
        payload = _b64(json.dumps([1, 2, 3]).encode())
        d = decode.decode_token(header + "." + payload + ".sig")
        self.assertFalse(d.ok)
        self.assertTrue(any("not an object" in e for e in d.errors))


class ClaimsTests(unittest.TestCase):
    def test_alg_none_flagged(self):
        tok = make_token({"alg": "none"}, {"sub": "a"})
        d = decode.decode_token(tok)
        findings = claims.audit_claims(d, DEFAULT_POLICY, NOW)
        self.assertTrue(any(f.rule == "TS002" for f in findings))

    def test_missing_required_claim(self):
        tok = make_token(
            {"alg": "HS256", "kid": "k"},
            {"iss": "i", "sub": "s", "exp": NOW + 100, "iat": NOW},
            SECRET,
        )
        d = decode.decode_token(tok)
        findings = claims.audit_claims(d, DEFAULT_POLICY, NOW)
        self.assertTrue(
            any(f.rule == "TS006" and "aud" in f.message for f in findings)
        )

    def test_expired_flagged(self):
        tok = make_token(
            {"alg": "HS256", "kid": "k"},
            {
                "iss": "i",
                "sub": "s",
                "aud": "a",
                "iat": NOW - 7200,
                "exp": NOW - 3600,
            },
            SECRET,
        )
        d = decode.decode_token(tok)
        findings = claims.audit_claims(d, DEFAULT_POLICY, NOW)
        self.assertTrue(any(f.rule == "TS008" for f in findings))

    def test_excessive_lifetime(self):
        tok = make_token(
            {"alg": "HS256", "kid": "k"},
            {
                "iss": "i",
                "sub": "s",
                "aud": "a",
                "iat": NOW,
                "exp": NOW + 86400,
            },
            SECRET,
        )
        d = decode.decode_token(tok)
        findings = claims.audit_claims(d, DEFAULT_POLICY, NOW)
        self.assertTrue(any(f.rule == "TS011" for f in findings))

    def test_missing_kid_under_rotation(self):
        tok = make_token(
            {"alg": "HS256"},
            {
                "iss": "i",
                "sub": "s",
                "aud": "a",
                "iat": NOW,
                "exp": NOW + 100,
            },
            SECRET,
        )
        d = decode.decode_token(tok)
        findings = claims.audit_claims(d, DEFAULT_POLICY, NOW)
        self.assertTrue(any(f.rule == "TS005" for f in findings))

    def test_confusion_risk_for_hmac(self):
        tok = make_token(
            {"alg": "HS256", "kid": "k"},
            {
                "iss": "i",
                "sub": "s",
                "aud": "a",
                "iat": NOW,
                "exp": NOW + 100,
            },
            SECRET,
        )
        d = decode.decode_token(tok)
        findings = claims.audit_claims(d, DEFAULT_POLICY, NOW)
        self.assertTrue(any(f.rule == "TS004" for f in findings))

    def test_no_confusion_when_only_hmac_allowed(self):
        policy = Policy(allowed_algs=("HS256",))
        tok = make_token(
            {"alg": "HS256", "kid": "k"},
            {
                "iss": "i",
                "sub": "s",
                "aud": "a",
                "iat": NOW,
                "exp": NOW + 100,
            },
            SECRET,
        )
        d = decode.decode_token(tok)
        findings = claims.audit_claims(d, policy, NOW)
        self.assertFalse(any(f.rule == "TS004" for f in findings))

    def test_oversized_payload(self):
        policy = Policy(max_payload_bytes=10)
        tok = make_token(
            {"alg": "HS256", "kid": "k"},
            {
                "iss": "i",
                "sub": "s",
                "aud": "a",
                "iat": NOW,
                "exp": NOW + 100,
            },
            SECRET,
        )
        d = decode.decode_token(tok)
        findings = claims.audit_claims(d, policy, NOW)
        self.assertTrue(any(f.rule == "TS014" for f in findings))

    def test_bad_numeric_date_type(self):
        tok = make_token(
            {"alg": "HS256", "kid": "k"},
            {
                "iss": "i",
                "sub": "s",
                "aud": "a",
                "iat": "not-a-number",
                "exp": NOW + 100,
            },
            SECRET,
        )
        d = decode.decode_token(tok)
        findings = claims.audit_claims(d, DEFAULT_POLICY, NOW)
        self.assertTrue(any(f.rule == "TS007" for f in findings))


class VerifyTests(unittest.TestCase):
    def test_valid_signature(self):
        tok = make_token({"alg": "HS256"}, {"sub": "a"}, SECRET)
        d = decode.decode_token(tok)
        v = verify.verify(d, SECRET)
        self.assertEqual(v.status, verify.VALID)

    def test_wrong_secret(self):
        tok = make_token({"alg": "HS256"}, {"sub": "a"}, SECRET)
        d = decode.decode_token(tok)
        v = verify.verify(d, b"wrong-secret")
        self.assertEqual(v.status, verify.INVALID)

    def test_asymmetric_unsupported(self):
        tok = make_token({"alg": "RS256"}, {"sub": "a"}, SECRET)
        d = decode.decode_token(tok)
        v = verify.verify(d, SECRET)
        self.assertEqual(v.status, verify.UNSUPPORTED)

    def test_none_unsupported(self):
        tok = make_token({"alg": "none"}, {"sub": "a"})
        d = decode.decode_token(tok)
        v = verify.verify(d, SECRET)
        self.assertEqual(v.status, verify.UNSUPPORTED)


class ReportTests(unittest.TestCase):
    def test_inspect_is_line_oriented(self):
        tok = make_token({"alg": "HS256"}, {"sub": "a", "iss": "i"}, SECRET)
        d = decode.decode_token(tok)
        lines = report.render_inspect(0, d)
        self.assertTrue(all(isinstance(x, str) for x in lines))
        self.assertTrue(lines[0].startswith("token[0]"))

    def test_canonical_json_is_sorted(self):
        tok = make_token({"alg": "HS256"}, {"b": 2, "a": 1}, SECRET)
        d = decode.decode_token(tok)
        lines = report.render_inspect(0, d)
        payload_line = [x for x in lines if x.strip().startswith("payload:")][0]
        self.assertIn('{"a":1,"b":2}', payload_line)


class CliTests(unittest.TestCase):
    def _run(self, argv) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
