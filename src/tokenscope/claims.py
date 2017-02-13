"""Registered claim validation and structural finding generation.

This module turns a decoded token plus a policy into a list of findings. Each
finding names a rule, carries a severity, and states the fact that triggered it.
No value from the token is trusted: a claim is checked for presence, type, and
consistency with the policy, and every conclusion is derived only from the
decoded material and the reference time supplied by the caller.

Determinism matters. The auditor never reads the wall clock. The caller passes a
`now` value (a Unix timestamp) so that identical input plus identical `now`
produces byte-identical findings. The CLI records the `now` it used in the
report header so a run can be reproduced.
"""

from __future__ import annotations

from dataclasses import dataclass

from .decode import DecodedToken
from .policy import Policy

# Severity ordering used for stable sorting and for the report legend.
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Registered claims and the JSON type each must have when present.
# `aud` may be a string or a list of strings per RFC 7519 section 4.1.3.
_NUMERIC_DATE_CLAIMS = ("exp", "nbf", "iat")


@dataclass(frozen=True)
class Finding:
    """One audited fact about a token.

    rule:     stable identifier such as TS001.
    severity: high, medium, low, or info.
    message:  a single line stating the fact, no trailing period.
    """

    rule: str
    severity: str
    message: str

    def sort_key(self) -> tuple[int, str]:
        return (SEVERITY_ORDER.get(self.severity, 9), self.rule)


def _is_numeric_date(value: object) -> bool:
    """True when value is a JSON number usable as a NumericDate.

    RFC 7519 defines NumericDate as a number of seconds since the epoch. A bool
    is a subtype of int in Python, so it is excluded explicitly.
    """
    if isinstance(value, bool):
        return False
    return isinstance(value, (int, float))


def _alg_findings(token: DecodedToken, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    alg = token.header.get("alg")
    if alg is None:
        findings.append(
            Finding("TS001", "high", "header has no 'alg' field")
        )
        return findings
    if not isinstance(alg, str):
        findings.append(
            Finding(
                "TS001",
                "high",
                "header 'alg' is a %s, not a string" % type(alg).__name__,
            )
        )
        return findings
    if alg.lower() == "none":
        findings.append(
            Finding(
                "TS002",
                "high",
                "alg is 'none': token is unsecured and any signature is ignored",
            )
        )
        return findings
    if not policy.allows_alg(alg):
        findings.append(
            Finding(
                "TS003",
                "high",
                "alg %r is not in the policy allow list" % alg,
            )
        )
    return findings


def _confusion_findings(token: DecodedToken, policy: Policy) -> list[Finding]:
    """Flag algorithm confusion exposure.

    The classic attack: a server configured to verify RS256 is handed a token
    whose header says HS256, and if it feeds the RSA public key into an HMAC
    verifier the public key becomes the shared secret. We cannot know the
    server's configuration from the token alone, so we report the exposure
    whenever an HMAC-signed token is present in a set whose policy also permits
    RSA, which is the condition under which the confusion is possible.
    """
    alg = token.header.get("alg")
    if not isinstance(alg, str):
        return []
    if not policy.is_hmac(alg):
        return []
    rsa_allowed = any(policy.is_rsa(a) for a in policy.allowed_algs)
    if not rsa_allowed:
        return []
    return [
        Finding(
            "TS004",
            "high",
            "HMAC alg %s under a policy that also allows RSA: algorithm "
            "confusion risk if an RSA public key is used as the HMAC secret"
            % alg,
        )
    ]


def _kid_findings(token: DecodedToken, policy: Policy) -> list[Finding]:
    if not policy.key_rotation:
        return []
    alg = token.header.get("alg")
    if isinstance(alg, str) and alg.lower() == "none":
        return []
    if "kid" not in token.header:
        return [
            Finding(
                "TS005",
                "medium",
                "no 'kid' header while policy declares key rotation: verifier "
                "cannot select the signing key",
            )
        ]
    return []


def _presence_findings(token: DecodedToken, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for claim in policy.required_claims:
        if claim not in token.payload:
            findings.append(
                Finding(
                    "TS006",
                    "medium",
                    "required claim %r is missing" % claim,
                )
            )
    return findings


def _type_findings(token: DecodedToken) -> list[Finding]:
    findings: list[Finding] = []
    for claim in _NUMERIC_DATE_CLAIMS:
        if claim in token.payload and not _is_numeric_date(token.payload[claim]):
            findings.append(
                Finding(
                    "TS007",
                    "medium",
                    "claim %r must be a numeric date, found %s"
                    % (claim, type(token.payload[claim]).__name__),
                )
            )
    if "aud" in token.payload:
        aud = token.payload["aud"]
        aud_ok = isinstance(aud, str) or (
            isinstance(aud, list) and all(isinstance(x, str) for x in aud)
        )
        if not aud_ok:
            findings.append(
                Finding(
                    "TS007",
                    "medium",
                    "claim 'aud' must be a string or list of strings",
                )
            )
    for claim in ("iss", "sub"):
        if claim in token.payload and not isinstance(token.payload[claim], str):
            findings.append(
                Finding(
                    "TS007",
                    "medium",
                    "claim %r must be a string, found %s"
                    % (claim, type(token.payload[claim]).__name__),
                )
            )
    return findings


def _time_findings(token: DecodedToken, policy: Policy, now: int) -> list[Finding]:
    findings: list[Finding] = []
    exp = token.payload.get("exp")
    nbf = token.payload.get("nbf")
    iat = token.payload.get("iat")

    skew = policy.clock_skew_seconds

    if _is_numeric_date(exp):
        exp_i = int(exp)
        if exp_i < now - skew:
            findings.append(
                Finding(
                    "TS008",
                    "high",
                    "token expired at %d, before now %d (skew %d)"
                    % (exp_i, now, skew),
                )
            )
        elif exp_i < now:
            findings.append(
                Finding(
                    "TS009",
                    "low",
                    "token exp %d is within clock skew of now %d: skew hazard"
                    % (exp_i, now),
                )
            )
