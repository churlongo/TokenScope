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
