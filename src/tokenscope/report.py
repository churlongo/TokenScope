"""Line-oriented rendering of inspect, audit, and verify results.

Every function here returns a list of strings, one per output line, so results
diff cleanly in git and are trivial to test. No function reads the clock or the
environment; the reference time is passed in and echoed back so a report is
reproducible.
"""

from __future__ import annotations

import json

from .claims import Finding, present_claims
from .decode import DecodedToken
from .policy import Policy, describe
from .verify import Verdict

_REGISTERED = ("iss", "sub", "aud", "exp", "nbf", "iat")


def render_inspect(index: int, token: DecodedToken) -> list[str]:
    """Render the decoded header and payload for one token without judging it."""
    lines = ["token[%d]:" % index]
    lines.append("  segments: %d" % token.segments)
    if token.errors:
        for err in token.errors:
            lines.append("  decode-error: %s" % err)
    lines.append("  header: %s" % _canonical_json(token.header))
    lines.append("  payload: %s" % _canonical_json(token.payload))
    present = present_claims(token)
    lines.append("  registered-claims-present: %s" % (", ".join(present) or "none"))
    return lines


def _canonical_json(obj: dict) -> str:
    """Serialize with sorted keys and compact separators for stable output."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def render_audit_header(policy: Policy, now: int, source: str, count: int) -> list[str]:
    lines = [
        "tokenscope audit",
        "source: %s" % source,
        "tokens: %d" % count,
        "now:    %d" % now,
        "policy:",
    ]
    for line in describe(policy):
        lines.append("  " + line)
    lines.append("")
    return lines


def render_audit_token(index: int, token: DecodedToken, findings: list[Finding]) -> list[str]:
    """Render one token's findings block."""
    alg = token.header.get("alg", "?")
    if not isinstance(alg, str):
        alg = "(non-string)"
    lines = ["token[%d] alg=%s findings=%d" % (index, alg, len(findings))]
    if not findings:
        lines.append("  OK no findings")
    else:
        for f in findings:
            lines.append("  [%s] %s %s" % (f.severity.upper(), f.rule, f.message))
    return lines


def render_audit_summary(total_findings: int, by_severity: dict[str, int]) -> list[str]:
    lines = ["", "summary:"]
    for sev in ("high", "medium", "low", "info"):
        lines.append("  %-6s %d" % (sev + ":", by_severity.get(sev, 0)))
    lines.append("  total: %d" % total_findings)
    return lines


def render_verify(index: int, token: DecodedToken, verdict: Verdict) -> list[str]:
    alg = token.header.get("alg", "?")
    if not isinstance(alg, str):
        alg = "(non-string)"
    return [
        "token[%d] alg=%s verify=%s" % (index, alg, verdict.status),
        "  %s" % verdict.detail,
    ]

# draft note 1529
