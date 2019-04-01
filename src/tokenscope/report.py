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

