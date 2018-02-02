"""Declared audit policy: the rules a token set is measured against.

A policy is a set of expectations the operator declares up front, separate from
whatever a token happens to assert. Keeping the policy in one place means the
auditor never has to guess what "too long" or "wrong algorithm" means; the
answer is stated once and applied uniformly.

The default policy below is conservative and is used when the CLI is run without
a policy file. It is deliberately strict so that a clean result means something.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Registered claims that a well formed access token is expected to carry.
# Names come from RFC 7519 section 4.1.
_DEFAULT_REQUIRED = ("exp", "iat", "iss", "sub", "aud")

# Algorithms this policy is willing to see. `none` is intentionally absent, so a
# token that declares it becomes a finding rather than a silent pass.
_DEFAULT_ALLOWED_ALGS = ("HS256", "HS384", "HS512", "RS256", "RS384", "RS512")


@dataclass(frozen=True)
class Policy:
    """The expectations a token set is audited against.

    max_lifetime_seconds:  largest allowed span from iat (or nbf) to exp.
    required_claims:       claims that must be present and well formed.
    allowed_algs:          the `alg` values considered acceptable.
    clock_skew_seconds:    tolerance applied when judging nbf and exp so that a
                           token a few seconds out of range is flagged as a
                           skew hazard rather than a hard failure.
    key_rotation:          when True, a token is expected to carry a `kid`
                           header so a rotating key set can select the key.
    max_payload_bytes:     largest acceptable decoded payload size.
    """

    max_lifetime_seconds: int = 3600
    required_claims: tuple[str, ...] = field(default_factory=lambda: _DEFAULT_REQUIRED)
    allowed_algs: tuple[str, ...] = field(
        default_factory=lambda: _DEFAULT_ALLOWED_ALGS
