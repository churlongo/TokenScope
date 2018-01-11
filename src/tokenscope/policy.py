"""Declared audit policy: the rules a token set is measured against.

A policy is a set of expectations the operator declares up front, separate from
whatever a token happens to assert. Keeping the policy in one place means the
auditor never has to guess what "too long" or "wrong algorithm" means; the
answer is stated once and applied uniformly.

The default policy below is conservative and is used when the CLI is run without
a policy file. It is deliberately strict so that a clean result means something.
"""

from __future__ import annotations

