"""Command line interface for tokenscope.

Subcommands:

    inspect  decode each token and print its header and payload, no judgement
    audit    apply the policy and print findings per token, exit 1 on findings
    verify   verify HMAC signatures with a supplied secret, exit 1 on failures
    version  print the package version

Exit codes: 0 clean, 1 findings present, 2 usage error. argparse itself exits
with 2 on argument errors, which matches the standard.

Determinism: the auditor never reads the wall clock. The reference time used for
claim checks is taken from --now, which defaults to a fixed recorded epoch so
that a run is byte-for-byte reproducible. The chosen value is printed in the
audit header.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__, claims, decode, report
from .policy import DEFAULT_POLICY
from .verify import VALID, UNSUPPORTED, verify

# Fixed reference time so audit output is reproducible without the wall clock.
# 2026-01-01T00:00:00Z. Recorded in the audit header on every run.
DEFAULT_NOW = 1767225600


def _read_tokens(path: str) -> tuple[list[str], str | None]:
    """Read a token file, one token per non-empty, non-comment line.

    Returns (tokens, error). Lines beginning with '#' are treated as comments.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw_lines = handle.read().splitlines()
    except OSError as exc:
        return [], "cannot read %s: %s" % (path, exc)
