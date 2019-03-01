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
    tokens = []
    for line in raw_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        tokens.append(stripped)
    return tokens, None


def _cmd_inspect(args: argparse.Namespace) -> int:
    tokens, error = _read_tokens(args.file)
    if error is not None:
        print("error: %s" % error, file=sys.stderr)
        return 2
    for index, raw in enumerate(tokens):
        token = decode.decode_token(raw)
        for line in report.render_inspect(index, token):
            print(line)
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    tokens, error = _read_tokens(args.file)
    if error is not None:
        print("error: %s" % error, file=sys.stderr)
        return 2
    policy = DEFAULT_POLICY
    now = args.now
    for line in report.render_audit_header(policy, now, args.file, len(tokens)):
        print(line)
    total = 0
    by_severity: dict[str, int] = {}
    for index, raw in enumerate(tokens):
        token = decode.decode_token(raw)
        findings = claims.audit_claims(token, policy, now)
        total += len(findings)
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        for line in report.render_audit_token(index, token, findings):
            print(line)
    for line in report.render_audit_summary(total, by_severity):
        print(line)
    return 1 if total else 0


def _cmd_verify(args: argparse.Namespace) -> int:
    tokens, error = _read_tokens(args.file)
    if error is not None:
        print("error: %s" % error, file=sys.stderr)
        return 2
    secret = args.secret.encode("utf-8")
    failures = 0
    for index, raw in enumerate(tokens):
        token = decode.decode_token(raw)
        verdict = verify(token, secret)
        for line in report.render_verify(index, token, verdict):
            print(line)
        # A failure to confirm a signature counts as a finding, except the
        # honest "unsupported" verdict for asymmetric algorithms, which is a
        # limitation of this tool rather than a fault in the token.
        if verdict.status not in (VALID, UNSUPPORTED):
            failures += 1
    return 1 if failures else 0


def _cmd_version(args: argparse.Namespace) -> int:
    print("tokenscope %s" % __version__)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tokenscope",
        description="Offline structural auditor for JWT and JWS tokens.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser(
