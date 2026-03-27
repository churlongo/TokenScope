"""Strict base64url decoding with padding repair and honest error reporting.

JWT segments are base64url encoded without padding (RFC 7515, appendix C). This
module decodes a segment while reporting every deviation it had to tolerate, so
the auditor can distinguish a clean token from one that is merely close.

The decoder never raises for malformed input. It returns a Decoded result whose
`ok` flag says whether decoding succeeded, and whose `error` string explains the
first problem found. This lets the caller keep auditing the rest of a token set
rather than aborting on the first bad segment.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

# The base64url alphabet from RFC 4648 section 5, without padding.
_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_"
)


@dataclass(frozen=True)
class Decoded:
    """Result of decoding one base64url segment.

    ok:            True when the bytes were recovered.
    data:          the decoded bytes, empty when ok is False.
    padding_added: number of '=' characters the decoder had to supply.
    error:         first problem found, or empty string when ok.
    """

    ok: bool
    data: bytes
    padding_added: int
    error: str


def _find_bad_char(segment: str) -> str:
    for ch in segment:
        if ch not in _ALPHABET:
            return ch
    return ""


def decode_segment(segment: str) -> Decoded:
    """Decode one base64url segment, repairing missing padding.

    A correct JWT segment carries no '=' padding and no characters outside the
    base64url alphabet. This function accepts a segment that is missing its
    padding (the normal JWT case) and records how many pad characters it added.
    It rejects a segment that contains a standard base64 character (`+` or `/`),
    padding in the middle, or any other stray byte, and reports which character
    was at fault.
    """
    if segment == "":
        return Decoded(ok=False, data=b"", padding_added=0, error="empty segment")

    # A segment length of 1 mod 4 can never be valid base64.
    if len(segment) % 4 == 1:
        return Decoded(
            ok=False,
            data=b"",
            padding_added=0,
            error="invalid length: %d characters is never valid base64url"
            % len(segment),
        )

    bad = _find_bad_char(segment)
    if bad != "":
        if bad in "+/":
            return Decoded(
                ok=False,
                data=b"",
                padding_added=0,
                error="standard base64 character %r found; expected base64url"
                % bad,
            )
        if bad == "=":
            return Decoded(
                ok=False,
                data=b"",
                padding_added=0,
                error="unexpected padding character '=' inside segment",
            )
        return Decoded(
            ok=False,
            data=b"",
            padding_added=0,
            error="character %r is not in the base64url alphabet" % bad,
        )

    pad_needed = (-len(segment)) % 4
    padded = segment + ("=" * pad_needed)
    try:
        data = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        return Decoded(
            ok=False,
            data=b"",
            padding_added=0,
            error="base64 decode failed: %s" % exc,
        )
    return Decoded(ok=True, data=data, padding_added=pad_needed, error="")
