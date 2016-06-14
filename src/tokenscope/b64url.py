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
