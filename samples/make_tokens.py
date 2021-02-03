"""Generate the bundled test-vector tokens with genuine HMAC signatures.

Run from the project root with the package on the path:

    PYTHONPATH=src python samples/make_tokens.py

This writes samples/tokens.txt. The signing secret is a published test vector
from RFC 7515 appendix A.1 (the octets of the ASCII string below), so the
signatures are real and reproducible, not placeholders. Times are fixed relative
to the auditor's default reference time so the audit output is deterministic.
"""

from __future__ import annotations

import base64
