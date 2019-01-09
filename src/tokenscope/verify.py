"""Signature verification, limited to HMAC and honest about the rest.

This module verifies the HMAC family (HS256, HS384, HS512) using the standard
library only, comparing the recomputed MAC with hmac.compare_digest so the
comparison runs in constant time. It refuses to pretend it can check RSA or
ECDSA signatures, because doing that correctly needs big-integer modular
arithmetic and curve maths that are not implemented here. For asymmetric
algorithms it returns a clear "unsupported" verdict rather than a false pass.
