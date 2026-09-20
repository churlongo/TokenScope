# FAQ

**Does TokenScope verify signatures?**
No. It audits structure and claims offline. Verification needs the key and a
trust decision, which is out of scope for a structural auditor.

**Why pin the clock?**
Expiry findings depend on the instant of the audit. `--now` makes a report
reproducible, which matters when it is attached to a review.

**What formats are supported?**
Compact JWT and JWS strings, one per line. The decoder accepts padded and
unpadded base64url segments.
