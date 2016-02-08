<div align="center">
  <img src="docs/assets/logo.svg" width="180" alt="TokenScope wordmark, the token morpheme in ink and the scope morpheme in amber, over the tagline JWT and JWS structural auditor">
  <h1>TokenScope</h1>
</div>

<details>
<summary>Full audit of the bundled token set</summary>

```
$ PYTHONPATH=src python -m tokenscope audit samples/tokens.txt
tokenscope audit
source: samples\tokens.txt
tokens: 6
now:    1767225600
policy:
  max_lifetime_seconds: 3600
  clock_skew_seconds:   60
  key_rotation:         yes
  max_payload_bytes:    4096
  required_claims:      exp, iat, iss, sub, aud
  allowed_algs:         HS256, HS384, HS512, RS256, RS384, RS512

token[0] alg=HS256 findings=1
  [HIGH] TS004 HMAC alg HS256 under a policy that also allows RSA: algorithm confusion risk if an RSA public key is used as the HMAC secret
token[1] alg=none findings=1
  [HIGH] TS002 alg is 'none': token is unsecured and any signature is ignored
token[2] alg=HS256 findings=2
  [HIGH] TS004 HMAC alg HS256 under a policy that also allows RSA: algorithm confusion risk if an RSA public key is used as the HMAC secret
  [HIGH] TS008 token expired at 1767222000, before now 1767225600 (skew 60)
token[3] alg=HS256 findings=2
  [HIGH] TS004 HMAC alg HS256 under a policy that also allows RSA: algorithm confusion risk if an RSA public key is used as the HMAC secret
  [MEDIUM] TS006 required claim 'aud' is missing
token[4] alg=HS256 findings=2
  [HIGH] TS004 HMAC alg HS256 under a policy that also allows RSA: algorithm confusion risk if an RSA public key is used as the HMAC secret
  [HIGH] TS011 lifetime 2592060 s exceeds policy maximum 3600 s
token[5] alg=HS256 findings=2
  [HIGH] TS000 decode error: payload is not valid JSON: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)
  [HIGH] TS004 HMAC alg HS256 under a policy that also allows RSA: algorithm confusion risk if an RSA public key is used as the HMAC secret

summary:
  high:  9
  medium: 1
  low:   0
  info:  0
  total: 10
```

</details>

TokenScope is an offline structural auditor for JSON Web Tokens (JWT) and their
signed form (JWS) in compact serialization. It reads a file of tokens, decodes
the header and claims without trusting a single value in them, and reports the
weaknesses it can prove from the bytes alone. It verifies HMAC signatures when
you supply the shared secret, and it says plainly when it cannot verify an
asymmetric signature rather than pretending the token is sound.

The whole tool is Python 3.11 and the standard library. It opens no sockets,
resolves no names, and runs no subprocesses. You can point it at a token dump
from a log, a fixture set in a test suite, or a paste from an incident, and it
will produce the same lines every time.

## The problem

A JWT looks trustworthy because it is signed, and that appearance is exactly
the trap. The three base64url segments are readable by anyone, and most of the
danger in a token lives in fields that are perfectly valid JSON: an `alg` header
that says `none`, an `exp` that is years away, an `aud` that is missing so the
token is accepted by a service it was never minted for. None of these are
decode errors. A parser that only asks "did this decode" will pass them all.

The other classic trap is who verifies the signature and how. A server that
accepts both RSA and HMAC can be tricked: hand it a token whose header claims
HMAC, and if the code path feeds the RSA public key (which is not secret) into
an HMAC verifier, the public key becomes the shared secret and the attacker can
forge tokens at will. You cannot see this from a single token, but you can see
the precondition: an HMAC token sitting in a set whose policy also permits RSA.

