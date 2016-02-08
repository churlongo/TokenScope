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
