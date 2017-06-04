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

TokenScope exists to make those readable-but-wrong fields loud. It treats the
token as untrusted input, applies a declared policy, and prints one line per
problem so the result diffs cleanly in review.

## Install and run

There is nothing to install beyond Python 3.11. Run it straight from the source
tree with the package on the path.

```
$ PYTHONPATH=src python -m tokenscope version
tokenscope 0.1.0
```

The three working subcommands take a file of tokens, one token per line. Lines
that are blank or begin with `#` are ignored, so the bundled `samples/tokens.txt`
can carry comments describing each vector.

## Subcommands

| Command   | What it does                                              | Exit on issue |
| --------- | --------------------------------------------------------- | ------------- |
| `inspect` | decode header and payload, list present claims, no verdict | always 0     |
| `audit`   | apply the policy, print findings per token                | 1 if findings |
| `verify`  | check HMAC signatures against a supplied secret           | 1 if a check fails |
| `version` | print the package version                                 | 0             |

### inspect

`inspect` is the honest first look. It decodes each token and prints the header
and payload as canonical JSON (keys sorted, compact separators) so two runs
compare byte for byte. It renders no judgement, which makes it the right tool
when you want to see what a token actually contains before deciding anything.

```
$ PYTHONPATH=src python -m tokenscope inspect samples/tokens.txt
token[0]:
  segments: 3
  header: {"alg":"HS256","kid":"key-2026-01","typ":"JWT"}
  payload: {"aud":"api.example","exp":1767229140,"iat":1767225540,"iss":"https://issuer.example","nbf":1767225540,"sub":"user-1001"}
  registered-claims-present: iss, sub, aud, exp, nbf, iat
token[1]:
  segments: 3
  header: {"alg":"none","typ":"JWT"}
  payload: {"aud":"api.example","exp":1767229140,"iat":1767225540,"iss":"https://issuer.example","sub":"user-1002"}
  registered-claims-present: iss, sub, aud, exp, iat
token[2]:
  segments: 3
  header: {"alg":"HS256","kid":"key-2026-01","typ":"JWT"}
  payload: {"aud":"api.example","exp":1767222000,"iat":1767218400,"iss":"https://issuer.example","sub":"user-1003"}
  registered-claims-present: iss, sub, aud, exp, iat
token[3]:
  segments: 3
  header: {"alg":"HS256","kid":"key-2026-01","typ":"JWT"}
  payload: {"exp":1767229140,"iat":1767225540,"iss":"https://issuer.example","sub":"user-1004"}
  registered-claims-present: iss, sub, exp, iat
token[4]:
  segments: 3
  header: {"alg":"HS256","kid":"key-2026-01","typ":"JWT"}
  payload: {"aud":"api.example","exp":1769817600,"iat":1767225540,"iss":"https://issuer.example","sub":"user-1005"}
  registered-claims-present: iss, sub, aud, exp, iat
token[5]:
  segments: 3
  decode-error: payload is not valid JSON: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)
  header: {"alg":"HS256","kid":"key-2026-01","typ":"JWT"}
  payload: {}
  registered-claims-present: none
```

### verify

`verify` recomputes the HMAC over the exact signing input (the header and
payload segments joined by a dot) and compares it with the signature segment
using `hmac.compare_digest`, a constant time comparison. It only handles the
HMAC family. For an asymmetric algorithm it returns `unsupported`, and for an
unsecured `none` token it also returns `unsupported`, because there is no
signature to check. The secret used below is the published test secret shipped
with the samples.

```
$ PYTHONPATH=src python -m tokenscope verify samples/tokens.txt --secret your-256-bit-secret
token[0] alg=HS256 verify=valid
  HMAC HS256 signature verified against supplied secret
token[1] alg=none verify=unsupported
  alg 'none' carries no signature to verify
token[2] alg=HS256 verify=valid
  HMAC HS256 signature verified against supplied secret
token[3] alg=HS256 verify=valid
  HMAC HS256 signature verified against supplied secret
token[4] alg=HS256 verify=valid
  HMAC HS256 signature verified against supplied secret
token[5] alg=HS256 verify=invalid
  HMAC HS256 signature does not match: wrong secret or tampered token
```

Four tokens verify against the real secret, which proves their signatures are
genuine rather than placeholder bytes. Token 5 fails because its payload was
corrupted after signing, so the recomputed MAC no longer matches. The two
`unsupported` lines are honest limits, not passes.

## Output format as a contract

The `audit` output at the top of this page is a stable format. Each field is
defined here so you can parse it or diff it with confidence.

| Line                          | Meaning                                                     |
| ----------------------------- | ----------------------------------------------------------- |
| `source:`                     | the file path passed on the command line                    |
| `tokens:`                     | how many non-comment lines were read                        |
| `now:`                        | the reference Unix time used for every time based check      |
| `policy:` block               | the declared expectations, one field per line               |
| `token[N] alg=A findings=K`   | token index N, its `alg` header, and finding count K         |
| `  [SEV] RULE message`        | one finding: severity, rule id, and the fact that fired it   |
| `summary:` block              | counts per severity and the grand total                     |

Findings are sorted by severity (high, medium, low, info) and then by rule id,
so the same input always yields the same order.

## The findings

| Rule  | Severity | Fires when                                                        |
| ----- | -------- | ----------------------------------------------------------------- |
| TS000 | high     | a structural decode error: bad base64url, non-JSON, wrong shape   |
| TS001 | high     | the header has no `alg`, or `alg` is not a string                 |
| TS002 | high     | `alg` is `none`: the token is unsecured                           |
| TS003 | high     | `alg` is a string but not on the policy allow list                |
| TS004 | high     | an HMAC token exists under a policy that also allows RSA          |
| TS005 | medium   | no `kid` header while the policy declares key rotation            |
| TS006 | medium   | a required registered claim is missing                            |
| TS007 | medium   | a claim has the wrong JSON type (for example `exp` not numeric)   |
| TS008 | high     | `exp` is before now, beyond the skew tolerance: expired           |
| TS009 | low      | `exp` or `nbf` sits inside the skew window: a clock skew hazard    |
| TS010 | medium   | `nbf` is after now, beyond the skew tolerance: not yet valid      |
| TS011 | high     | the lifetime from `iat` (or `nbf`) to `exp` exceeds the maximum   |
| TS012 | medium   | negative lifetime: `exp` precedes the start claim                 |
| TS013 | low      | `iat` is in the future relative to now: a clock hazard            |
| TS014 | low      | the encoded payload is larger than the policy maximum             |

## How to read the report, and what to do

Each finding points at an action, not just a fact.

- TS002 `alg none`: reject the token. An unsecured token should never be
  accepted on an authenticated path. Check why your issuer emitted it.
- TS004 confusion risk: pin your verifier to one algorithm family per key. Do
  not let a single endpoint accept both RSA and HMAC with the same key material.
- TS006 missing claim: decide whether the claim is truly required for this
  audience. A missing `aud` means the token is not scoped to your service.
- TS008 expired: reject. If you see many, your issuer or client clocks may be
  wrong, or lifetimes are too short for the traffic.
- TS011 excessive lifetime: shorten the issuer's token lifetime, or raise the
  policy maximum deliberately and record why.
- TS005 missing `kid`: add a key id at the issuer so a rotating key set can be
  selected without trial verification.

## The algorithm, and the edge case that makes it hard

Decoding a JWT is three base64url decodes and two JSON parses, which sounds
trivial until you meet malformed input. base64url has no padding in a JWT, so
the decoder must add padding back before decoding, and it must reject a segment
that is the wrong length or carries a standard base64 character (`+` or `/`)
rather than the URL safe `-` and `_`. The `b64url` module reports each of these
distinctly so a corrupt token is diagnosed, not just failed.

The genuinely hard part is time. A NumericDate is seconds since the epoch, but
clocks disagree. If a token expired one second ago, is it expired or is your
clock fast? TokenScope answers with a declared skew tolerance: past the skew it
is a hard expiry (TS008), inside the skew it is a hazard (TS009). The same split
applies to `nbf`. Lifetime is measured from `iat` when present, otherwise from
`nbf`, and only when `exp` is also present, because a lifetime needs two ends.

When the data is ambiguous the tool does not guess. A payload that fails to
parse yields a TS000 decode error and the claim checks are skipped, because
there is nothing trustworthy to inspect. That is why token 5 in the bundled set
shows only the decode error and the policy level confusion advisory, and no
claim findings.

## Determinism

The auditor never reads the wall clock. Every time based check uses the `now`
value, which defaults to a fixed recorded epoch (1767225600, that is
2026-01-01T00:00:00Z) and is printed in the audit header. Pass `--now` to audit
against a different reference time. Because the reference is explicit, an audit
of the same file always produces byte-identical output, which is what lets you
commit a run and diff the next one.

## Worked example: token 3

Follow the missing-aud token from bytes to verdict.

1. The line is read from `samples/tokens.txt` and split on the two dots into
   header, payload, and signature segments.
2. Each segment is base64url decoded. `b64url` adds the padding a JWT omits and
   confirms every character is in the URL safe alphabet.
3. The header parses to `{"alg":"HS256","kid":"key-2026-01","typ":"JWT"}` and
   the payload to an object with `iss`, `sub`, `iat`, and `exp`, but no `aud`.
4. `claims` checks the policy required set (exp, iat, iss, sub, aud) against the
   payload and finds `aud` absent, raising TS006 at medium.
5. Because the token is HMAC and the default policy also allows RSA, TS004 fires
   at high as a confusion advisory.
6. `verify` recomputes the HS256 MAC with the published secret and it matches,
   so the signature is genuine even though the claim set is incomplete. A valid
   signature does not make an incomplete token safe, which is the whole point.

## Exit codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| 0    | clean, no findings and no failures |
| 1    | findings present (audit) or a verification failed (verify) |
| 2    | usage error, for example an unreadable file |

## Design decisions

**Verify only HMAC, and say so.** Implementing RSA or ECDSA verification from
the standard library would mean writing modular exponentiation and curve
arithmetic by hand, and getting the padding checks exactly right. Done badly,
that is worse than nothing, because a subtly wrong verifier reports false
confidence. The rejected alternative was to shell out to openssl, which breaks
the offline rule. So the tool verifies HMAC and returns `unsupported` for the
rest, which is a limit stated honestly rather than a risk hidden.

**Confusion risk is a policy property.** TS004 fires on every HMAC token when
the policy allows RSA, even a token that is otherwise clean. The rejected
alternative was to fire only on tokens that look suspicious, but there is no
per-token signal for this attack; the exposure is created by the verifier
configuration, which the policy models. Flagging it uniformly is the honest
choice. Run with an HMAC-only policy to remove the advisory when it does not
apply to your deployment.

**A fixed reference time, not the clock.** Reading the wall clock would make
every audit non-reproducible and every committed run undiffable. The rejected
alternative, reading `time.time()`, was set aside for a recorded `--now` with a
fixed default. This is the single most important decision for using the tool in
CI, where a stable output is the whole value.

**Never trust decoded values.** The decode module returns data, never a
decision. Nothing in the pipeline acts on a claim before the policy has judged
it. This is why a `none` token is decoded and reported rather than shortcut, and
why a corrupt payload still yields a report instead of an exception.

## Repository layout

```
tokenscope/
  README.md                     this file
  LICENSE                       MIT, holder "the tokenscope authors", 2026
  CHANGELOG.md                  release notes
  pyproject.toml                setuptools, src layout, console script
  .gitignore                    ignore caches and build output
  src/tokenscope/
    __init__.py                 package version
    __main__.py                 enables python -m tokenscope
    cli.py                      argparse subcommands and exit codes
    b64url.py                   strict base64url decode with padding repair
    decode.py                   header and payload decode, never trusting values
    claims.py                   registered claim validation and findings
    policy.py                   declared maximum lifetime, required claims, algs
    verify.py                   HMAC verification with hmac.compare_digest
    report.py                   line-oriented rendering of results
  tests/
    test_tokenscope.py          unittest suite for every module and the CLI
  samples/
    README.md                   how the vectors were built, and the test secret
    make_tokens.py              generates genuine signed tokens
    tokens.txt                  the six committed test vectors
  docs/assets/
    logo.svg                    wordmark, morpheme colour split
    claim-coverage.svg          claim presence and fired findings per token
```

## The claim coverage diagram

![Matrix of the six bundled tokens showing which registered claims are present per token and which finding rule ids fired, from a real audit run](docs/assets/claim-coverage.svg)

Every filled cell, dash, and rule id in that graphic comes from the `audit` and
`inspect` runs shown above, at the same reference time. It is a picture of this
repository's real output, not an illustration.

## Glossary

- **JWT**: JSON Web Token, a set of claims encoded as three base64url segments.
- **JWS**: JSON Web Signature, the signed structure a signed JWT uses.
- **claim**: a name and value in the payload, such as `sub` or `exp`.
- **registered claim**: a claim with a standard meaning from RFC 7519, such as
  `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`.
- **NumericDate**: a claim value that is seconds since the Unix epoch.
- **alg**: the header field naming the signing algorithm.
- **kid**: the header field naming which key signed the token.
- **signing input**: the header and payload segments joined by a dot, the exact
  bytes a signature covers.
- **clock skew**: the tolerance applied to time checks so a small clock
  difference is a hazard rather than a hard failure.
- **algorithm confusion**: an attack where an HMAC token is verified with an RSA
  public key used as the shared secret.

## Verification

The suite is stdlib `unittest`, 28 tests covering base64url edge cases, decode
behaviour, every finding rule, HMAC verification including the wrong-secret and
unsupported cases, report rendering, and the CLI exit codes.

```
$ PYTHONPATH=src python -m unittest discover -s tests -v
...
Ran 28 tests in 0.007s

OK
```

## Integration notes

In CI, run `audit` over your token dump and let the exit code gate the job:
exit 1 means findings, exit 0 means clean. Because output is deterministic, you
can commit a baseline audit and diff a later run in git to see exactly which
findings appeared or cleared. The `--now` flag lets a CI job pin the reference
time so a token that expires between runs does not flip the result unexpectedly.

## Limitations

This tool does what it can prove and stops there.

- It verifies only the HMAC family (HS256, HS384, HS512). It does not verify
  RSA or ECDSA signatures and returns `unsupported` for them, because a correct
  asymmetric verifier is not implemented here.
- It cannot tell you whether a signature is valid for an `alg none` token,
  because there is no signature.
- It does not fetch keys, JWKS documents, or any network resource. Key rotation
  is judged only by the presence of a `kid` header, not by resolving the key.
- It does not decrypt JWE (encrypted tokens). It handles signed and unsecured
  compact tokens only.
- It does not validate claim values against a schema beyond type and time
  checks. It will not tell you that an `iss` is the wrong issuer, only that it
  is present and a string.
- The confusion advisory (TS004) is a policy level signal, not proof that a
  specific verifier is misconfigured. It marks the precondition.

## Roadmap

Without promising dates:

- An optional policy file so required claims, allowed algorithms, and limits can
  be declared per project rather than using the built in default.
- A JSON output mode alongside the line-oriented text, for machine consumers.
- Recognition of JWE compact serialization so an encrypted token is reported as
  out of scope rather than as a decode error.

## License

MIT. See [LICENSE](LICENSE). The samples are test vectors signed with a public
secret documented in [samples/README.md](samples/README.md).

<!-- draft note 169 -->
