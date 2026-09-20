# Cookbook: auditing tokens in CI

Keep the audit reproducible by writing tokens to a file and pinning the clock.

## 1. Write the token set

One token per line, comments allowed with `#`. Keep the file out of git when
it holds production values; the sample flow here uses the bundled set.

## 2. Audit against a fixed instant

```
python -m tokenscope audit tokens.txt --now 1767225600
```

The `--now` value keeps expiry findings stable between runs, which is what
makes a report attachable to a change request.

## 3. Fail the job on findings

Exit code 1 means findings, 2 means usage error. Treat them differently: a 2
is a broken job, a 1 is a token to fix.

## 4. Keep the coverage line

The coverage summary is the cheapest early warning for a token minted with a
different claim set than the API expects.
