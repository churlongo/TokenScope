# Recipes: running the audit in CI

```yaml
name: token-audit
on:
  pull_request:
    paths:
      - "tokens/**"
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: PYTHONPATH=src python -m tokenscope audit tokens/known.txt --now 1767225600
```

The job fails on findings by design. Pair it with a scheduled run weekly so
tokens that expire between changes are still caught.
