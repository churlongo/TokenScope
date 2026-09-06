# Contributing to TokenScope

Thanks for taking the time to contribute.

## Setup

```
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

The project is standard library only at runtime. If a change needs a third
party runtime dependency, it is out of scope by design.

## Running the checks

```
python -m unittest discover -s tests -v
```

There is no separate verify script yet; the test suite is the gate.

## What a good change looks like

- One topic per commit, conventional prefix (`fix:`, `feat:`, `docs:`, `test:`).
- Tests for behavior changes. A bug fix without a regression test is incomplete.
- No network access anywhere in the code. Offline execution is a hard rule.
- Deterministic output: identical input must produce byte identical output.
- Keep the output line oriented so reports diff cleanly in git.
- No em dashes anywhere. Use a comma, colon, or parentheses.

## Pull requests

Fill in the pull request template. Small, focused changes are reviewed fastest.
If a change alters output, include the before and after in the description.
