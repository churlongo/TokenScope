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

