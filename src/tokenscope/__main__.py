"""Module entry point so `python -m tokenscope` works."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
