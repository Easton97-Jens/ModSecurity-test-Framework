#!/usr/bin/env python3
"""Compatibility entrypoint for the public explicit-checkout Framework CLI."""
from modsecurity_test_framework.connector import main


if __name__ == "__main__":
    raise SystemExit(main())
