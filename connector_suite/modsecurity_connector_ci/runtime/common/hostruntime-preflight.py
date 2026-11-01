#!/usr/bin/env python3
"""Compatibility entry point used by connector workflows."""

from modsecurity_connector_ci.runtime.common.hostruntime_preflight import main


if __name__ == "__main__":
    raise SystemExit(main())
