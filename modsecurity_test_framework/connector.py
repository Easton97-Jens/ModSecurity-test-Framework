"""Run the admitted connector suite against an explicitly selected checkout.

Example::

    python -m modsecurity_test_framework.connector \
        --connector-root /work/connector --connector-revision <exact-sha> \
        --test-root /work/framework --profile nginx-native \
        --output-root /work/results --group nginx --check

Framework self-tests do not invoke this adapter or require a Connector checkout.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
import subprocess
import sys
from typing import Iterator

from .connector_context import ConnectorContext, ContextError, framework_revision


_INPUTS = {
    "connector_root": "CONNECTOR_ROOT",
    "connector_revision": "CONNECTOR_REVISION",
    "test_root": "TEST_ROOT",
    "profile": "CONNECTOR_TEST_PROFILE",
    "output_root": "CONNECTOR_TEST_OUTPUT_ROOT",
}


@contextmanager
def _selected_environment(values: dict[str, str]) -> Iterator[None]:
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    for argument, variable in _INPUTS.items():
        parser.add_argument("--" + argument.replace("_", "-"), default=os.environ.get(variable),
                            help=f"explicit invocation value; alternatively set {variable}")
    return parser


def _run_engine(context: ConnectorContext, arguments: list[str], environment: dict[str, str]) -> int:
    command = [sys.executable, "-P", "-m", "modsecurity_connector_ci.lib.active_test_inventory",
               "--output-root", str(context.output), *arguments]
    result = subprocess.run(command, cwd=context.connector, env=environment, check=False)
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


def main(argv: list[str] | None = None) -> int:
    """Validate provenance first, then start the uniquely named Framework engine."""
    parser = build_parser()
    known, arguments = parser.parse_known_args(argv)
    selected = {variable: value for argument, variable in _INPUTS.items()
                if (value := getattr(known, argument)) is not None}
    try:
        with _selected_environment(selected):
            context = ConnectorContext.from_environment()
            tests_revision = framework_revision()
            environment = dict(os.environ)
        environment.update(
            CONNECTOR_ROOT=str(context.connector), CONNECTOR_REVISION=context.revision,
            TEST_ROOT=str(context.tests), FRAMEWORK_ROOT=str(context.tests),
            FRAMEWORK_REVISION=tests_revision,
            CONNECTOR_TEST_PROFILE=context.profile, CONNECTOR_TEST_OUTPUT_ROOT=str(context.output),
            PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1", PYTHONSAFEPATH="1",
            PYTHONPATH=os.pathsep.join((str(context.tests), str(context.tests / "connector_suite"))),
        )
        return _run_engine(context, arguments, environment)
    except (ContextError, OSError, subprocess.SubprocessError) as error:
        print(f"CONNECTOR_TEST_REJECTED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
