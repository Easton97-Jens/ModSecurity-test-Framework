"""Public source-checkout namespace for explicitly selected Framework self-tests."""
from importlib.resources import files

__path__ = [str(files("modsecurity_test_framework").parent / "tests")]
