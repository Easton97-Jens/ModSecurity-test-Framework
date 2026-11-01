"""Public source-checkout namespace for Framework runner implementations."""
from importlib.resources import files

__path__ = [str(files("modsecurity_test_framework").parent / "tests" / "runners")]
