"""Public source-checkout namespace for Framework-owned support modules."""
from importlib.resources import files

__path__ = [str(files("modsecurity_test_framework").parent / "ci" / "lib")]
