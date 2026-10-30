"""Public source-checkout namespace for Framework result normalizers."""
from importlib.resources import files

__path__ = [str(files("modsecurity_test_framework").parent / "tests" / "normalizers")]
