"""Public source-checkout namespace for Framework-owned support modules."""
from importlib.resources import files

_framework = files("modsecurity_test_framework").parent
__path__ = [str(_framework / "ci" / "lib"), str(_framework / "ci" / "tools")]
