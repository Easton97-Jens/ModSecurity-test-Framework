"""Public interfaces for the ModSecurity test Framework.

Use :mod:`modsecurity_test_framework.contracts` for the stable API.  Keeping
the package initializer free of eager imports also makes ``python -m`` execute
the contracts module without a runtime-warning side channel.
"""

__all__: tuple[str, ...] = ()
