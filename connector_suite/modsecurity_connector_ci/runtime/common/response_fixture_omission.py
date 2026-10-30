"""Closed opt-in omission for the genuine missing Content-Type fixture.

Default response metadata is unchanged unless the case explicitly requests the
one supported omission. No framing/security header suppression is authorized.
"""
from collections.abc import Iterable


def validate_omitted_headers(value: object, configured_names: Iterable[str]) -> tuple[str, ...]:
    """Validate independent omission metadata against configured header names."""
    if not isinstance(value, list) or value not in ([], ["Content-Type"]):
        raise ValueError("omit_headers must be [] or exactly ['Content-Type']")
    if value and any(name.lower() == "content-type" for name in configured_names):
        raise ValueError("omitted Content-Type must not also be configured, even empty")
    # This API returns an immutable collection, not a fixed-arity tuple record.
    return tuple(name.lower() for name in value)
