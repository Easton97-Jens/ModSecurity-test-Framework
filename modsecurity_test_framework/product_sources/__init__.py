"""Explicitly selected product subjects, isolated from global Python lookup.

Only an explicit test import enters this namespace. Product sources never
become Python search roots for the Framework or the standard library.
"""
from ..connector_context import connector_root

__path__ = [str(connector_root())]
