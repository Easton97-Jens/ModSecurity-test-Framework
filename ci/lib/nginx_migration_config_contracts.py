"""Closed NGINX Engine-lexical and removed-directive configuration contracts.

The status case does not define a numeric range. The scope-file cases test
rejection of the removed adapter API, not parsing of MIME policy by the Engine.
The coordinator binds these declarations to actual retained host operations.
"""

from copy import deepcopy


_CONTRACTS = {
    "invalid_status": {
        "operation": "configtest",
        "directive": "modsecurity_rules",
        "value": 'SecRule REQUEST_URI "@unconditionalMatch" "id:1100901,phase:1,deny,status:not-a-number"',
        "expected_exit_code": 1,
        "expected_outcome": "config_rejected",
        "error_class": "invalid_status",
        "diagnostic_fragments": ['"modsecurity_rules" directive Rules error',
                                 "Expecting an action, got:  status:not-a-number"],
    },
    "phase4_invalid_scope_file": {
        "operation": "configtest",
        "directive": "modsecurity_phase4_content_types_file",
        "value": "invalid-content-type-scope.txt",
        "expected_exit_code": 1,
        "expected_outcome": "config_rejected",
        "error_class": "phase4_invalid_scope_file",
        "diagnostic_fragments": ['unknown directive "modsecurity_phase4_content_types_file"'],
    },
    "phase4_wildcard_scope_rejected": {
        "operation": "configtest",
        "directive": "modsecurity_phase4_content_types_file",
        "value": "wildcard-content-type-scope.txt",
        "expected_exit_code": 1,
        "expected_outcome": "config_rejected",
        "error_class": "phase4_wildcard_scope_rejected",
        "diagnostic_fragments": ['unknown directive "modsecurity_phase4_content_types_file"'],
    },
}


def nginx_migration_config_contracts() -> dict[str, dict[str, object]]:
    """Return independent declarations for exactly three authorized cases."""
    return deepcopy(_CONTRACTS)
