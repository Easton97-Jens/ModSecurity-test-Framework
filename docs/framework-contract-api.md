# Framework contract API

**Language:** English | [Deutsch](framework-contract-api.de.md)

modsecurity_test_framework.contracts is the supported public boundary for a
consumer that needs Framework test inventory, selection, scenario metadata,
typed expectations, result validation, or the five-connector CRS profile. It
replaces direct file loading of ci/checks/catalog/*.py; a consumer does not
need to mutate sys.path, import a private sibling module, or run from the
Framework checkout.

## Install and import

Install a Framework checkout or a built wheel into the consumer environment:

    python3 -m pip install /path/to/ModSecurity-test-Framework

Then import the public module:

    from modsecurity_test_framework.contracts import (
        describe_test,
        load_capability_manifest,
        load_profile_contract,
        load_test_catalog,
        normalize_expectation,
        select_tests,
        validate_test_result,
    )

The package uses a dependency-free PEP 517 build backend and bundles a
payload-free contract catalog. framework_commit is read from a source checkout
when available; a wheel records the source commit during its build. If neither
exists, the field is "unavailable" rather than a guessed value.

## Operations

| Operation | Purpose |
|---|---|
| load_test_catalog(catalog=..., profile=...) | Returns canonical metadata for package-owned No-CRS and YAML case sources. |
| load_capability_manifest(source) | Validates a mapping or a bounded relative JSON capability file. |
| select_tests(manifest, ...) | Applies declared capability states and returns selected IDs plus all selection states. |
| describe_test(id) | Returns one canonical scenario record. |
| normalize_expectation(value) | Validates and canonicalizes the closed tagged expectation union. |
| validate_test_result(id, result) | Validates a bounded, payload-free result mapping against that test's expectation. |
| load_profile_contract(name) | Returns a fixed public profile such as five-connectors-with-crs-no-mrts. |

Inventory and selection responses include schema_version, framework_commit,
profile/catalog context, identifiers, expectation type, and applicable
scenario metadata. A scenario record includes framework_test_id, display_name,
declared scenario_category when one exists, phase, area, profile,
required_capabilities, expectation, and applicability. Categories are copied
only from declared Framework metadata; they are never derived from a CRS rule
ID, rule message, log content, or path.

The no-crs-baseline catalog view preserves its 166 declared catalog records.
The framework-yaml view exposes the checked-in YAML corpus. When a YAML file is
the materialized source of the same generic No-CRS case, the package records
both sources under one canonical test identity instead of inventing a
duplicate. Connector-specific source cases remain distinct where their
declared connector applicability makes them distinct tests.

## Typed expectations

The union is closed. Unknown kinds, unexpected fields, malformed identifiers,
duplicate rule IDs, and booleans in integer fields are contract errors.

| Kind | Required structured fields |
|---|---|
| http_status | http_status (100–599) |
| intervention | action, optionally http_status and rule_ids |
| action | action, optionally rule_ids |
| rule_match | rule_ids |
| event | fields and/or a bounded event_type identifier |
| request_headers / response_headers | Header names, never header values |
| request_body / response_body | A bounded body state, never body content |
| transport | A declared transport state |
| lifecycle | Explicit Boolean predicates |
| cleanup | A declared cleanup state |
| compound | Two or more explicit typed conditions |
| not_applicable | A closed applicability reason |

Only http_status and intervention can carry an HTTP status. Actions, events,
body states, transport, lifecycle, cleanup, and applicability are not silently
converted into synthetic HTTP values.

## JSON-only CLI

After installation, the module works from any working directory:

    python3 -m modsecurity_test_framework.contracts inventory --catalog no-crs-baseline
    python3 -m modsecurity_test_framework.contracts select --capabilities capabilities.json
    python3 -m modsecurity_test_framework.contracts describe --test-id no-crs-baseline:allow_without_marker
    python3 -m modsecurity_test_framework.contracts validate --test-id no-crs-baseline:allow_without_marker --result result.json

Every command writes exactly one JSON object to standard output. Successful
commands exit 0. A contract or argument violation exits 2 and emits only a
stable error code in JSON; no exception text, absolute host path, request or
response payload, credential, or secret is included. Other internal failures
exit 1 with internal_error.

The --capabilities and --result options deliberately accept only relative,
regular, non-symlink JSON files. The reader rejects absolute, empty, dot,
double-separator, and backslash path aliases; traversal; intermediate or final
symlinks; special files; duplicate JSON keys; oversized documents; and
malformed UTF-8 before processing input. This is an explicit caller input
boundary, not a dependency on the Framework current working directory.

## Catalog maintenance and compatibility

The package resource is generated from checked-in catalog/YAML sources without
copying rules, header values, request bodies, response bodies, raw logs, or
absolute paths:

    python3 ci/tools/generate-framework-contract-catalog.py
    make check-framework-contract-catalog
    make test-contract-api

The generator fails on ambiguous identities or invalid source metadata. It is
checked by the API target, so a case-source change cannot silently leave the
public inventory stale. Its optional output path is also opened through a
descriptor-based no-follow walk under the physical Framework root and atomically
replaced; a symlinked output parent is rejected.

Existing entry points remain supported:

    python3 ci/checks/catalog/no_crs_baseline.py ...
    python3 ci/checks/catalog/five_connectors_with_crs_no_mrts.py ...

The five-connector legacy script now supplies its own fixed Framework sibling
lookup for direct-file compatibility. New consumers should still use the
public package rather than relying on that legacy implementation detail.
