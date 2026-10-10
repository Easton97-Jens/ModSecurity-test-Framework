# Change record

**Language:** English | [Deutsch](20261008-26-nginx-explicit-native-authority.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-26-nginx-explicit-native-authority |
| UTC date | 2026-10-08 |
| Framework base revision | `fd928ad7f7d864048a065106f17a7af2f6ba4a52` |

## Motivation and problem statement

Native operation receipts must not supply their own trusted build/source digests. An explicitly selected local authority file needs strict loading and original-byte preservation before the coordinator passes its context to the native bundle reader.

## Affected components and security boundaries

New Framework authority helper, focused tests and this paired record only. Parent authority producer, central validator/schema/CLI/normalizer, retention writes, Git state checks, MRTS and Gitlinks remain outside this slice.

## Acceptance criteria

Require an explicit exact run/Parent/Framework/MRTS tuple and closed schema1 nginx metadata. Reject unsafe/missing roots, aliases, artifact/source overlap, writable or foreign-owned files/directories, symlink components, hard links, nonregular or oversized files, duplicate/nonfinite JSON and malformed digests. Preserve legitimate Framework nesting beneath Parent. Return immutable context and original bytes/hash without writes or path fallback.

## Alternatives considered

Deriving expected authority from an operation receipt, inferring current revisions or defaulting to a fixed Framework directory would bypass explicit source selection. Reserializing metadata cannot preserve its original byte seal.

## Implementation decision

`load_native_operation_authority(path, expected)` reads at most16384 bytes through the strict no-follow/owned/single-link/regular/stable reader. Expected has exactly run_id and the three exact40 revisions. Metadata has exactly schema_version, connector, run_id, explicit artifact/Parent/Framework roots, those revisions, binary/module SHA256 and the closed selected-fault digest map. Roots must exist, be distinct actual directories and be owned without group/world write. Artifacts cannot overlap source checkouts; source nesting is permitted.

Returned mappings are recursively read-only. `dict(result['sources'])` supplies the existing reader's concrete coordinator dictionary. `authority_bytes` and `authority_sha256` preserve the exact original file for coordinator-owned verified retention. `serialized_mapping(result)` returns a fresh plain schema1 mapping after checking original-byte and metadata bindings; it writes nothing and is not a new seal.

## Changed files and tests

`tests/runners/nginx_native_operation_authority.py`, `tests/no_crs/test_nginx_native_operation_authority.py` and this record pair. Nine focused tests cover exact bindings, nested source boundaries, immutable/copy behavior, retained originals and negative file/JSON/path/digest controls. Fixtures are local unit inputs, not native build or runtime authority.

## Commands and results

Test-first missing-module RED was observed, followed by nine focused authority tests passing. The owning Framework Python passed48 authority/reader/projection/registry tests. Repository-native `make test-no-crs-contract` passed all309 tests; `make check-documentation` and staged whitespace checks passed. Exact commands and external logs are retained in the handoff. RTK wrapped every shell command.

## Security impact

No digest, revision or root is derived from candidate receipts. Every authority field is closed and typed; compiled fixture map keys are restricted to the eight actual fault cases. Empty fault maps permit non-fault operations only; the bundle reader still requires a selected compiled fault digest for fault cases. Foreign owner checks use actual descriptors with controlled metadata in unit tests, since ownership changes are unsupported in the managed test filesystem.

## Documentation and runtime evidence

This loader verifies the selected local manifest boundary only. Root still establishes actual producer/build/Git/run authority, checks snapshot digests through the bundle reader and performs secure retained copying. Original bytes must be retained unchanged and rechecked, not replaced with serialized_mapping output.

## Checks not run

No native build/E2E/runtime. No Git cleanliness or Gitlink inference. Ruff unavailable and not installed; no remote SonarQube closure claim.

## Limitations and residual risk

A matching local manifest alone does not prove trusted build provenance. Explicit file selection and expected tuple belong to the coordinator, not the receipt. Root/source paths are validated at load time; later artifact and source reads must still use the strict reader, and retention must compare the original seal.

## Final diff and review status

Focused four-file authority slice only. No status/PASS promotion, receipt mutation, central policy/schema changes or arbitrary root fallback.
