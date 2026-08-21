# Change records

**Language:** English | [Deutsch](README.de.md)

This directory holds paired English/German records for non-trivial Framework
changes. It is intentionally separate from connector-produced `reports/testing`
output and from any parent repository audit path.

Use [the English template](TEMPLATE.md) and its
[German counterpart](TEMPLATE.de.md). Keep both record files synchronized with
the final Framework diff, and keep evidence payload-free and redacted as
described in [change traceability](../../../docs/change-traceability.md).

## Current records

- [Fix inherited-upstream snapshot re-entry (2026-08-21)](20260821-02-fix-inherited-upstream-snapshot-reentry.md)
- [Remediate Traefik runtime pin divergence (2026-08-14)](20260814-01-remediate-traefik-runtime-pin-divergence.md)
- [Add five-connector With-CRS/No-MRTS evidence contract (2026-08-10)](20260810-01-add-five-connectors-with-crs-no-mrts-contract.md)
- [Allow only canonical empty CRS `.gitmodules` provenance metadata (2026-08-09)](20260809-02-allow-exact-empty-crs-gitmodules-provenance.md)
- [Fix Common-version post-apply test-fixture invariance (2026-08-09)](20260809-01-fix-common-version-post-apply-test-invariance.md)
- [Migrate the Common-version publisher to a GitHub App token (2026-08-08)](20260808-02-migrate-common-version-publisher-app-token.md)
- [PR #50 CI and SonarQube Cloud follow-up (2026-07-26)](20260726-04-remediate-pr50-ci-sonar-followup.md)
- [Restore exact ModSecurity v3 recursive topology provenance validation (2026-07-23)](20260723-02-remediate-modsecurity-v3-topology-provenance.md)
- [Framework CPython 3.14 CI migration (2026-07-22)](20260722-02-migrate-framework-python-314-ci.md)
- [Framework PRs 39–41 consolidation (2026-07-22)](20260722-01-consolidate-framework-pr-39-41.md)
- [Framework workflow tooling update (2026-07-21)](20260721-01-framework-workflow-tools-update.md)
