# Framework Context Index

This directory contains only Framework-specific policy deltas. Shared controls are inherited from the Parent V3.2 catalog through `.codex/inheritance-manifest.toml`.

## Local delta owners

| Decision domain | Framework-local owner |
| --- | --- |
| Framework/Parent/MRTS ownership | `repository-boundaries.md` |
| Framework tests and evidence semantics | `testing-and-evidence.md` |
| Framework security scope | `security-policy.md` |
| Framework branch/PR/delivery delta | `delivery-policy.md` |
| MRTS default read-only boundary | `mrts-boundary-policy.md` |
| Framework Python environment/dependencies | `python-policy.md` |
| EN/DE docs and Framework Change Records | `documentation-and-traceability.md` |
| Framework cleanup/restoration | `cleanup-and-restoration.md` |
| Framework completion overlay | `definition-of-done.md` |

## Inherited Parent owners

The inheritance manifest pins the Parent policy IDs and SHA-256 digests. Do not copy those Parent bodies into this repository.

Important inherited owners include:

- `PARENT-POLICY-PRECEDENCE`
- `PARENT-TASK-WORKFLOW`
- `PARENT-COMMAND-EXECUTION`
- `PARENT-RESOURCES-AND-STORAGE`
- `PARENT-SECURITY-POLICY`
- `PARENT-GIT-POLICY`
- `PARENT-DELIVERY-AND-CI`
- `PARENT-PR-REMEDIATION`
- `PARENT-MASTER-INTEGRATION`
- `PARENT-FRAMEWORK-ORCHESTRATION`
- `PARENT-PYTHON-POLICY`
- `PARENT-TESTING-AND-EVIDENCE`
- `PARENT-SONARQUBE-POLICY`
- `PARENT-DEFINITION-OF-DONE`

## Repository-native authority

The current Framework `Makefile`, `docs/`, `ci/`, `tests/`, and versioned schemas are the technical sources of truth. Historical `.codex` audits and reports are evidence only.
