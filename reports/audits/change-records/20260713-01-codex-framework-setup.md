# Change record: 20260713-01-codex-framework-setup

**Language:** English | [Deutsch](20260713-01-codex-framework-setup.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260713-01-codex-framework-setup` |
| UTC date | 2026-07-13 |
| Framework base revision | `77b4e89d230a23a75bff4d871d87345d55fcad28` |
| Issue or pull request | None; repository setup task |

## Motivation and problem statement

The standalone Framework needed local Codex guidance, a Framework-owned
traceability process, and bilingual collaboration templates. The prior
documentation validator covered only selected documentation peers, not audit
records or issue templates. The pull request template also lacked the required
English/German sections and review facts.

## Affected components and security boundaries

This changes local Codex/RTK guidance, documentation and repository-path
validation, collaboration templates, and Framework audit records. It adds no
connector runtime behavior, host adapter, capability, promotion decision, or
runtime evidence. The relevant boundary is safe handling of local instructions
and review evidence: local setup remains ignored, and records remain
payload-free and secret-free.

## Acceptance criteria

1. Local `AGENTS.md`, `RTK.md`, and `.codex/` guidance exists and is ignored
   through the resolved local Git exclude file.
2. The existing validator covers tracked manual docs, change records, and
   issue-template pairs while explicitly excluding local Codex/RTK material.
3. The pull request template has English and German sections for summary,
   motivation, change ID, criteria, changes, tests, security, documentation,
   runtime evidence, limitations, skipped checks, and secrets.
4. Paired traceability documentation, audit README, and change-record templates
   exist under Framework-owned paths.
5. Focused documentation checks, lint, static contract tests, and whitespace
   checks pass without changing the parent repository.

## Alternatives considered

- A new standalone bilingual checker was rejected. Extending
  `check-variable-documentation.py` keeps the existing entry point while a
  distinct reader-facing inventory avoids mixing templates with variable and
  placeholder extraction.
- A parent-repository audit directory was rejected because the Framework is an
  independent Git repository. `reports/audits/change-records/` is separate from
  connector-produced testing output.
- Hand-editing generated German reports was rejected because generated material
  belongs to its generator.

## Implementation decision

The existing checker now uses tracked Markdown to require pairs for manual
Framework docs, audit records, and issue templates. It retains generator and
upstream exceptions, validates bilingual pull request sections, and is exposed
as `make check-bilingual-docs` while preserving the existing compatibility
target. Repository-path validation skips local Codex and RTK paths so ignored
local guidance cannot affect lint.

The versioned process adds English/German traceability documentation, templates,
and this record. Issue templates receive German counterparts; the pull request
template and automated version-update pull request body are inline bilingual.

## Changed files and tests

Versioned files changed or added:

- `.github/ISSUE_TEMPLATE/{bug_report,documentation,feature_request,security_hardening,test_case_request}.md`
  and their `.de.md` counterparts, plus `.github/ISSUE_TEMPLATE/config.yml`.
- `.github/pull_request_template.md` and
  `.github/workflows/check-common-versions.yml`.
- `Makefile`,
  `ci/checks/documentation/check-variable-documentation.py`, and
  `ci/checks/documentation/check-repository-path-references.py`.
- `README.md`, `README.de.md`, `docs/README.md`, `docs/README.de.md`,
  `docs/development.md`, `docs/development.de.md`,
  `docs/change-traceability.md`, and `docs/change-traceability.de.md`.
- `reports/audits/change-records/{README,TEMPLATE}.md` and their `.de.md`
  counterparts, plus this paired record.

Local ignored setup consists of `AGENTS.md`, `RTK.md`, and `.codex/`; it is not
part of the Framework commit. Focused validation exercised the changed
documentation scripts; existing No-CRS and protocol contract suites supplied
positive and negative security-boundary coverage.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk init --codex` | 0 | Created local RTK instructions and Codex reference | Not applicable |
| `rtk git check-ignore -v AGENTS.md RTK.md .codex/config.toml` | 0 | All local paths matched the resolved local exclude file | Local Git exclude only |
| `rtk make check-bilingual-docs` | 0 | Required manual/template inventory passed; local and generated exceptions reported | Not applicable |
| `rtk make check-doc-links` | 0 | Tracked Markdown links and anchors passed | Not applicable |
| `rtk make check-repository-path-references` | 0 | Maintained files scanned; no obsolete paths found | Not applicable |
| `rtk make lint` | 0 | Shell, Python, workflow, security-data-flow, catalog, documentation, and diff checks passed | Not applicable |
| `rtk make test-no-crs-contract` | 0 | 81 tests passed | Temporary test artifacts only |
| `rtk make test-protocol-client` | 0 | 16 tests passed | Temporary test artifacts only |
| `rtk make quick-check` | 0 | Lint, importer check, and diff check passed | Not applicable |
| `rtk git diff --check` and `rtk git diff --cached --check` | 0 | No whitespace errors | Staged Framework diff |

## Security impact

No application, connector, authentication, authorization, validation, sandbox,
path, or protocol behavior changed. The change improves review safety by keeping
local guidance outside version control and requiring records to omit secrets and
raw payloads. No security scan or remediation was performed, so there is no
original attack-path or alternate-bypass retest.

## Documentation and runtime evidence

The Framework navigation, development guidance, traceability process, audit
templates, pull request template, issue templates, and automated version-update
pull request body now provide English and German content. No runtime, smoke,
integration, or lifecycle evidence was collected or claimed.

## Checks not run

Connector provisioning, host smoke, runtime matrix, full lifecycle, and
generator-refresh checks were not run. They require connector-owned harnesses
or can rewrite generated outputs, and this bounded setup changes no runtime
behavior or generator source. No feature, bug, or security remediation was
performed by design.

## Limitations and residual risk

Generator-owned German report companions are pre-existing and materially stale;
the current generator emits English report content and must be extended before
repository-wide generated-report equivalence can be claimed. Generated reports
were not hand-edited.

Read-only analysis also found a pre-existing CI case-count guard that does not
match the current corpus, and a separate pre-existing security-regression test
failure concerning a shared temporary runtime-root policy. Neither observation
is a confirmed security finding or a remediation claim, and neither was changed
by this setup.

## Final diff and review status

The staged Framework diff was reviewed for scope, local-path separation,
whitespace, and sensitive content. Both diff checks passed. The parent
repository was deliberately excluded; the Framework commit follows this record
after final documentation verification.
