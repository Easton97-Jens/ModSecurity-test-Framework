# Change record: 20260718-01-fix-pcre2-archive-digest

**Language:** English | [Deutsch](20260718-01-fix-pcre2-archive-digest.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260718-01-fix-pcre2-archive-digest` |
| UTC date | 2026-07-18 |
| Framework base revision | `cdc91a398d6c156eaff927d742b23018a3817fb6` |
| Issue or pull request | `FND-FRAMEWORK-0005`; [Draft PR #22](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/22) |

## Motivation and problem statement

`build_pcre2_from_source` accepted an empty literal digest and an empty digest
URL, then extracted the downloaded PCRE2 archive. That violated the required
fail-closed archive-integrity boundary in
`ci/provisioning/prepare-apache-build.sh`.

## Affected components and security boundaries

The affected Framework paths are `ci/lib/common.sh`,
`ci/provisioning/prepare-apache-build.sh`, isolated PCRE2 fixture tests, and
this paired documentation. The security boundary is the PCRE2 archive between
the configured source URL and its first `tar` extraction: no archive may reach
that sink or later processing before a non-empty, syntactically valid,
exactly matching SHA-256 digest succeeds.

## Acceptance criteria

1. The default PCRE2 digest is pinned, while an explicitly empty override is
   preserved for a fail-closed rejection.
2. Empty, whitespace-only, malformed, and mismatching PCRE2 digests return a
   blocked result before a PCRE2 `tar` invocation.
3. A matching local archive fixture reaches the real extraction boundary only
   after digest verification.
4. The new control does not use `PCRE2_SHA256_URL` as an optional bypass.
5. English and German reference documentation and this Change Record describe
   the same control and test boundary.

## Alternatives considered

- Continuing to accept `PCRE2_SHA256_URL` as an optional secondary verifier
  was rejected because an empty URL is the original bypass and the upstream
  release asset has no stable per-asset checksum URL.
- Changing the generic HTTPD/APR helpers was rejected because the finding and
  required remediation are limited to the PCRE2 path.
- A real download or full Apache build was rejected as unnecessary: the
  isolated full-script fixture reaches the actual digest-to-`tar` boundary.

## Implementation decision

`PCRE2_SHA256` has a reviewed literal pin using parameter expansion that
defaults only when the variable is unset. `verify_required_pcre2_sha256`
rejects empty or non-64-hex input, normalizes valid hexadecimal notation,
computes the archive SHA-256, and blocks on mismatch. The PCRE2 build calls it
immediately before `extract_tar_strip`; the prior optional URL check and
"local hash recorded only" success path are removed. `PCRE2_SHA256_URL` is
retained only for common-version metadata compatibility, never as extraction
verification input.

## Changed files and tests

Versioned Framework changes:

- `ci/lib/common.sh`.
- `ci/provisioning/prepare-apache-build.sh`.
- `tests/fixtures/pcre2-digest/cases.json` and its local `configure` source
  fixture.
- `tests/security_regression/test_pcre2_archive_digest.py`.
- `docs/reference/variables.md` and `docs/reference/variables.de.md`.
- This paired Change Record.

The full-script test uses only a generated local `.tar.bz2` archive and local
fake `curl`, `tar`, compiler, and `make` tools. It covers empty, whitespace,
malformed, and wrong digests with no PCRE2 `tar` marker, and a matching digest
with exactly one marker and a successful fixture path.

## Commands and results

All write-capable commands use a registered task-specific external temporary
run; no real download or full Apache build is performed.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| Focused PCRE2 archive-digest unittest | 0 | Four negative digest cases did not reach the PCRE2 `tar` spy; the matching control did | `20260718T092308Z-fnd-framework-0005-pcre2-digest-e064e1d8` |
| `make check-documentation` | 0 | Links, bilingual variable coverage, and repository-path references passed | Same task run |
| `make lint` | 0 | Shell syntax, Python compilation, static Framework checks, security-data-flow checks, catalog checks, documentation checks, and diff check passed | Same task run |
| `sh -n` and `bash -n` on the changed shell files | 0 | Syntax passed | Same task run |
| ShellCheck on the changed shell files | 1 | The unchanged baseline has 17 diagnostics outside the changed PCRE2 control; no new diagnostic is in the modified logic | Compared with clean base `cdc91a3` |
| `git diff --check` | 0 | No whitespace errors | Framework worktree |
| `gh pr create --draft` | 0 | Draft PR #22 created for the task branch at `f0619fc75d7e4fb3fe98357759421ad17d2e91ab` | GitHub PR #22 |

## Security impact

The original optional-digest path is replaced by a required literal digest
gate before the sole PCRE2 extraction call. The focused regression retests the
empty, whitespace-only, malformed, and mismatching bypass classes and the
matching legitimate control through the real preparation script. No alternate
PCRE2 URL fallback remains in that build path.

## Documentation and runtime evidence

The paired reference pages document the exact digest requirement and the fact
that `PCRE2_SHA256_URL` is not a fallback. This paired Change Record records
the security boundary and test evidence.

No connector runtime, network download, or full Apache-build evidence was
collected. The local fixture proves the digest/extraction enforcement boundary
only; it is not a production connector or lifecycle result.

## Checks not run

- The complete runtime `make test` matrix is not run. It can fetch/build
  connector runtime dependencies and is unnecessary for this narrowly scoped
  pre-extraction control: the isolated full-script fixture proves the real
  enforcement boundary without a download or full Apache build.
- Current-head Draft-PR CI, review, and SonarQube Cloud gates are being
  checked after the final documentation handoff commit is pushed.

## Limitations and residual risk

The isolated fixture does not validate an upstream download service or a full
Apache build. It does prove the required PCRE2 archive gate using the actual
production script and extraction call. Archive replacement after verification
would be a separate filesystem TOCTOU concern, not the optional-digest bypass
addressed here.

## Final diff and review status

The local Framework diff was reviewed for the named scope, generated artifacts,
and sensitive content. First task commit
`f0619fc75d7e4fb3fe98357759421ad17d2e91ab` is on Draft PR #22; `git diff
--check` passed. No merge, Parent change, Parent Gitlink update, or MRTS
modification is authorized. The final documentation handoff commit and the
exact-head checks will be recorded only after they occur.
