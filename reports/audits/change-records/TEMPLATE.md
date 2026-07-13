# Change record

**Language:** English | [Deutsch](TEMPLATE.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | Record the unique UTC-based ID |
| UTC date | Record the completion date in UTC |
| Framework base revision | Record the Git revision used as the starting point |
| Issue or pull request | Record the reference, or state that none exists |

## Motivation and problem statement

Explain why this Framework-only change is needed and which behavior, process,
or evidence boundary it affects.

## Affected components and security boundaries

List Framework paths and the relevant boundary. State when no security boundary
is affected; do not infer connector behavior.

## Acceptance criteria

List concrete, observable criteria used to decide completion.

## Alternatives considered

Summarize meaningful alternatives and why the selected approach fits the
Framework boundary.

## Implementation decision

Describe the final approach, compatibility considerations, and cleanup or
boundary handling.

## Changed files and tests

List changed files, added or modified tests, and positive, negative, or
boundary coverage as applicable.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Record each executed command | Record the actual exit code | Record a safe summary | Record only approved references |

## Security impact

State the security effect, original-path retest and alternate-bypass result for
a security fix, or state that no security remediation was performed.

## Documentation and runtime evidence

List English/German documentation changes. Record observed runtime or lifecycle
evidence, or explicitly state that no such evidence was collected.

## Checks not run

List every relevant omitted check and its reason.

## Limitations and residual risk

State known limitations, unremediated prerequisites, and remaining risk without
copying sensitive material.

## Final diff and review status

Record staged/unstaged diff review, whitespace review, secret review, and the
final commit or handoff status.
