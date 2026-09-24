# Framework Repository Boundaries

## Framework ownership

The Framework owns reusable YAML case schemas/corpus, runners, normalizers, catalog checks, evidence validators, CI helpers, and report generators.

It does not own connector host adapters, host configuration, connector capability declarations, canonical connector runtime artifacts, or connector promotion decisions.

## Repository separation

Parent, Framework, and MRTS are separate source/Git/delivery scopes. Framework changes must be committed and reviewed in the Framework repository only.

A Framework change does not authorize:

- Parent file edits;
- Parent Framework gitlink updates;
- MRTS edits or delivery;
- combining files from multiple repositories in one commit.

## Connector boundary

Framework cases and validators may describe or validate all six connector families, but host behavior remains connector-owned. A generated Framework view never promotes connector support by itself.

## Parent coordination

When invoked from a Parent task, follow inherited `PARENT-FRAMEWORK-ORCHESTRATION`. Parent may coordinate Framework work, but Framework delivery and Parent gitlink delivery remain separate operations.
