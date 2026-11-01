# Harness - Connector Template

**Language:** English | [Deutsch](README.de.md)

This directory describes the harness evidence expected for a future connector.
It intentionally contains no runnable harness implementation.

## Required harness responsibilities

- [ ] prepare build/runtime prerequisites
- [ ] start server process
- [ ] stop server process
- [ ] reload server process, if supported
- [ ] apply rules for a framework case
- [ ] materialize request/response fixtures
- [ ] send a real HTTP request
- [ ] collect server, connector, audit, and access logs
- [ ] write result JSON
- [ ] summarize PASS/FAIL/BLOCKED counts
- [ ] clean runtime artifacts without deleting global sources

## Runtime variant responsibilities

- [ ] No-CRS mode keeps local YAML-case rules separated from CRS.
- [ ] With-CRS mode documents CRS source and preamble paths.
- [ ] Variant-specific expectations are respected when present.
- [ ] PASS/FAIL/BLOCKED rows are not reclassified without evidence.

## Evidence to record

```text
Command:
Exit code:
Connector:
Case scope:
Variant:
Result directory:
Summary JSON:
Logs:
```

## Not included

This template does not define server APIs, process management commands,
network ports, or build flags for an unknown future connector.
