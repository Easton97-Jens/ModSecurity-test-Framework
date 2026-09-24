# Framework Codex Control Plane V3.2

This `.codex` directory is the Framework-local layer under Parent Control Plane V3.2.

- `config.toml` contains Framework machine/runtime settings.
- `inheritance-manifest.toml` pins canonical Parent policies by ID and digest.
- `context/` contains only Framework-specific deltas.
- Do not copy Parent policy bodies into `context/`.
- Parent RTK, SonarQube, task workflow, generic Git/PR, resources, subagents, and finding rules remain inherited primary owners.
