# Normalizers

Status: scaffolded

Normalizers remove or stabilize volatile values from artifacts before
comparison.

Implemented skeleton scope:

- timestamps
- process IDs
- thread IDs
- localhost ports
- absolute paths under the current workspace
- transaction IDs
- common server banners

Open work is tracked in `docs/roadmap/todo-inventory.md`:

- Header order normalization is not implemented. It needs an artifact-specific
  parser.
- Audit log section parsing is not implemented.
- Connector-specific log formats must be handled in connector-specific code.
