# Framework Security Delta

Framework security work is a separate security scope from Parent connector security and MRTS.

Apply inherited `PARENT-SECURITY-POLICY`, `PARENT-FINDINGS`, and the applicable security assessment rules, but validate findings against Framework-owned code/contracts only.

Framework-specific security surfaces include:

- case and schema parsing;
- runner/materializer inputs;
- path and command construction;
- source/provenance acquisition helpers;
- CI workflow inputs and permissions;
- artifact normalization and evidence validation;
- report generators;
- cross-repository path/variable handling;
- secret and payload redaction boundaries.

A possible issue in Parent connector code or MRTS is an external/cross-repository finding. Do not patch another repository from a Framework-only security task.

Do not weaken schema, provenance, path, CI, evidence, or privacy controls to obtain a passing scan or test.
