# Framework Documentation and Traceability Delta

Maintained reader-facing Framework documentation is repository-owned and follows the Framework English/German pairing contract.

For non-trivial Framework implementation, bug-fix, security, validation-contract, generator, workflow, or integration-decision changes, create/update the paired Framework Change Record under:

`reports/audits/change-records/`

Do not mix Parent connector findings, Parent revisions, or MRTS delivery facts into a Framework Change Record except as explicitly identified external dependencies/impacts.

Generated reports, including the root `TEST-COVERAGE-SUMMARY.md`, are updated only through their documented generator.

Use current repository documentation checks after applicable documentation changes. Preserve secrets, raw bodies, credentials, and unreviewed raw logs outside versioned documentation/records.
