# ModSecurity v2 Regression Map

Status: implemented

Local source: `<local ModSecurity v2 checkout>/tests/`
Upstream source: https://github.com/owasp-modsecurity/ModSecurity

The v2 tree is used only as a regression, semantics, and compatibility source.
No v2 architecture or Apache harness code is imported into this monorepo.

Observed local inventory on 2026-05-15: 115 files under `tests/`.

| original_path | source_repo | version | category | purpose | portable | connector_specific | engine_specific | target_location | status | required_capabilities | known_limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `tests/op/streq.t` | ModSecurity_V2 | v2/master observed 2.9.13 | operators | String equality operator semantics | yes | no | yes | `tests/common/cases/v2-imported/v2_operator_streq_block.yaml` | imported | operators, query-args, phase2 | Converted from Perl operator harness to HTTP intervention assertion |
| `tests/op/contains.t` | ModSecurity_V2 | v2/master observed 2.9.13 | operators | Substring operator semantics | yes | no | yes | `tests/common/cases/v2-imported/v2_operator_contains_block.yaml` | imported | operators, query-args, phase2 | Empty-string edge cases remain mapped only |
| `tests/op/beginsWith.t` | ModSecurity_V2 | v2/master observed 2.9.13 | operators | Prefix operator semantics using param `abcdef`, input `abcdefghi`, ret 1 | yes | no | yes | `tests/common/cases/v2-imported/v2_operator_begins_with_block.yaml` | imported | operators, query-args, phase2 | Empty-string and mismatch branches remain mapped only |
| `tests/op/endsWith.t` | ModSecurity_V2 | v2/master observed 2.9.13 | operators | Suffix operator semantics using param `ghi`, input `abcdefghi`, ret 1 | yes | no | yes | `tests/common/cases/v2-imported/v2_operator_ends_with_block.yaml` | imported | operators, query-args, phase2 | NUL-containing branch remains mapped only |
| `tests/op/pm.t` | ModSecurity_V2 | v2/master observed 2.9.13 | operators | Phrase-match semantics using param `abc`, input `abcdefghi`, ret 1 | yes | no | yes | `tests/common/cases/v2-imported/v2_operator_pm_block.yaml` | imported | operators, query-args, phase2 | Long phrase-list and no-match branches remain mapped only |
| `tests/op/containsWord.t` | ModSecurity_V2 | v2/master observed 2.9.13 | operators | Word-boundary substring semantics using param `abc`, input `abc def ghi`, ret 1 | yes | no | yes | `tests/common/cases/v2-imported/v2_operator_contains_word_block.yaml` | imported | operators, query-args, phase2 | Negative word-boundary branches remain mapped only |
| `tests/op/*.t` | ModSecurity_V2 | v2/master observed 2.9.13 | operators | Operator semantics matrix | partial | no | yes | `tests/common/cases/v2-imported/` or maps | mapped | operators | Optional-library operators and file-backed operators need separate fixture support |
| `tests/tfn/lowercase.t` | ModSecurity_V2 | v2/master observed 2.9.13 | transformations | Lowercase transformation semantics | yes | no | yes | `tests/common/cases/v2-imported/v2_transformation_lowercase_block.yaml` | imported | transformations, query-args, phase2 | Embedded NUL cases remain mapped only |
| `tests/tfn/trim.t` | ModSecurity_V2 | v2/master observed 2.9.13 | transformations | Leading/trailing whitespace trimming | yes | no | yes | `tests/common/cases/v2-imported/v2_transformation_trim_block.yaml` | imported | transformations, query-args, phase2 | Complex whitespace and NUL cases remain mapped only |
| `tests/tfn/urlDecode.t` | ModSecurity_V2 | v2/master observed 2.9.13 | transformations | URL decode transformation using input `Test+Case`, output `Test Case`, ret 1 | yes | no | yes | `tests/common/cases/v2-imported/v2_transformation_url_decode_block.yaml` | imported | transformations, request-uri, phase1 | Full-byte, NUL, and invalid-encoding branches remain mapped only |
| `tests/tfn/htmlEntityDecode.t` | ModSecurity_V2 | v2/master observed 2.9.13 | transformations | HTML entity decode transformation using `&lt;&gt;` -> `<>` | yes | no | yes | `tests/common/cases/v2-imported/v2_transformation_html_entity_decode_block.yaml` | imported | transformations, request-headers, phase1 | NUL, nbsp, non-ASCII, and invalid entity branches remain mapped only |
| `tests/tfn/*.t` | ModSecurity_V2 | v2/master observed 2.9.13 | transformations | Transformation semantics matrix | partial | no | yes | `tests/common/cases/v2-imported/` or maps | mapped | transformations | Many cases require binary/NUL fixture representation not in the YAML smoke schema |
| `tests/regression/misc/00-multipart-parser.t` | ModSecurity_V2 | v2/master observed 2.9.13 | multipart | Multipart parser behavior and parser errors | partial | no | yes | maps | mapped-only | multipart, files, request-body | Normal text-field coverage exists in Apache/NGINX-derived cases; malformed parser cases remain unmapped to active smoke |
| `tests/regression/rule/10-xml.t` | ModSecurity_V2 | v2/master observed 2.9.13 | xml | XML parser, schema, and DTD behavior | partial | no | yes | maps | mapped-only | xml, body-processors, fixtures | Schema/DTD validation needs fixture-file materialization before active import |
| `tests/regression/rule/15-json.t` | ModSecurity_V2 | v2/master observed 2.9.13 | json | JSON body processor and parser behavior | partial | no | yes | maps | mapped-only | json, body-processors | Raw JSON body matching is covered elsewhere; parsed JSON collection parity remains mapped |
| `tests/regression/target/00-targets.t` | ModSecurity_V2 | v2/master observed 2.9.13 | collections | Variable/collection coverage including ARGS, FILES, XML | partial | no | yes | maps and imported common cases | mapped | collections, files, xml | Some variables require upload temp paths or XML parser setup |
| `tests/regression/action/*.t` | ModSecurity_V2 | v2/master observed 2.9.13 | actions | Disruptive and logging actions | partial | no | yes | `tests/common/cases/imported/` and maps | mapped | actions, audit-log | Log text and v2 audit formatting are not portable |
| `tests/regression/config/*.t` | ModSecurity_V2 | v2/master observed 2.9.13 | rule-parser | Directive/config behavior | partial | no | yes | maps | mapped-only | rule-parser | Environment-specific paths and files need fixture support |
| `tests/regression/misc/00-phases.t` | ModSecurity_V2 | v2/master observed 2.9.13 | phase-processing | Phase lifecycle behavior | partial | partial | yes | maps and minimal cases | mapped | phase1, phase2, phase3, phase4 | Exact hook/log behavior is connector-specific |
| `tests/run-regression-tests.pl.in` | ModSecurity_V2 | v2/master observed 2.9.13 | connector-specific | Historical Apache regression harness | no | yes | no | documentation only | mapped-only | Apache runtime | Not imported; v2 Apache architecture is not a model for new connectors |

## Active V2-Derived Imports

These active cases were observed locally through `make smoke-common` with
`BUILD_ROOT=<local-build-root>`; Apache and NGINX both returned
the expected HTTP 403.

| case | source | status |
| --- | --- | --- |
| `v2_operator_streq_block.yaml` | `tests/op/streq.t` | fully-imported-common |
| `v2_operator_contains_block.yaml` | `tests/op/contains.t` | fully-imported-common |
| `v2_operator_begins_with_block.yaml` | `tests/op/beginsWith.t` | fully-imported-common |
| `v2_operator_ends_with_block.yaml` | `tests/op/endsWith.t` | fully-imported-common |
| `v2_operator_pm_block.yaml` | `tests/op/pm.t` | fully-imported-common |
| `v2_operator_contains_word_block.yaml` | `tests/op/containsWord.t` | fully-imported-common |
| `v2_transformation_lowercase_block.yaml` | `tests/tfn/lowercase.t` | fully-imported-common |
| `v2_transformation_trim_block.yaml` | `tests/tfn/trim.t` | fully-imported-common |
| `v2_transformation_url_decode_block.yaml` | `tests/tfn/urlDecode.t` | fully-imported-common |
| `v2_transformation_html_entity_decode_block.yaml` | `tests/tfn/htmlEntityDecode.t` | fully-imported-common |
