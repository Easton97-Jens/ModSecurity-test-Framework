"""Regression tests for the read-only Framework candidate contract verifier."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from modsecurity_connector_tests.framework_sha_fixture import set_framework_sha_fixture
from modsecurity_test_framework.workflow_sources import expand_workflow_source


ROOT = connector_root()
VERIFIER = load_source(source_path('ci/tools/verify-framework-candidate-contract.py', root=ROOT))

SYNC = load_source(source_path('ci/tools/sync-framework-component-versions.py', root=ROOT))


CANDIDATE_SHA = "d4f7b69dc264852eac74e1439c0887fcb9fbe372"
CURRENT_PARENT_FRAMEWORK_SHA = "0" * 40
GENERIC_SOURCE_COMMON = """\
ENVOY_VERSION="1.39.1"
LIGHTTPD_SERIES="1.4"
LIGHTTPD_RELEASE_ROOT_URL="https://download.lighttpd.net/lighttpd"
LIGHTTPD_SERIES_BASE_URL="$LIGHTTPD_RELEASE_ROOT_URL/releases-$LIGHTTPD_SERIES.x"
LIGHTTPD_VERSION="1.4.85"
LIGHTTPD_SOURCE_URL="$LIGHTTPD_SERIES_BASE_URL/"
LIGHTTPD_ARCHIVE_NAME="lighttpd-$LIGHTTPD_VERSION.tar.xz"
LIGHTTPD_DOWNLOAD_URL="$LIGHTTPD_SOURCE_URL$LIGHTTPD_ARCHIVE_NAME"
LIGHTTPD_SHA256="18de51b393bac4a6827879e1a7ff377c169e414bae92cd245091d80fc2601d13"
HAPROXY_SERIES="3.2"
HAPROXY_RELEASE_ROOT_URL="https://www.haproxy.org/download"
HAPROXY_SERIES_BASE_URL="$HAPROXY_RELEASE_ROOT_URL/$HAPROXY_SERIES/src"
HAPROXY_VERSION="3.2.23"
HAPROXY_ARCHIVE_NAME="haproxy-$HAPROXY_VERSION.tar.gz"
HAPROXY_SOURCE_URL="$HAPROXY_SERIES_BASE_URL/$HAPROXY_ARCHIVE_NAME"
HAPROXY_SHA256="82d14ef33571e4edeb9197516c0d058a3775fb80541e46afe4377428e461fef0"
HAPROXY_HTX_SERIES="3.2"
HAPROXY_HTX_SERIES_BASE_URL="$HAPROXY_RELEASE_ROOT_URL/$HAPROXY_HTX_SERIES/src"
HAPROXY_HTX_VERSION="3.2.23"
HAPROXY_HTX_ARCHIVE_NAME="haproxy-$HAPROXY_HTX_VERSION.tar.gz"
HAPROXY_HTX_SOURCE_URL="$HAPROXY_HTX_SERIES_BASE_URL/$HAPROXY_HTX_ARCHIVE_NAME"
HAPROXY_HTX_SHA256="82d14ef33571e4edeb9197516c0d058a3775fb80541e46afe4377428e461fef0"
CRS_APPROVED_REPO_URL="https://github.com/coreruleset/coreruleset.git"
CRS_APPROVED_COMMIT="ab3ccd5fcd691424ba3f320d4040c61417270193"
CRS_RELEASE_TAG="v4.29.0"
MODSECURITY_V3_APPROVED_REPO_URL="https://github.com/owasp-modsecurity/ModSecurity.git"
MODSECURITY_V3_APPROVED_COMMIT="7ea9fefbe0ba409d8733b4d682c8c4c059cd028d"
MODSECURITY_V3_RELEASE_TAG="v3.0.16"
"""
CANDIDATE_COMMON = GENERIC_SOURCE_COMMON + """\
NGINX_SOURCE_MODE="github-release"
NGINX_SOURCE_REPO_URL="https://github.com/nginx/nginx"
NGINX_RELEASE_TAG="release-1.31.6"
NGINX_SOURCE_GIT_REF="$NGINX_RELEASE_TAG"
NGINX_RELEASE_ASSET_NAME="nginx-${NGINX_RELEASE_TAG#release-}.tar.gz"
NGINX_SHA256="974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1"
OPENSSL_SHA256="736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8"
CI_SECURITY_TOOL_OSV_SCANNER_COMMIT="e840a6e8adb14b7777c78e26cfbf6e2abc1d1fc6"
CI_SECURITY_TOOL_RUFF_COMMIT="62914c4b9b79a9e5004374a9c482ad2ed69290e1"
"""


class VerifyFrameworkCandidateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        shutil.copytree(
            ROOT,
            self.root,
            ignore=shutil.ignore_patterns(
                ".git", "ModSecurity-test-Framework", "__pycache__", ".pytest_cache"
            ),
        )
        # Only the temporary copy uses the offline candidate's test identity.
        set_framework_sha_fixture(self.root, CANDIDATE_SHA)
        # Legacy mutation fixtures contain explicit captured test inputs;
        # production reads the external pinned Framework source owner.
        for relative in (VERIFIER.RUNTIME_COMPONENTS_PATH, VERIFIER.RUNTIME_PRODUCER_READINESS_PATH,
                         "tests/test_ci_security_workflows.py", "ci/runtime/broker/nginx_root_broker.py",
                         "modules/ModSecurity-test-Framework/connector_suite/workflows/nginx-root-broker.historical.yml"):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source_path(relative, root=ROOT).read_bytes())
        for relative in (VERIFIER.NGINX_EXACT_HEAD_WORKFLOW_PATH, VERIFIER.NGINX_FULL_SMOKE_WORKFLOW_PATH):
            path = self.root / relative
            path.write_text(expand_workflow_source(path.read_text(), framework_root=test_root(),
                                                  framework_revision=CANDIDATE_SHA, workflow_name=path.name))
        self.common = Path(self.temporary.name) / "framework-common.sh"
        self.common.write_text(CANDIDATE_COMMON, encoding="utf-8")
    def write_common(self, text: str) -> None:
        self.common.write_text(text, encoding="utf-8")

    def parent_bytes(self) -> dict[Path, bytes]:
        paths = {
            projection.relative_path for projection in VERIFIER.PARENT_NGINX_PROJECTIONS
        }
        paths.update(
            projection.relative_path for projection in VERIFIER.PARENT_NGINX_POLICY_PROJECTIONS
        )
        paths.update(
            {
                ".github/workflows/test-connectors-with-crs-no-mrts.yml",
                "tests/test_ci_security_workflows.py",
                "ci/tooling/project-versions.lock.json",
            }
        )
        return {self.root / path: (self.root / path).read_bytes() for path in paths}

    def set_static_parent_framework_sha(self, framework_sha: str) -> None:
        set_framework_sha_fixture(self.root, framework_sha)

    def test_parent_fixture_can_be_reset_after_a_repository_pin_update(self) -> None:
        before = self.parent_bytes()
        self.set_static_parent_framework_sha("c" * 40)
        self.assertNotEqual(before, self.parent_bytes())
        self.set_static_parent_framework_sha(CANDIDATE_SHA)
        self.assertEqual(before, self.parent_bytes())
        self.assertEqual(
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)["release_tag"],
            "release-1.31.6",
        )

    def test_current_parent_contract_matches_the_candidate_without_writing(self) -> None:
        before = self.parent_bytes()
        values = VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)
        self.assertEqual(values["release_tag"], "release-1.31.6")
        self.assertEqual(before, self.parent_bytes())
        protected_workflow = (
            self.root / "modules/ModSecurity-test-Framework/connector_suite/workflows/nginx-root-broker.historical.yml"
        ).read_text(encoding="utf-8")
        protected_broker = (
            self.root / "ci/runtime/broker/nginx_root_broker.py"
        ).read_text(encoding="utf-8")
        self.assertIn("NGINX_RELEASE_TAG: release-1.31.4", protected_workflow)
        self.assertIn('NGINX_PINNED_RELEASE_TAG = "release-1.31.4"', protected_broker)

    def test_checked_out_framework_common_passes_the_data_contract(self) -> None:
        framework_common = source_path('modules/ModSecurity-test-Framework/ci/lib/common.sh', root=ROOT)
        if not framework_common.is_file():
            self.skipTest("reviewed Framework submodule is not initialized")
        self.common.write_bytes(framework_common.read_bytes())
        before = self.parent_bytes()
        values = VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)
        self.assertEqual(values["release_tag"], "release-1.31.6")
        self.assertEqual(before, self.parent_bytes())

    def test_new_shell_structure_is_not_blocked_by_a_fixed_digest(self) -> None:
        self.write_common(CANDIDATE_COMMON + "\nfuture_helper() { :; }\n")
        self.assertEqual(
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)["release_tag"],
            "release-1.31.6",
        )

    def test_current_parent_projection_can_be_checked_before_candidate_projection(
        self,
    ) -> None:
        self.set_static_parent_framework_sha(CURRENT_PARENT_FRAMEWORK_SHA)
        before = self.parent_bytes()
        values = VERIFIER.verify_contract(
            self.root,
            CANDIDATE_SHA,
            self.common,
            expected_parent_framework_sha=CURRENT_PARENT_FRAMEWORK_SHA,
        )
        self.assertEqual(values["release_tag"], "release-1.31.6")
        self.assertEqual(before, self.parent_bytes())
        with self.assertRaisesRegex(VERIFIER.ContractError, "expected Parent Framework SHA"):
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)

    def test_mutable_source_field_allowlist_matches_the_generic_registry(self) -> None:
        self.assertEqual(tuple(SYNC.SOURCE_FIELDS), VERIFIER.MUTABLE_SOURCE_FIELDS)

    def test_registered_source_data_rhs_can_change_without_structure_review(self) -> None:
        self.common.write_text(
            CANDIDATE_COMMON.replace('ENVOY_VERSION="1.39.1"', 'ENVOY_VERSION="1.39.2"'),
            encoding="utf-8",
        )
        self.assertEqual(
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)["release_tag"],
            "release-1.31.6",
        )

    def test_registered_modsecurity_v3_tuple_can_change_without_structure_review(self) -> None:
        updated = CANDIDATE_COMMON.replace(
            'MODSECURITY_V3_RELEASE_TAG="v3.0.16"',
            'MODSECURITY_V3_RELEASE_TAG="v3.0.17"',
        ).replace(
            'MODSECURITY_V3_APPROVED_COMMIT="7ea9fefbe0ba409d8733b4d682c8c4c059cd028d"',
            'MODSECURITY_V3_APPROVED_COMMIT="1925753989ccce977cdaae417b55c9726c7cf02c"',
        )
        self.common.write_text(updated, encoding="utf-8")
        self.assertEqual(
            VERIFIER._framework_common_structure_sha256(updated.encode("utf-8")),
            VERIFIER._framework_common_structure_sha256(CANDIDATE_COMMON.encode("utf-8")),
        )
        self.assertEqual(
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)["release_tag"],
            "release-1.31.6",
        )

    def test_unsafe_registered_source_rhs_fails_before_parent_projection(self) -> None:
        self.common.write_text(
            CANDIDATE_COMMON.replace('ENVOY_VERSION="1.39.1"', 'ENVOY_VERSION="$(id)"'),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(VERIFIER.ContractError, "source-data"):
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)

    def test_ambiguous_unbraced_source_reference_fails_before_parent_projection(self) -> None:
        self.common.write_text(
            CANDIDATE_COMMON.replace(
                'LIGHTTPD_DOWNLOAD_URL="$LIGHTTPD_SOURCE_URL$LIGHTTPD_ARCHIVE_NAME"',
                'LIGHTTPD_DOWNLOAD_URL="$LIGHTTPD_SOURCE_URLlighttpd-$LIGHTTPD_VERSION.tar.xz"',
            ),
            encoding="utf-8",
        )
        before = self.parent_bytes()
        with self.assertRaisesRegex(
            VERIFIER.ContractError, "ambiguous source-data reference"
        ):
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)
        self.assertEqual(before, self.parent_bytes())

    def test_unreviewed_nginx_data_change_fails_the_parent_handoff(self) -> None:
        self.common.write_text(
            CANDIDATE_COMMON.replace("release-1.31.6", "release-1.31.7"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(VERIFIER.ContractError, "unprotected NGINX handoff mismatch"):
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)

    def test_unregistered_maintenance_pins_do_not_block_manual_updates(self) -> None:
        replacements = (
            (
                'OPENSSL_SHA256="736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8"',
                'OPENSSL_SHA256="' + "a" * 64 + '"',
            ),
            (
                'CI_SECURITY_TOOL_OSV_SCANNER_COMMIT="e840a6e8adb14b7777c78e26cfbf6e2abc1d1fc6"',
                'CI_SECURITY_TOOL_OSV_SCANNER_COMMIT="' + "a" * 40 + '"',
            ),
            (
                'CI_SECURITY_TOOL_RUFF_COMMIT="62914c4b9b79a9e5004374a9c482ad2ed69290e1"',
                'CI_SECURITY_TOOL_RUFF_COMMIT="' + "a" * 40 + '"',
            ),
        )
        for expected, replacement in replacements:
            with self.subTest(expected=expected):
                self.write_common(CANDIDATE_COMMON.replace(expected, replacement))
                self.assertEqual(
                    VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)["release_tag"],
                    "release-1.31.6",
                )

    def test_stale_framework_sha_fails_closed_without_parent_writes(self) -> None:
        set_framework_sha_fixture(self.root, "0" * 40)
        before = self.parent_bytes()
        with self.assertRaisesRegex(VERIFIER.ContractError, "revision lock Framework SHA"):
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)
        self.assertEqual(before, self.parent_bytes())

    def test_malformed_framework_lock_fails_closed_without_parent_writes(self) -> None:
        lock = self.root / "ci/tooling/project-versions.lock.json"
        original = json.loads(lock.read_bytes())
        cases = ("{", "[]", json.dumps(original | {"unknown": 1}),
                 json.dumps({"schema_version": 1, "framework_sha": CANDIDATE_SHA}),
                 json.dumps(original | {"mrts_sha": "invalid"}),
                 '{"schema_version":1,"schema_version":1}')
        for contents in cases:
            with self.subTest(contents=contents):
                lock.write_text(contents)
                before = self.parent_bytes()
                with self.assertRaisesRegex(VERIFIER.ContractError, "revision lock"):
                    VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)
                self.assertEqual(before, self.parent_bytes())

    def test_valid_but_stale_nginx_candidate_fails_closed_without_parent_writes(self) -> None:
        stale = CANDIDATE_COMMON.replace("release-1.31.6", "release-1.31.4").replace(
            "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1",
            "e6f20b644a17a643f059ae6467a1971fe2811587d025e071068753a1f1e3b3c3",
        )
        self.write_common(stale)
        before = self.parent_bytes()
        with self.assertRaisesRegex(VERIFIER.ContractError, "unprotected NGINX handoff mismatch"):
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)
        self.assertEqual(before, self.parent_bytes())

    def test_malformed_candidate_checksum_fails_before_parent_projection(self) -> None:
        self.write_common(
            CANDIDATE_COMMON.replace(
                "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1",
                "0" * 63,
            )
        )
        with self.assertRaisesRegex(VERIFIER.ContractError, "canonical release tuple"):
            VERIFIER.parse_candidate_nginx_handoff(self.common)

    def test_noncanonical_candidate_tuple_fails_before_parent_projection(self) -> None:
        self.write_common(
            CANDIDATE_COMMON.replace(
                'NGINX_SOURCE_MODE="github-release"',
                'NGINX_SOURCE_MODE="git"',
            )
        )
        with self.assertRaisesRegex(VERIFIER.ContractError, "canonical release tuple"):
            VERIFIER.parse_candidate_nginx_handoff(self.common)

    def test_alternate_nginx_assignment_forms_fail_before_parent_projection(self) -> None:
        cases = (
            '\n NGINX_SHA256="' + "0" * 64 + '"\n',
            '\nexport NGINX_SHA256="' + "0" * 64 + '"\n',
            '\nNGINX_SHA256+="x"\n',
            '\nreadonly NGINX_SHA256="' + "0" * 64 + '"\n',
            '\ndeclare -- NGINX_SHA256="' + "0" * 64 + '"\n',
            '\nlocal NGINX_SHA256="' + "0" * 64 + '"\n',
            '\ntypeset NGINX_SHA256="' + "0" * 64 + '"\n',
            "\nunset -v -- NGINX_SHA256\n",
            '\n: "${NGINX_SHA256:=invalid}"\n',
        )
        for suffix in cases:
            with self.subTest(suffix=suffix):
                self.write_common(CANDIDATE_COMMON + suffix)
                with self.assertRaises(VERIFIER.ContractError):
                    VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)

    def test_parent_owned_nginx_provenance_flag_rejects_candidate_assignments(self) -> None:
        cases = (
            "\nNGINX_REQUIRE_PINNED_PROVENANCE=0\n",
            "\nexport NGINX_REQUIRE_PINNED_PROVENANCE=0\n",
            '\n: "${NGINX_REQUIRE_PINNED_PROVENANCE:=0}"\n',
            "\nunset NGINX_REQUIRE_PINNED_PROVENANCE\n",
        )
        for suffix in cases:
            with self.subTest(suffix=suffix):
                self.write_common(CANDIDATE_COMMON + suffix)
                with self.assertRaisesRegex(
                    VERIFIER.ContractError, "NGINX_REQUIRE_PINNED_PROVENANCE"
                ):
                    VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)

    def test_indirect_eval_target_writes_fail_before_parent_projection(self) -> None:
        cases = (
            '\nfield=NGINX_SHA256; eval "$field=' + "0" * 64 + '"\n',
            '\nfield=NGINX_REQUIRE_PINNED_PROVENANCE; eval "$field=0"\n',
        )
        for suffix in cases:
            with self.subTest(suffix=suffix):
                self.write_common(CANDIDATE_COMMON + suffix)
                with self.assertRaisesRegex(VERIFIER.ContractError, "dynamic shell evaluation"):
                    VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)

    def test_indirect_shell_assignment_fails_before_parent_projection(self) -> None:
        cases = (
            '\nfield=NGINX_SHA256; printf -v "$field" "%s" "' + "0" * 64 + '"\n',
            '\nfield=NGINX_REQUIRE_PINNED_PROVENANCE; unset "$field"\n',
            '\nfield=NGINX_REQUIRE_PINNED_PROVENANCE; export -n "$field"\n',
            '\nfield=NGINX_SHA256; declare -n reference="$field"; reference="' + "0" * 64 + '"\n',
        )
        for suffix in cases:
            with self.subTest(suffix=suffix):
                self.common.write_text(CANDIDATE_COMMON + suffix, encoding="utf-8")
                with self.assertRaisesRegex(
                    VERIFIER.ContractError, "unsupported indirect shell assignment"
                ):
                    VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)

    def test_missing_revision_lock_is_rejected(self) -> None:
        (self.root / "ci/tooling/project-versions.lock.json").unlink()
        with self.assertRaisesRegex(VERIFIER.ContractError, "revision lock"):
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)

    def test_candidate_mrts_gitlink_must_match_locked_selection(self) -> None:
        from unittest.mock import patch
        mrts = json.loads((self.root / "ci/tooling/project-versions.lock.json").read_bytes())["mrts_sha"]
        for observed in (mrts, "0" * 40):
            with self.subTest(observed=observed):
                with patch.object(VERIFIER, "read_framework_mrts_gitlink", return_value=observed) as read:
                    if observed == mrts:
                        VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common, candidate_framework_root=self.root)
                    else:
                        with self.assertRaisesRegex(VERIFIER.ContractError, "MRTS gitlink"):
                            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common, candidate_framework_root=self.root)
                    read.assert_called_once_with(self.root, CANDIDATE_SHA)
        with patch.object(VERIFIER, "read_framework_mrts_gitlink", side_effect=VERIFIER.FrameworkRevisionPinsError("missing gitlink")):
            with self.assertRaisesRegex(VERIFIER.ContractError, "cannot verify"):
                VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common, candidate_framework_root=self.root)

    def test_parent_nginx_provenance_policy_requires_both_workflows(self) -> None:
        for projection in VERIFIER.PARENT_NGINX_POLICY_PROJECTIONS:
            with self.subTest(relative_path=projection.relative_path):
                target = self.root / projection.relative_path
                original = target.read_text(encoding="utf-8")
                expected = f'{projection.name}: "{projection.expected_value}"'
                self.assertIn(expected, original)
                target.write_text(
                    original.replace(expected, f'{projection.name}: "0"', 1),
                    encoding="utf-8",
                )
                before = self.parent_bytes()
                with self.assertRaisesRegex(VERIFIER.ContractError, "Parent NGINX policy"):
                    VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)
                self.assertEqual(before, self.parent_bytes())
                target.write_text(original, encoding="utf-8")

    def test_safe_framework_parameter_reads_and_bare_exports_are_accepted(self) -> None:
        safe_common = CANDIDATE_COMMON.replace(
            'NGINX_SHA256="974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1"\n',
            'if [ "${NGINX_SHA256+x}" = x ]; then\n'
            '    NGINX_SHA256_WAS_SET=1\n'
            "fi\n"
            'NGINX_SHA256_REQUESTED="${NGINX_SHA256-}"\n'
            'NGINX_SHA256="974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1"\n',
        ) + "export NGINX_SOURCE_MODE NGINX_SHA256\n"
        self.write_common(safe_common)
        self.assertEqual(
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)["archive_sha256"],
            "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1",
        )

    def test_each_unprotected_handoff_layer_rejects_a_representative_drift(self) -> None:
        cases = (
            (
                ".github/workflows/test-nginx-exact-head.yml",
                "NGINX_RELEASE_ASSET_NAME: nginx-1.31.6.tar.gz",
                "NGINX_RELEASE_ASSET_NAME: nginx-1.31.4.tar.gz",
                "NGINX_RELEASE_ASSET_NAME",
            ),
            (
                ".github/workflows/test-full-smoke-sequential.yml",
                "NGINX_SOURCE_GIT_REF: release-1.31.6",
                "NGINX_SOURCE_GIT_REF: release-1.31.4",
                "NGINX_SOURCE_GIT_REF",
            ),
            (
                "ci/checks/evidence/check-runtime-producer-readiness.py",
                'CANONICAL_NGINX_ARCHIVE_SHA256 = "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1"',
                'CANONICAL_NGINX_ARCHIVE_SHA256 = "e6f20b644a17a643f059ae6467a1971fe2811587d025e071068753a1f1e3b3c3"',
                "CANONICAL_NGINX_ARCHIVE_SHA256",
            ),
        )
        for relative_path, expected, replacement, name in cases:
            with self.subTest(relative_path=relative_path, name=name):
                target = self.root / relative_path
                original = target.read_text(encoding="utf-8")
                self.assertIn(expected, original)
                target.write_text(original.replace(expected, replacement, 1), encoding="utf-8")
                before = self.parent_bytes()
                with self.assertRaisesRegex(
                    VERIFIER.ContractError,
                    f"{relative_path}:{name}",
                ):
                    VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)
                self.assertEqual(before, self.parent_bytes())
                target.write_text(original, encoding="utf-8")

        target = self.root / VERIFIER.NGINX_EXACT_HEAD_WORKFLOW_PATH
        original = target.read_text(encoding="utf-8")
        for name in (*VERIFIER.NGINX_FIELDS, *VERIFIER.PARENT_OWNED_NGINX_FIELDS):
            expected = f'{name}="${name}"'
            self.assertEqual(original.count(expected), 1)
            replacements = ("", expected + " " + expected, f'{name}="unreviewed"', "# " + expected)
            for replacement in replacements:
                with self.subTest(name=name, replacement=replacement):
                    target.write_text(
                        original.replace(expected, replacement, 1), encoding="utf-8"
                    )
                    before = self.parent_bytes()
                    with self.assertRaisesRegex(
                        VERIFIER.ContractError,
                        f"{VERIFIER.NGINX_EXACT_HEAD_WORKFLOW_PATH}:{name}",
                    ):
                        VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)
                    self.assertEqual(before, self.parent_bytes())
                    target.write_text(original, encoding="utf-8")

    def test_unsafe_candidate_expression_fails_before_parent_projection(self) -> None:
        self.write_common(
            CANDIDATE_COMMON.replace(
                'NGINX_SOURCE_GIT_REF="$NGINX_RELEASE_TAG"',
                'NGINX_SOURCE_GIT_REF="$(id)"',
            )
        )
        with self.assertRaisesRegex(VERIFIER.ContractError, "candidate NGINX handoff"):
            VERIFIER.verify_contract(self.root, CANDIDATE_SHA, self.common)

    def test_cli_reports_the_verified_candidate(self) -> None:
        self.assertEqual(
            VERIFIER.main(
                (
                    "--repo-root",
                    str(self.root),
                    "--candidate-sha",
                    CANDIDATE_SHA,
                    "--framework-common",
                    str(self.common),
                    "--expected-parent-framework-sha",
                    CANDIDATE_SHA,
                )
            ),
            0,
        )

    def test_cli_rejects_an_invalid_expected_parent_framework_sha(self) -> None:
        self.assertEqual(
            VERIFIER.main(
                (
                    "--repo-root",
                    str(self.root),
                    "--candidate-sha",
                    CANDIDATE_SHA,
                    "--framework-common",
                    str(self.common),
                    "--expected-parent-framework-sha",
                    "A" * 40,
                )
            ),
            2,
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
