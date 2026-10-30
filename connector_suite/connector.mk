# Framework-owned connector test orchestration. Invoke through Connector Make
# or make -f <this file> -C <explicit Connector checkout> with explicit roots.
TEST_ROOT ?= $(FRAMEWORK_ROOT)
CONNECTOR_REVISION ?= $(shell git -C "$(CONNECTOR_ROOT)" rev-parse HEAD)
FRAMEWORK_REVISION ?= $(shell git -C "$(TEST_ROOT)" rev-parse HEAD)
CONNECTOR_TEST_PROFILE ?= h1
export TEST_ROOT CONNECTOR_REVISION FRAMEWORK_REVISION CONNECTOR_TEST_PROFILE CONNECTOR_TEST_OUTPUT_ROOT
export PYTHONPATH := $(TEST_ROOT):$(TEST_ROOT)/connector_suite

# Parent behavioral defaults use this inventory. The mandatory master-owned
# Sonar workflow retains its own Python, Go and Common native assessment.
# Specialist commands require an explicit on-demand invocation; they are not a
# second automatic catalogue. Static compilation/analysis gates stay independent.
ACTIVE_TEST_RUNNER = $(PYTHON) -P -m modsecurity_test_framework.connector --connector-root "$(CONNECTOR_ROOT)" --connector-revision "$(CONNECTOR_REVISION)" --test-root "$(TEST_ROOT)" --profile "$(CONNECTOR_TEST_PROFILE)" --output-root "$(CONNECTOR_TEST_OUTPUT_ROOT)"
ON_DEMAND_TESTS ?= 0
export ON_DEMAND_TESTS

PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
MSCONNECTOR_C_STD ?= c17
MSCONNECTOR_CFLAGS ?= -std=$(MSCONNECTOR_C_STD) -Wall -Wextra -Werror
MSCONNECTOR_COMPILER_ID ?= $(notdir $(firstword $(CC)))
CLANG_TIDY ?= clang-tidy
CLANG ?= clang
CLANGXX ?= clang++
CLANG_TIDY_CHECKS ?= -*,bugprone-*,cert-*
CLANG_ANALYZER_CHECKS ?= core,unix,security,cplusplus,deadcode
FRAMEWORK_PYTHON := $(if $(findstring /,$(PYTHON)),$(abspath $(PYTHON)),$(PYTHON))
VERIFIED_RUN_PARENT ?= $(if $(RUNNER_TEMP),$(RUNNER_TEMP),$(if $(TMPDIR),$(TMPDIR),/var/tmp))
VERIFIED_RUN_ROOT ?= $(VERIFIED_RUN_PARENT)/ModSecurity-conector-verified
VERIFIED_STATE_ROOT ?= $(VERIFIED_RUN_ROOT)/state
VERIFIED_BUILD_ROOT ?= $(VERIFIED_RUN_ROOT)/build
VERIFIED_SOURCE_ROOT ?= $(VERIFIED_RUN_ROOT)/src
VERIFIED_TMP_ROOT ?= $(VERIFIED_RUN_ROOT)/tmp
VERIFIED_LOG_ROOT ?= $(VERIFIED_RUN_ROOT)/logs
# Cache-v2 is deliberately separate from ephemeral connector build/run trees.
# The shared child is the only reusable component cache passed to all targets.
CACHE_ROOT ?= $(VERIFIED_RUN_ROOT)/cache-v2
VERIFIED_COMPONENT_CACHE ?= $(CACHE_ROOT)/shared
VERIFIED_EVIDENCE_ROOT ?= $(VERIFIED_RUN_ROOT)/evidence
RUNTIME_RUN_ROOT ?= $(VERIFIED_RUN_ROOT)/runs
RUNTIME_LOG_ROOT ?= $(VERIFIED_RUN_ROOT)/run-logs
STATE_HOME ?= $(VERIFIED_STATE_ROOT)
SOURCE_ROOT ?= $(VERIFIED_SOURCE_ROOT)
BUILD_ROOT ?= $(VERIFIED_BUILD_ROOT)
# Host harnesses may create connector-local transient files and require their
# temporary root to remain below BUILD_ROOT.  Keep the legacy verified tmp
# root available for callers that need it, but make the standard target
# default build-contained so no inherited run-root tmp path can block HAProxy.
TMP_ROOT ?= $(BUILD_ROOT)/tmp
LOG_ROOT ?= $(BUILD_ROOT)/logs
MATRIX_ROOT ?= $(BUILD_ROOT)/full-matrix
FRAMEWORK_ROOT ?= $(CURDIR)/modules/ModSecurity-test-Framework
CONNECTOR_ROOT := $(CURDIR)
# Keep the six native profiles as the default, while allowing a bounded
# connector subset for isolated diagnostics without editing the Makefile.
NO_CRS_CONNECTORS ?= apache nginx haproxy envoy traefik lighttpd
EVIDENCE_ROOT ?= $(VERIFIED_EVIDENCE_ROOT)/no-crs-evidence
RUNTIME_EVIDENCE_ROOT ?= $(VERIFIED_EVIDENCE_ROOT)/runtime-evidence
CAPABILITY_PLAN_ROOT ?= $(BUILD_ROOT)/no-crs-capability-plans
CAPABILITY_REPORT_EVIDENCE_ROOT ?= $(EVIDENCE_ROOT)
CAPABILITY_REPORT_RUN_ID ?= $(NO_CRS_RUN_ID)
CAPABILITY_REPORT_OUTPUT_DIR ?= $(EVIDENCE_ROOT)/connector-capabilities
NO_CRS_RUN_ID ?=
NO_CRS_RULES_FILE ?= $(FRAMEWORK_ROOT)/tests/rules/no-crs-baseline.conf
# Optional managed client bundle for a forced modern-protocol run.  The
# canonical root runner validates that it stays inside the invocation's raw
# evidence tree before passing it to Framework finalization.
NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR ?=
# Opt in to a stage-owned protocol probe without having to pre-create the
# fresh raw-run directory.  It is non-promoting unless every protocol case,
# client observation, and host event passes the Framework's causal checks.
NO_CRS_PROTOCOL_CLIENT ?= 0
REQUESTED_VERIFIED_RUN_ID := $(VERIFIED_RUN_ID)
DEFAULT_VERIFIED_RUN_ID := $(shell date -u +%Y-%m-%dT%H-%M-%SZ)-$(shell git rev-parse --short=8 HEAD 2>/dev/null || printf unknown)
EXISTING_VERIFIED_RUN_ID := $(shell "$(PYTHON)" -c 'import json,pathlib; p=pathlib.Path("reports/testing/generated/manifest/verified-run-manifest.generated.json"); d=json.loads(p.read_text()) if p.is_file() else {}; print(d.get("verified_run_id") or d.get("metadata", {}).get("verified_run_id") or "")' 2>/dev/null)
VERIFIED_RUN_ID := $(if $(REQUESTED_VERIFIED_RUN_ID),$(REQUESTED_VERIFIED_RUN_ID),$(if $(EXISTING_VERIFIED_RUN_ID),$(EXISTING_VERIFIED_RUN_ID),$(DEFAULT_VERIFIED_RUN_ID)))
FRESH_VERIFIED_RUN_ID := $(if $(REQUESTED_VERIFIED_RUN_ID),$(REQUESTED_VERIFIED_RUN_ID),$(DEFAULT_VERIFIED_RUN_ID))
CONNECTOR_COMPONENT_CACHE ?= $(VERIFIED_COMPONENT_CACHE)
NGINX_HARNESS_PARENT ?= $(BUILD_ROOT)/nginx-harness
MRTS_BUILD_ROOT ?= $(BUILD_ROOT)/mrts
MRTS_NATIVE_ROOT ?= $(BUILD_ROOT)/mrts-native
MRTS_NATIVE_TARGETS ?= apache2_ubuntu nginx-pr24
MRTS_NATIVE_APACHE_PORT ?= 19080
MRTS_NATIVE_NGINX_PORT ?= 19081
MRTS_NATIVE_BACKEND_PORT ?= 19082
GO_FTW_BIN ?= go-ftw
ALBEDO_BIN ?= albedo
VERIFIED_RUN_RUNTIME_MATRIX_TIMEOUT_SECONDS ?= 1800
VERIFIED_RUN_FULL_MATRIX_RUNTIME_TIMEOUT_SECONDS ?= $(if $(filter undefined,$(origin VERIFIED_RUN_FULL_MATRIX_TIMEOUT_SECONDS)),7200,$(VERIFIED_RUN_FULL_MATRIX_TIMEOUT_SECONDS))
VERIFIED_RUN_REPORT_REFRESH_TIMEOUT_SECONDS ?= 1800
VERIFIED_RUN_NATIVE_MRTS_TIMEOUT_SECONDS ?= 1800
VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS ?= 3600
VERIFIED_RUN_JOB_FINALIZE_GRACE_SECONDS ?= 60
VERIFIED_RUN_FULL_MATRIX_TOTAL_TIMEOUT_SECONDS ?= 14400
SKIP_RUNTIME_COMPONENT_PREPARE ?= 0
RUNTIME_COMPONENT_STRICT_VERIFY ?= 0
KEEP_RUNTIME_ARTIFACTS ?= 0
PYTHONDONTWRITEBYTECODE ?= 1
WITH_RUNTIME_COMPONENTS = SKIP_RUNTIME_COMPONENT_PREPARE=1 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/provisioning/cache/with-runtime-components.sh

export BUILD_ROOT
export SOURCE_ROOT
export TMP_ROOT
export LOG_ROOT
export MATRIX_ROOT
export VERIFIED_RUN_ROOT
export VERIFIED_STATE_ROOT
export VERIFIED_BUILD_ROOT
export VERIFIED_SOURCE_ROOT
export VERIFIED_TMP_ROOT
export VERIFIED_LOG_ROOT
export VERIFIED_COMPONENT_CACHE
export CACHE_ROOT
export VERIFIED_EVIDENCE_ROOT
export RUNTIME_RUN_ROOT
export RUNTIME_LOG_ROOT
export VERIFIED_RUN_ID
export VERIFIED_RUN_RUNTIME_MATRIX_TIMEOUT_SECONDS
export VERIFIED_RUN_FULL_MATRIX_RUNTIME_TIMEOUT_SECONDS
export VERIFIED_RUN_REPORT_REFRESH_TIMEOUT_SECONDS
export VERIFIED_RUN_NATIVE_MRTS_TIMEOUT_SECONDS
export VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS
export VERIFIED_RUN_JOB_FINALIZE_GRACE_SECONDS
export VERIFIED_RUN_FULL_MATRIX_TOTAL_TIMEOUT_SECONDS
export RESULTS_DIR
export FRAMEWORK_ROOT
export CONNECTOR_ROOT
export EVIDENCE_ROOT
export RUNTIME_EVIDENCE_ROOT
export CAPABILITY_PLAN_ROOT
export NO_CRS_RUN_ID
export NO_CRS_RULES_FILE
export NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR
export NO_CRS_PROTOCOL_CLIENT
export NGINX_HARNESS_PARENT
export PYTHON
export PYTHONDONTWRITEBYTECODE
export DEFAULT_BRANCH
export REFRESH
export SMOKE_CASES
export CASE_SCOPE
export FORCE_ALL_CASES
export MODSECURITY_REPO_URL
export MODSECURITY_GIT_REF
export MODSECURITY_APACHE_REPO_URL
export MODSECURITY_NGINX_REPO_URL
export ALLOW_EXTERNAL_CONNECTOR_REPOS
export MODSECURITY_SOURCE_DIR
export MODSECURITY_V3_SOURCE_DIR
export MODSECURITY_V3_ROOT
export MODSECURITY_APACHE_SOURCE_DIR
export MODSECURITY_NGINX_SOURCE_DIR
export MODSECURITY_V3_GIT_URL
export MODSECURITY_V3_GIT_REF
export MODSECURITY_APACHE_GIT_URL
export MODSECURITY_APACHE_GIT_REF
export MODSECURITY_NGINX_GIT_URL
export MODSECURITY_NGINX_GIT_REF
export MODSECURITY_TEST_VARIANT
export MODSECURITY_MRTS_VARIANT
export MODSECURITY_RULESET
export MODSECURITY_SMOKE_CASE
export CRS_SMOKE_CASE
export MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO
export MODSECURITY_MRTS_PREPARED
export EXTRA_CASE_ROOTS
export MRTS_ROOT
export MRTS_DEFINITIONS
export MRTS_RULES_OUT
export MRTS_FTW_OUT
export MRTS_LOAD_FILE
export MRTS_CASE_ROOT
export MRTS_BUILD_ROOT
export MRTS_NATIVE_ROOT
export MRTS_NATIVE_TARGETS
export MRTS_NATIVE_APACHE_PORT
export MRTS_NATIVE_NGINX_BIN
export MRTS_NATIVE_NGINX_MODULE_DIR
export MRTS_NATIVE_NGINX_PORT
export MRTS_NATIVE_BACKEND_PORT
export GO_FTW_BIN
export GO_FTW_SOURCE_URL
export GO_FTW_PROMPT_EXPECTED_LATEST
export GO_FTW_GIT_REF
export ALBEDO_BIN
export ALBEDO_SOURCE_URL
export ALBEDO_PROMPT_EXPECTED_LATEST
export ALBEDO_GIT_REF
# The Framework snapshots active provenance inputs before applying its reviewed
# defaults.  Preserve the absence of optional Parent inputs; explicit empty and
# altered values must remain visible so the Framework can reject them fail closed.
define export_framework_optional_provenance
ifneq ($(origin $(1)),undefined)
export $(1)
endif
endef

override FRAMEWORK_OPTIONAL_PROVENANCE_EXPORTS := \
	CRS_REPO_URL \
	CRS_GIT_REF \
	NGINX_SOURCE_MODE \
	NGINX_SOURCE_REPO_URL \
	NGINX_SOURCE_GIT_REF \
	NGINX_GITHUB_REPO \
	NGINX_RELEASE_TAG \
	HAPROXY_VERSION \
	HAPROXY_SOURCE_URL \
	HAPROXY_SHA256_URL \
	HAPROXY_SHA256 \
	HTTPD_VERSION \
	HTTPD_SOURCE_URL \
	HTTPD_SHA256 \
	HTTPD_SHA256_URL \
	APR_VERSION \
	APR_SOURCE_URL \
	APR_SHA256 \
	APR_SHA256_URL \
	APR_UTIL_VERSION \
	APR_UTIL_SOURCE_URL \
	APR_UTIL_SHA256 \
	APR_UTIL_SHA256_URL \
	PCRE2_VERSION \
	PCRE2_SOURCE_URL \
	PCRE2_SHA256 \
	PCRE2_SHA256_URL

$(foreach framework_optional_provenance,$(FRAMEWORK_OPTIONAL_PROVENANCE_EXPORTS),$(eval $(call export_framework_optional_provenance,$(framework_optional_provenance))))

export CRS_SOURCE_DIR
export CRS_RUNTIME_DIR
export MODSECURITY_RULE_PREAMBLE_FILE
export BUILD_HTTPD_FROM_SOURCE
export BUILD_PCRE2_FROM_SOURCE
export BUILD_NGINX_FROM_SOURCE
export HAPROXY_SOURCE_ROOT
export HAPROXY_DOWNLOAD_DIR
export HAPROXY_SOURCE_DIR
export HAPROXY_RUNTIME_BUILD_DIR
export HAPROXY_RUNTIME_BUILD_WORKTREE
export HAPROXY_RUNTIME_DIR
export HAPROXY_BIN
export EXPAT_SOURCE_URL
export EXPAT_GIT_REF
export EXPAT_GIT_URL
export EXPAT_PROMPT_EXPECTED_LATEST

.PHONY: framework-apr-util-env
framework-apr-util-env:
	@/bin/sh "$(CURDIR)/ci/tools/print-framework-apr-util-env.sh" "$(FRAMEWORK_ROOT)" "$(CURDIR)"
export APACHE_BIN
export APACHECTL_BIN
export APXS_BIN
export NGINX_BIN
export RESPONSE_BODY_PROBE_REPEAT
export RESPONSE_BODY_PROBE_ROOT
export RESPONSE_BODY_PROBE_CASE
export CONNECTOR_COMPONENT_CACHE
export SKIP_RUNTIME_COMPONENT_PREPARE
export RUNTIME_COMPONENT_STRICT_VERIFY
export KEEP_RUNTIME_ARTIFACTS
export DECISION_BACKEND
export ENVOY_DECISION_BACKEND
export TRAEFIK_DECISION_BACKEND
export LIGHTTPD_DECISION_BACKEND

.PHONY: check-framework prepare-runtime-components prepare-envoy-runtime prepare-traefik-runtime prepare-lighttpd-runtime prepare-lighttpd-runtime-build prepare-open-connector-runtimes runtime-components-inventory runtime-components-sources check-framework-fixture-syntax check-runtime-producer-readiness check-runtime-path-policy check-bilingual-docs check-doc-links check-variable-documentation check-connector-config-reference generate-connector-config-reference refresh-connector-reports refresh-all-reports check-generated-report-layout report-governance verified-report-evidence-gate generate-system-environment-proof prove-generated-reports verified-runtime-producers verified-report-refresh verified-report-producers verified-report-consumers verified-report-checks verified-report-run verified-report-run-soft verified-report-run-smoke verified-full-matrix-job verified-case verified-native-case verified-apache-case verified-nginx-case verified-haproxy-case verified-full-matrix-resume full-matrix-single-job-runtime full-matrix-resume-runtime smoke-common smoke-apache smoke-nginx soak-nginx smoke-envoy smoke-envoy-modsecurity smoke-envoy-crs smoke-envoy-crs-secondary smoke-haproxy smoke-lighttpd smoke-lighttpd-modsecurity smoke-lighttpd-crs smoke-lighttpd-crs-secondary smoke-traefik smoke-traefik-modsecurity smoke-traefik-crs smoke-traefik-crs-secondary smoke-open-connectors-crs smoke-open-connectors-crs-secondary smoke-new-connectors smoke-all test test-no-crs test-with-crs test-haproxy-no-crs test-haproxy-with-crs runtime-matrix runtime-matrix-all runtime-matrix-all-runtime runtime-matrix-haproxy full-runtime-matrix full-mrts-runtime-matrix mrts-only-full-run full-matrix-parallel full-matrix-parallel-runtime generate-full-runtime-matrix generate-full-matrix-job-completeness generate-nginx-mrts-http500-cluster-analysis generate-work-queue generate-phase-work-queue generate-nolog-audit-evidence-analysis generate-response-header-hook-analysis generate-phase4-hard-abort-capability generate-intervention-blocking-analysis generate-no-mrts-intervention-nomatch-analysis generate-body-processor-analysis generate-rule-chain-semantics-analysis generate-final-consistency-audit generate-native-semantics-comparison generate-remaining-critical-batch-analysis generate-remaining-failure-analysis mrts-native-full-run mrts-native-full-run-runtime mrts-native-apache-full mrts-native-nginx-pr24-full mrts-upstream-infra-check probe-response-body connector-starter-checks lint summary case-matrix setup-dev install-dev-deps doctor doctor-quick env-check fetch-deps fetch-modsecurity-v3 fetch-crs prepare-crs bootstrap-runtime quick-check codex-check quick-all smoke-installed installed-readiness doctor-install-hints cloud-quick-check generate-test-matrix check-test-matrix mrts-generate mrts-load mrts-import test-no-mrts test-with-mrts-feature-demo test-mrts-matrix mrts-ftw
.PHONY: smoke-envoy-request-body smoke-traefik-request-body smoke-lighttpd-request-body smoke-open-connectors-request-body
.PHONY: with-crs-no-mrts-runtime
.PHONY: memcheck-nginx
.PHONY: check-compiler-guides
.PHONY: check-connector-guides
.PHONY: check-ci-security-contract
.PHONY: check-go-version-contract
.PHONY: check-analysis-tools compile-db-nginx-c17 check-targeted-evaluator-cpp17 compile-db-cpp17 check-clangd-c17
.PHONY: check-clang-analysis-tools clang-tidy-baseline clang-analyzer-baseline clang-analysis-baseline
.PHONY: build-apache build-nginx build-haproxy build-envoy build-traefik build-lighttpd build-all-connectors
.PHONY: check-config-apache check-config-nginx check-config-haproxy check-config-envoy check-config-traefik check-config-lighttpd check-config-all-connectors
.PHONY: start-smoke-apache start-smoke-nginx start-smoke-haproxy start-smoke-all-connectors
.PHONY: runtime-smoke-apache runtime-smoke-nginx runtime-smoke-haproxy runtime-smoke-all-connectors
.PHONY: no-crs-baseline-apache no-crs-baseline-nginx no-crs-baseline-haproxy no-crs-baseline-envoy no-crs-baseline-traefik no-crs-baseline-lighttpd no-crs-baseline-all-connectors
.PHONY: capabilities-apache capabilities-nginx capabilities-haproxy capabilities-envoy capabilities-traefik capabilities-lighttpd capabilities-all-connectors capabilities-all-connectors-evidence
.PHONY: evidence-check-apache evidence-check-nginx evidence-check-haproxy evidence-check-envoy evidence-check-traefik evidence-check-lighttpd evidence-check-all-connectors
.PHONY: check-no-crs-result-schema check-no-crs-evidence-completeness check-no-crs-capability-consistency check-no-crs-claim-policy check-no-crs-artifact-layout check-no-crs-body-payload-absence check-no-crs-status-consistency check-no-crs-protocol-client check-no-crs-doc-consistency check-no-crs-source-normalization
.PHONY: full-lifecycle-apache full-lifecycle-nginx full-lifecycle-haproxy full-lifecycle-envoy full-lifecycle-traefik full-lifecycle-lighttpd full-lifecycle-all-connectors
.PHONY: full-lifecycle-haproxy-htx full-lifecycle-envoy-ext-proc full-lifecycle-traefik-native full-lifecycle-lighttpd-patched
.PHONY: check-first-byte-before-response-end check-no-full-response-buffering check-full-lifecycle-event-privacy check-full-lifecycle-transport check-full-lifecycle-lifecycle check-full-lifecycle-transport-hardening check-full-lifecycle-promotion check-six-connector-core-completion
.PHONY: protocol-client check-protocol-evidence test-protocol-client

define RUN_WITH_REFRESH_ALL
	@set +e; \
	$(1); \
	runtime_rc=$$?; \
	set -e; \
	refresh_rc=0; \
	$(MAKE) refresh-all-reports || refresh_rc=$$?; \
	if [ "$$runtime_rc" -ne 0 ]; then exit "$$runtime_rc"; fi; \
	exit "$$refresh_rc"
endef

check-framework:
	@test -d "$(FRAMEWORK_ROOT)" || { \
		echo "BLOCKED: FRAMEWORK_ROOT is missing: $(FRAMEWORK_ROOT)"; \
		echo "Hint: run git submodule update --init --recursive or set FRAMEWORK_ROOT=/path/to/ModSecurity-test-Framework"; \
		exit 77; \
	}

# Forward the opt-in managed protocol client and its evidence gate from the
# Framework without implying that a host build alone is protocol evidence.
protocol-client: check-framework
	$(MAKE) -C "$(FRAMEWORK_ROOT)" protocol-client CONNECTOR_ROOT="$(CURDIR)" BUILD_ROOT="$(BUILD_ROOT)"

check-protocol-evidence: check-framework
	$(MAKE) -C "$(FRAMEWORK_ROOT)" check-protocol-evidence CONNECTOR_ROOT="$(CURDIR)" BUILD_ROOT="$(BUILD_ROOT)"

test-protocol-client: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	$(MAKE) -C "$(FRAMEWORK_ROOT)" test-protocol-client CONNECTOR_ROOT="$(CURDIR)" BUILD_ROOT="$(BUILD_ROOT)"
else
	$(ACTIVE_TEST_RUNNER) --group protocol
endif

check-framework-fixture-syntax: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/evidence/check-framework-fixture-syntax.py --framework-root "$(FRAMEWORK_ROOT)"

prepare-runtime-components: check-framework
	@if [ "$(SKIP_RUNTIME_COMPONENT_PREPARE)" = "1" ]; then \
		echo "prepare-runtime-components: skipped (SKIP_RUNTIME_COMPONENT_PREPARE=1)"; \
	else \
		PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/provisioning/components/prepare-runtime-components.sh; \
	fi

prepare-envoy-runtime: check-framework
	FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh "$(FRAMEWORK_ROOT)/ci/provisioning/prepare-envoy-runtime.sh"

prepare-traefik-runtime: check-framework
	FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh "$(FRAMEWORK_ROOT)/ci/provisioning/prepare-traefik-runtime.sh"

prepare-lighttpd-runtime: check-framework
	FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh "$(FRAMEWORK_ROOT)/ci/provisioning/prepare-lighttpd-runtime.sh"

prepare-lighttpd-runtime-build: check-framework
	ALLOW_RUNTIME_BUILDS=1 $(MAKE) prepare-lighttpd-runtime

prepare-open-connector-runtimes: check-framework
	@rc=0; \
	for target in prepare-envoy-runtime prepare-traefik-runtime prepare-lighttpd-runtime; do \
		$(MAKE) $$target || rc=$$?; \
	done; \
	exit $$rc

runtime-components-inventory: check-framework
	FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/provisioning/cache/runtime-components-inventory.sh inventory

runtime-components-sources: check-framework
	FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/provisioning/cache/runtime-components-inventory.sh sources

check-runtime-producer-readiness: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/evidence/check-runtime-producer-readiness.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)"

check-runtime-path-policy: check-framework
	$(ACTIVE_TEST_RUNNER) --group runtime-path-policy

check-bilingual-docs:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/documentation/check-bilingual-docs.py

check-ci-security-contract: check-project-versions
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest -v modsecurity_connector_tests.test_ci_security_workflows modsecurity_connector_tests.test_lint_workflows modsecurity_connector_tests.test_nginx_exact_head_gate_contract modsecurity_connector_tests.test_framework_revision_pins modsecurity_connector_tests.test_project_toolchain_pins modsecurity_connector_tests.test_validate_submodule_candidate_state modsecurity_connector_tests.test_update_submodules_local_git modsecurity_connector_tests.test_update_framework_versions modsecurity_connector_tests.test_verify_framework_candidate_contract modsecurity_connector_tests.test_prepare_readonly_submodule_validation_sandbox modsecurity_connector_tests.test_run_readonly_submodule_validation_namespace modsecurity_connector_tests.ci_security.test_update_workflow_tools.WorkflowToolUpdaterTests modsecurity_connector_tests.test_install_ci_dependencies modsecurity_connector_tests.test_python_version_contract.WorkflowActionPinsTest
else
	$(ACTIVE_TEST_RUNNER) --group supply-chain
endif
	$(PYTHON) ci/tools/fetch_security_tool.py --tool actionlint --validate-only
	$(PYTHON) ci/tools/fetch_security_tool.py --tool zizmor --validate-only
	$(PYTHON) ci/tools/fetch_security_tool.py --tool gitleaks --validate-only

.PHONY: check-bounded-smoke-runtime-contract
check-bounded-smoke-runtime-contract: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest -v modsecurity_connector_tests.test_full_smoke_workflow_contract modsecurity_connector_tests.test_bounded_nginx_cases modsecurity_connector_tests.test_nginx_harness_path_authority modsecurity_connector_tests.test_resolve_traefik_host_binary modsecurity_connector_tests.test_runtime_path_utils modsecurity_connector_tests.test_resolve_lighttpd_host_binary modsecurity_connector_tests.test_trusted_lighttpd_namespace_dispatch_workflow modsecurity_connector_tests.test_apache_process_guard
else
	$(ACTIVE_TEST_RUNNER) --group common
endif

check-variable-documentation:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/documentation/check-variable-documentation.py

check-compiler-guides:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_compiler_guides
else
	$(ACTIVE_TEST_RUNNER) --group supply-chain
endif

check-connector-guides:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_connector_guides
else
	$(ACTIVE_TEST_RUNNER) --group supply-chain
endif

check-analysis-tools:
	PYTHONDONTWRITEBYTECODE=1 CC="$(CC)" CXX="$(CXX)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/analysis/check-analysis-tools.sh

check-clang-analysis-tools:
	PYTHONDONTWRITEBYTECODE=1 PYTHON="$(PYTHON)" CLANG_TIDY="$(CLANG_TIDY)" CLANG="$(CLANG)" CLANGXX="$(CLANGXX)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/analysis/check-clang-analysis-tools.sh

clang-tidy-baseline:
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/analysis/clang_analysis_baseline.py --mode tidy --compdb-output "$(COMPDB_OUTPUT)" --analysis-output "$(ANALYSIS_OUTPUT)" --clang-tidy "$(CLANG_TIDY)" --clang "$(CLANG)" --clangxx "$(CLANGXX)" --tidy-checks="$(CLANG_TIDY_CHECKS)" --analyzer-checks="$(CLANG_ANALYZER_CHECKS)"

clang-analyzer-baseline:
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/analysis/clang_analysis_baseline.py --mode analyzer --compdb-output "$(COMPDB_OUTPUT)" --analysis-output "$(ANALYSIS_OUTPUT)" --clang-tidy "$(CLANG_TIDY)" --clang "$(CLANG)" --clangxx "$(CLANGXX)" --tidy-checks="$(CLANG_TIDY_CHECKS)" --analyzer-checks="$(CLANG_ANALYZER_CHECKS)"

clang-analysis-baseline:
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/analysis/clang_analysis_baseline.py --mode combined --compdb-output "$(COMPDB_OUTPUT)" --analysis-output "$(ANALYSIS_OUTPUT)" --clang-tidy "$(CLANG_TIDY)" --clang "$(CLANG)" --clangxx "$(CLANGXX)" --tidy-checks="$(CLANG_TIDY_CHECKS)" --analyzer-checks="$(CLANG_ANALYZER_CHECKS)"

compile-db-nginx-c17:
	PYTHONDONTWRITEBYTECODE=1 CC="$(CC)" PYTHON="$(PYTHON)" COMPDB_OUTPUT="$(COMPDB_OUTPUT)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/analysis/compile-db-nginx-c17.sh

check-targeted-evaluator-cpp17:
	PYTHONDONTWRITEBYTECODE=1 CXX="$(CXX)" CPP_BUILD_ROOT="$(CPP_BUILD_ROOT)" MODSECURITY_INCLUDE_DIR="$(MODSECURITY_INCLUDE_DIR)" MODSECURITY_LIB_DIR="$(MODSECURITY_LIB_DIR)" MODSECURITY_LIB_FILE="$(MODSECURITY_LIB_FILE)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/analysis/check-targeted-evaluator-cpp17.sh

compile-db-cpp17:
	PYTHONDONTWRITEBYTECODE=1 CXX="$(CXX)" PYTHON="$(PYTHON)" COMPDB_OUTPUT="$(COMPDB_OUTPUT)" CPP_BUILD_ROOT="$(CPP_BUILD_ROOT)" MODSECURITY_INCLUDE_DIR="$(MODSECURITY_INCLUDE_DIR)" MODSECURITY_LIB_DIR="$(MODSECURITY_LIB_DIR)" MODSECURITY_LIB_FILE="$(MODSECURITY_LIB_FILE)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/analysis/compile-db-cpp17.sh

check-clangd-c17:
	PYTHONDONTWRITEBYTECODE=1 PYTHON="$(PYTHON)" COMPDB_OUTPUT="$(COMPDB_OUTPUT)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/analysis/check-clangd-c17.sh

generate-connector-config-reference:
	$(PYTHON) ci/tools/generate-connector-config-reference.py

check-connector-config-reference:
	$(PYTHON) ci/tools/generate-connector-config-reference.py --check
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/documentation/check-connector-config-reference.py

check-doc-links: check-framework
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/documentation/check-repository-path-references.py
	CONNECTOR_ROOT="$(CURDIR)" $(PYTHON) "$(FRAMEWORK_ROOT)/ci/checks/documentation/check-doc-links.py"

refresh-connector-reports: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/refresh-connector-reports.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --native-root "$(MRTS_NATIVE_ROOT)"

refresh-all-reports: check-framework
	@framework_rc=0; \
	$(MAKE) -C "$(FRAMEWORK_ROOT)" PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" OUTPUT_ROOT="$(FRAMEWORK_ROOT)" refresh-framework-reports || framework_rc=$$?; \
	connector_rc=0; \
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/refresh-connector-reports.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --native-root "$(MRTS_NATIVE_ROOT)" --strict-inputs || connector_rc=$$?; \
	if [ "$$framework_rc" -ne 0 ]; then exit "$$framework_rc"; fi; \
	exit "$$connector_rc"

check-generated-report-layout: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/documentation/check-generated-report-layout.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"

report-governance: check-framework
	$(MAKE) check-runtime-path-policy
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/documentation/check-generated-report-layout.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --governance-only

verified-report-evidence-gate: check-generated-report-layout
	@echo "verified-report-evidence-gate: strict generated-report evidence gate passed"

generate-system-environment-proof: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-system-environment-proof.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --output-dir "$(CURDIR)/reports/testing/generated/manifest"

generate-verified-runtime-mismatch-analysis: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-verified-runtime-mismatch-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --output-dir "$(CURDIR)/reports/testing/generated/manifest"

generate-remaining-critical-batch-analysis: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-remaining-critical-batch-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --output-dir "$(CURDIR)/reports/testing/generated/manifest"

generate-native-semantics-comparison: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-native-case-comparison.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --verified-run-root "$(VERIFIED_RUN_ROOT)" --output-dir "$(CURDIR)/reports/testing/generated/manifest" --report-only

prove-generated-reports:
	$(MAKE) refresh-connector-reports
	$(MAKE) check-generated-report-layout
	$(MAKE) lint
	$(MAKE) quick-check
	$(MAKE) generate-system-environment-proof

verified-runtime-producers: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	VERIFIED_RUN_ID="$(FRESH_VERIFIED_RUN_ID)" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-verified-report-run.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --phase runtime-producers

verified-report-producers: verified-runtime-producers

verified-report-refresh: check-framework
	@run_id="$${VERIFIED_RUN_ID:-$$(cat "$(BUILD_ROOT)/verified-runs/current-run-id" 2>/dev/null || true)}"; \
	if [ -z "$$run_id" ]; then run_id="$(FRESH_VERIFIED_RUN_ID)"; fi; \
	VERIFIED_RUN_ID="$$run_id" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-verified-report-run.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --phase report-refresh

verified-report-consumers: check-framework
	@run_id="$${VERIFIED_RUN_ID:-$$(cat "$(BUILD_ROOT)/verified-runs/current-run-id" 2>/dev/null || true)}"; \
	if [ -z "$$run_id" ]; then run_id="$(FRESH_VERIFIED_RUN_ID)"; fi; \
	VERIFIED_RUN_ID="$$run_id" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-verified-report-run.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --phase report-refresh

verified-report-checks: check-framework
	@run_id="$${VERIFIED_RUN_ID:-$$(cat "$(BUILD_ROOT)/verified-runs/current-run-id" 2>/dev/null || true)}"; \
	if [ -z "$$run_id" ]; then run_id="$(FRESH_VERIFIED_RUN_ID)"; fi; \
	VERIFIED_RUN_ID="$$run_id" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-verified-report-run.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --phase checks

verified-report-run: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	VERIFIED_RUN_ID="$(FRESH_VERIFIED_RUN_ID)" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-verified-report-run.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --mode strict

verified-report-run-soft: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	VERIFIED_RUN_ID="$(FRESH_VERIFIED_RUN_ID)" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-verified-report-run.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --mode soft

verified-report-run-smoke: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	VERIFIED_RUN_ID="$(FRESH_VERIFIED_RUN_ID)" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-verified-report-run.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --mode soft --profile smoke

verified-full-matrix-job: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	@test -n "$(CONNECTOR)" || { echo "CONNECTOR is required, e.g. CONNECTOR=nginx"; exit 2; }
	@test -n "$(CRS)" || { echo "CRS is required, e.g. CRS=with-crs"; exit 2; }
	@test -n "$(MRTS)" || { echo "MRTS is required, e.g. MRTS=with-mrts"; exit 2; }
	@run_id="$${VERIFIED_RUN_ID:-$$(cat "$(BUILD_ROOT)/verified-runs/current-run-id" 2>/dev/null || true)}"; \
	if [ -z "$$run_id" ]; then run_id="$(FRESH_VERIFIED_RUN_ID)"; fi; \
	VERIFIED_RUN_ID="$$run_id" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-verified-report-run.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --phase full-matrix-job --connector "$(CONNECTOR)" --crs "$(CRS)" --mrts "$(MRTS)"

verified-case: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	@test -n "$(CONNECTOR)" || { echo "CONNECTOR is required, e.g. CONNECTOR=nginx"; exit 2; }
	@test -n "$(CASE)" || { echo "CASE is required, e.g. CASE=action_deny_phase1"; exit 2; }
	@test -n "$(CRS)" || { echo "CRS is required, e.g. CRS=with-crs"; exit 2; }
	@test -n "$(MRTS)" || { echo "MRTS is required, e.g. MRTS=with-mrts"; exit 2; }
	@explain_args=""; \
	case "$${EXPLAIN:-$(EXPLAIN)}$${VERIFIED_CASE_EXPLAIN:-$(VERIFIED_CASE_EXPLAIN)}" in ""|0|false|False) $(MAKE) prepare-runtime-components ;; *) explain_args="--explain" ;; esac; \
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-verified-case.py --connector "$(CONNECTOR)" --case "$(CASE)" --crs "$(CRS)" --mrts "$(MRTS)" --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --source-root "$(SOURCE_ROOT)" --tmp-root "$(TMP_ROOT)" --verified-run-root "$(VERIFIED_RUN_ROOT)" --python "$(FRAMEWORK_PYTHON)" $$explain_args

verified-native-case: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	@test -n "$(CASE)" || { echo "CASE is required, e.g. CASE=unicode_whitespace_normalization_gap"; exit 2; }
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" CONNECTOR_ROOT="$(CURDIR)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" BUILD_ROOT="$(BUILD_ROOT)" VERIFIED_RUN_ROOT="$(VERIFIED_RUN_ROOT)" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-native-case-comparison.py --case "$(CASE)" --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --verified-run-root "$(VERIFIED_RUN_ROOT)" --output-dir "$(CURDIR)/reports/testing/generated/manifest"

verified-nginx-case: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	@test -n "$(CASE)" || { echo "CASE is required, e.g. CASE=action_deny_phase1"; exit 2; }
	@test -n "$(CRS)" || { echo "CRS is required, e.g. CRS=with-crs"; exit 2; }
	@test -n "$(MRTS)" || { echo "MRTS is required, e.g. MRTS=with-mrts"; exit 2; }
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" FORCE_ALL_CASES=1 MODSECURITY_TEST_VARIANT="$(CRS)" MODSECURITY_MRTS_VARIANT="$(MRTS)" TEST_CASE="$(CASE)" CASE_SCOPE=all RESULTS_DIR="$(BUILD_ROOT)/verified-nginx-case/$(CRS)/$(MRTS)/results" NGINX_HARNESS_WORK_ROOT="$(BUILD_ROOT)/verified-nginx-case/$(CRS)-$(MRTS)-nginx" sh "$(FRAMEWORK_ROOT)/ci/runtime/run-nginx-smoke.sh"

verified-apache-case: check-framework prepare-runtime-components
	@if [ "$(ON_DEMAND_TESTS)" != 1 ]; then \
		[ "$(CASE):$(CRS):$(MRTS)" = crs_sqli_anomaly_block:with-crs:no-mrts ] || { echo "FAIL: case is outside the active CRS inventory" >&2; exit 2; }; \
		$(ACTIVE_TEST_RUNNER) --check --execution runtime.crs.apache; \
	fi
	@test -n "$(CASE)" || { echo "CASE is required, e.g. CASE=action_deny_phase1"; exit 2; }
	@test -n "$(CRS)" || { echo "CRS is required, e.g. CRS=with-crs"; exit 2; }
	@test -n "$(MRTS)" || { echo "MRTS is required, e.g. MRTS=with-mrts"; exit 2; }
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" SOURCE_ROOT="$(SOURCE_ROOT)" CRS_SOURCE_DIR="$(CRS_SOURCE_DIR)" FORCE_ALL_CASES=1 MODSECURITY_TEST_VARIANT="$(CRS)" MODSECURITY_MRTS_VARIANT="$(MRTS)" TEST_CASE="$(CASE)" CASE_SCOPE=all RESULTS_DIR="$(BUILD_ROOT)/verified-apache-case/$(CRS)/$(MRTS)/results" APACHE_RUNTIME_LOG_DIR="$(BUILD_ROOT)/verified-apache-case/$(CRS)-$(MRTS)-apache/logs/apache-runtime" RUNTIME_BASE="$(BUILD_ROOT)/verified-apache-case/$(CRS)-$(MRTS)-apache/apache-runtime" sh "$(FRAMEWORK_ROOT)/ci/runtime/run-apache-smoke.sh"

verified-haproxy-case: check-framework prepare-runtime-components
	@if [ "$(ON_DEMAND_TESTS)" != 1 ]; then \
		[ "$(CASE):$(CRS):$(MRTS)" = crs_sqli_anomaly_block:with-crs:no-mrts ] || { echo "FAIL: case is outside the active CRS inventory" >&2; exit 2; }; \
		$(ACTIVE_TEST_RUNNER) --check --execution runtime.crs.haproxy; \
	fi
	@test -n "$(CASE)" || { echo "CASE is required, e.g. CASE=action_deny_phase1"; exit 2; }
	@test -n "$(CRS)" || { echo "CRS is required, e.g. CRS=with-crs"; exit 2; }
	@test -n "$(MRTS)" || { echo "MRTS is required, e.g. MRTS=with-mrts"; exit 2; }
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" SOURCE_ROOT="$${SOURCE_ROOT}" CRS_SOURCE_DIR="$${CRS_SOURCE_DIR}" BUILD_ROOT="$(BUILD_ROOT)" TMP_ROOT="$(BUILD_ROOT)/verified-haproxy-case/$(CRS)-$(MRTS)-haproxy/tmp" FORCE_ALL_CASES=1 MODSECURITY_TEST_VARIANT="$(CRS)" MODSECURITY_MRTS_VARIANT="$(MRTS)" TEST_CASE="$(CASE)" RUN_ONE_CASE=1 CASE_SCOPE=all RESULTS_DIR="$(BUILD_ROOT)/verified-haproxy-case/$(CRS)/$(MRTS)/results" LOG_ROOT="$(BUILD_ROOT)/verified-haproxy-case/$(CRS)-$(MRTS)-haproxy/logs" RUNTIME_BASE="$(BUILD_ROOT)/verified-haproxy-case/$(CRS)-$(MRTS)-haproxy/haproxy-runtime-cases" sh "$(FRAMEWORK_ROOT)/ci/runtime/run-haproxy-smoke.sh"

verified-full-matrix-resume: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	@run_id="$${VERIFIED_RUN_ID:-$$(cat "$(BUILD_ROOT)/verified-runs/current-run-id" 2>/dev/null || true)}"; \
	if [ -z "$$run_id" ]; then run_id="$(FRESH_VERIFIED_RUN_ID)"; fi; \
	VERIFIED_RUN_ID="$$run_id" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-verified-report-run.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --phase full-matrix-resume

smoke-common: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" CASE_SCOPE=common sh "$(FRAMEWORK_ROOT)/ci/runtime/run-connector-smokes.sh"

smoke-apache: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" RESULTS_DIR="$${RESULTS_DIR:-$(BUILD_ROOT)/results/$${MODSECURITY_TEST_VARIANT:-no-crs}/$${MODSECURITY_MRTS_VARIANT:-no-mrts}/apache}" CASE_SCOPE=all sh "$(FRAMEWORK_ROOT)/ci/runtime/run-apache-smoke.sh"

smoke-nginx: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" RESULTS_DIR="$${RESULTS_DIR:-$(BUILD_ROOT)/results/$${MODSECURITY_TEST_VARIANT:-no-crs}/$${MODSECURITY_MRTS_VARIANT:-no-mrts}/nginx}" CASE_SCOPE=all sh "$(FRAMEWORK_ROOT)/ci/runtime/run-nginx-smoke.sh"

# Opt-in bounded native lifecycle probe.  It deliberately remains outside the
# default smoke/test/CI targets and uses the existing Parent -> Framework
# runtime wrapper so build and path validation are unchanged.
soak-nginx: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" MSCONNECTOR_SMOKE_STAGE=bounded_soak MODSECURITY_TEST_VARIANT=no-crs NO_CRS_BASELINE=1 FORCE_ALL_CASES=1 MODSECURITY_RULE_PREAMBLE_FILE="$(NO_CRS_RULES_FILE)" RESULTS_DIR="$${RESULTS_DIR:-$(BUILD_ROOT)/results/no-crs/no-mrts/nginx-soak}" CASE_SCOPE=all sh "$(FRAMEWORK_ROOT)/ci/runtime/run-nginx-smoke.sh"

# Opt-in Valgrind Memcheck diagnostic.  It stays outside default smoke/test/CI
# targets, uses the existing wrapper, and deliberately defaults to one H1 case
# and one request worker beneath the external build/runtime root.
memcheck-nginx: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" MSCONNECTOR_SMOKE_STAGE=bounded_soak NGINX_MEMCHECK=1 VALGRIND_BIN="$${VALGRIND_BIN:-valgrind}" NGINX_PROTOCOL_PROFILE=h1 NGINX_DOWNSTREAM_PROTOCOL=http1 NGINX_UPSTREAM_PROTOCOL=http1 NGINX_SOAK_CASES="$${NGINX_MEMCHECK_CASES:-allow_without_marker}" NGINX_SOAK_DURATION_SECONDS="$${NGINX_MEMCHECK_DURATION_SECONDS:-30}" NGINX_SOAK_CONCURRENCY=1 MODSECURITY_TEST_VARIANT=no-crs NO_CRS_BASELINE=1 FORCE_ALL_CASES=1 MODSECURITY_RULE_PREAMBLE_FILE="$(NO_CRS_RULES_FILE)" NGINX_HARNESS_PARENT="$${NGINX_HARNESS_PARENT:-$(BUILD_ROOT)/nginx-memcheck-harness}" RESULTS_DIR="$${RESULTS_DIR:-$(BUILD_ROOT)/results/no-crs/no-mrts/nginx-memcheck}" CASE_SCOPE=all sh "$(FRAMEWORK_ROOT)/ci/runtime/run-nginx-smoke.sh"

smoke-envoy: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" CASE_SCOPE=all sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-legacy-open-connector-smoke.sh envoy

smoke-envoy-modsecurity:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	DECISION_BACKEND=libmodsecurity $(MAKE) smoke-envoy

smoke-envoy-request-body:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	DECISION_BACKEND=libmodsecurity MODSECURITY_SMOKE_CASE=request_body $(MAKE) smoke-envoy

smoke-envoy-crs:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	DECISION_BACKEND=libmodsecurity MODSECURITY_RULESET=crs $(MAKE) smoke-envoy

smoke-envoy-crs-secondary:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	DECISION_BACKEND=libmodsecurity MODSECURITY_RULESET=crs CRS_SMOKE_CASE=secondary $(MAKE) smoke-envoy

smoke-haproxy: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" RESULTS_DIR="$${RESULTS_DIR:-$(BUILD_ROOT)/results/$${MODSECURITY_TEST_VARIANT:-no-crs}/$${MODSECURITY_MRTS_VARIANT:-no-mrts}/haproxy}" CASE_SCOPE=all sh "$(FRAMEWORK_ROOT)/ci/runtime/run-haproxy-smoke.sh"

smoke-lighttpd: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" CASE_SCOPE=all sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-legacy-open-connector-smoke.sh lighttpd

smoke-lighttpd-modsecurity:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	DECISION_BACKEND=libmodsecurity $(MAKE) smoke-lighttpd

smoke-lighttpd-request-body:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	DECISION_BACKEND=libmodsecurity MODSECURITY_SMOKE_CASE=request_body $(MAKE) smoke-lighttpd

smoke-lighttpd-crs:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	DECISION_BACKEND=libmodsecurity MODSECURITY_RULESET=crs $(MAKE) smoke-lighttpd

smoke-lighttpd-crs-secondary:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	DECISION_BACKEND=libmodsecurity MODSECURITY_RULESET=crs CRS_SMOKE_CASE=secondary $(MAKE) smoke-lighttpd

smoke-traefik: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" CASE_SCOPE=all sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-legacy-open-connector-smoke.sh traefik

smoke-traefik-modsecurity:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	DECISION_BACKEND=libmodsecurity $(MAKE) smoke-traefik

smoke-traefik-request-body:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	DECISION_BACKEND=libmodsecurity MODSECURITY_SMOKE_CASE=request_body $(MAKE) smoke-traefik

smoke-traefik-crs:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	DECISION_BACKEND=libmodsecurity MODSECURITY_RULESET=crs $(MAKE) smoke-traefik

smoke-traefik-crs-secondary:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	DECISION_BACKEND=libmodsecurity MODSECURITY_RULESET=crs CRS_SMOKE_CASE=secondary $(MAKE) smoke-traefik

smoke-open-connectors-crs:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(MAKE) smoke-envoy-crs
	$(MAKE) smoke-traefik-crs
	$(MAKE) smoke-lighttpd-crs

smoke-open-connectors-request-body:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(MAKE) smoke-envoy-request-body
	$(MAKE) smoke-traefik-request-body
	$(MAKE) smoke-lighttpd-request-body

smoke-open-connectors-crs-secondary:
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(MAKE) smoke-envoy-crs-secondary
	$(MAKE) smoke-traefik-crs-secondary
	$(MAKE) smoke-lighttpd-crs-secondary

smoke-new-connectors: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	@$(WITH_RUNTIME_COMPONENTS) sh -eu -c 'set +e; \
	passed=0; blocked=0; failed=0; \
	for connector in envoy haproxy lighttpd traefik; do \
		echo "smoke-new-connectors: running $$connector"; \
		CASE_SCOPE=all sh "$(FRAMEWORK_ROOT)/ci/runtime/run-$$connector-smoke.sh"; \
		rc=$$?; \
		echo "smoke-new-connectors: $$connector rc=$$rc"; \
		if [ "$$rc" -eq 0 ]; then \
			passed=$$((passed + 1)); \
		elif [ "$$rc" -eq 77 ]; then \
			blocked=$$((blocked + 1)); \
		else \
			failed=$$((failed + 1)); \
		fi; \
	done; \
	echo "smoke-new-connectors: PASS=$$passed BLOCKED=$$blocked FAIL=$$failed"; \
	if [ "$$failed" -ne 0 ]; then \
		echo "smoke-new-connectors: FAIL"; \
		exit 1; \
	fi; \
	if [ "$$passed" -eq 0 ]; then \
		echo "smoke-new-connectors: BLOCKED - Runtime not verified"; \
		exit 77; \
	fi; \
	if [ "$$blocked" -ne 0 ]; then \
		echo "smoke-new-connectors: BLOCKED - some new connectors remain runtime not verified"; \
		exit 77; \
	fi; \
	echo "smoke-new-connectors: PASS - runtime smoke verified"; \
	exit 0'

smoke-all: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(call RUN_WITH_REFRESH_ALL,$(WITH_RUNTIME_COMPONENTS) env CASE_SCOPE=all sh "$(FRAMEWORK_ROOT)/ci/runtime/run-connector-smokes.sh")

test: test-active

test-no-crs: check-framework prepare-runtime-components
ifeq ($(ON_DEMAND_TESTS),1)
	$(call RUN_WITH_REFRESH_ALL,$(WITH_RUNTIME_COMPONENTS) env MODSECURITY_TEST_VARIANT=no-crs MODSECURITY_RULE_PREAMBLE_FILE= sh -eu -c '. "$(FRAMEWORK_ROOT)/ci/lib/common.sh"; RESULTS_DIR="$$BUILD_ROOT/results/no-crs"; export RESULTS_DIR; CASE_SCOPE=all sh "$(FRAMEWORK_ROOT)/ci/runtime/run-connector-smokes.sh"')
else
	$(ACTIVE_TEST_RUNNER) --group runtime-no-crs
endif

test-with-crs: check-framework prepare-runtime-components
ifeq ($(ON_DEMAND_TESTS),1)
	$(call RUN_WITH_REFRESH_ALL,$(WITH_RUNTIME_COMPONENTS) env MODSECURITY_TEST_VARIANT=with-crs sh -eu -c '. "$(FRAMEWORK_ROOT)/ci/lib/common.sh"; . "$(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/prepare-fresh-crs-source.sh"; sh "$(FRAMEWORK_ROOT)/ci/provisioning/fetch-crs.sh"; sh "$(FRAMEWORK_ROOT)/ci/provisioning/prepare-crs.sh"; MODSECURITY_RULE_PREAMBLE_FILE="$$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf"; RESULTS_DIR="$$BUILD_ROOT/results/with-crs"; export MODSECURITY_RULE_PREAMBLE_FILE RESULTS_DIR; CASE_SCOPE=all sh "$(FRAMEWORK_ROOT)/ci/runtime/run-connector-smokes.sh"')
else
	$(ACTIVE_TEST_RUNNER) --group runtime-crs
endif

# This bounded Apache/NGINX producer does not claim the full-matrix/MRTS
# inputs required by refresh-all-reports. Its own reports remain mandatory.
.PHONY: test-smoke-sequential-no-crs test-smoke-sequential-with-crs
ifeq ($(ON_DEMAND_TESTS),1)
test-smoke-sequential-no-crs test-smoke-sequential-with-crs: check-framework prepare-runtime-components
	@set -eu; \
	variant="$(patsubst test-smoke-sequential-%,%,$@)"; \
	smoke_root=$$(mktemp -d "$(BUILD_ROOT)/bounded-smoke-$$variant.XXXXXX"); \
	run_id=$$(basename "$$smoke_root"); \
	VERIFIED_RUN_ID="$$run_id" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/refresh-connector-reports.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$$smoke_root" --profile bounded-smoke --variant "$$variant" --begin-bounded-smoke; \
	runtime_rc=0; \
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" MODSECURITY_TEST_VARIANT="$$variant" MODSECURITY_RULE_PREAMBLE_FILE= RESULTS_DIR="$$smoke_root/results" CASE_SCOPE=all FORCE_ALL_CASES= TEST_CASE= SMOKE_CASES= NO_CRS_BASELINE= NO_CRS_SELECTED_CASE_IDS= RUN_ONE_CASE= sh -eu -c '. "$(FRAMEWORK_ROOT)/ci/lib/common.sh"; if [ "$$MODSECURITY_TEST_VARIANT" = with-crs ]; then . "$(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/prepare-fresh-crs-source.sh"; sh "$(FRAMEWORK_ROOT)/ci/provisioning/fetch-crs.sh"; sh "$(FRAMEWORK_ROOT)/ci/provisioning/prepare-crs.sh"; MODSECURITY_RULE_PREAMBLE_FILE="$$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf"; export MODSECURITY_RULE_PREAMBLE_FILE; fi; apache_rc=0; sh "$(FRAMEWORK_ROOT)/ci/runtime/run-apache-smoke.sh" || apache_rc=$$?; printf "%s\n" "$$apache_rc" > "$$RESULTS_DIR/apache.rc"; nginx_rc=0; "$(FRAMEWORK_PYTHON)" "$(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-bounded-nginx-cases.py" --variant "$$MODSECURITY_TEST_VARIANT" || nginx_rc=$$?; if [ "$$apache_rc" -ne 0 ]; then exit "$$apache_rc"; fi; exit "$$nginx_rc"' || runtime_rc=$$?; \
	refresh_rc=0; \
	VERIFIED_RUN_ID="$$run_id" MODSECURITY_TEST_VARIANT="$$variant" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/refresh-connector-reports.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$$smoke_root" --profile bounded-smoke --variant "$$variant" || refresh_rc=$$?; \
	if [ "$$runtime_rc" -ne 0 ]; then exit "$$runtime_rc"; fi; \
	exit "$$refresh_rc"

else
test-smoke-sequential-no-crs test-smoke-sequential-with-crs:
	$(error specialist smoke catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required)
endif

# The dedicated Parent runner owns fresh provisioning and evidence validation.
# Keep only the three newly promoted connectors in this narrow entrypoint.
with-crs-no-mrts-runtime: check-framework
	@test -n "$(CONNECTOR)" || { echo "CONNECTOR is required: envoy, traefik, or lighttpd" >&2; exit 2; }
	@case "$(CONNECTOR)" in envoy|traefik|lighttpd) ;; *) echo "CONNECTOR is not allowlisted: $(CONNECTOR)" >&2; exit 2 ;; esac
	@run_id="$${CRS_RUNTIME_RUN_ID:-$(FRESH_VERIFIED_RUN_ID)-$(CONNECTOR)}"; \
	case "$$run_id" in [A-Za-z0-9]*) ;; *) echo "CRS_RUNTIME_RUN_ID must start with an ASCII alphanumeric character" >&2; exit 2 ;; esac; \
	case "$$run_id" in *[!A-Za-z0-9._-]*) echo "CRS_RUNTIME_RUN_ID must be a bounded token" >&2; exit 2 ;; esac; \
	[ "$${#run_id}" -le 48 ] || { echo "CRS_RUNTIME_RUN_ID must be at most 48 characters" >&2; exit 2; }; \
	EVIDENCE_ROOT= CRS_RUNTIME_RUN_ID="$$run_id" CONNECTOR_ROOT="$(CURDIR)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" PYTHON="$(FRAMEWORK_PYTHON)" \
		sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-with-crs-no-mrts.sh "$(CONNECTOR)" "$$run_id"

mrts-generate: check-framework
	PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" $(MAKE) -C "$(FRAMEWORK_ROOT)" mrts-generate

mrts-load: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" $(MAKE) -C "$(FRAMEWORK_ROOT)" mrts-load

mrts-import: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" $(MAKE) -C "$(FRAMEWORK_ROOT)" mrts-import

test-no-mrts: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(call RUN_WITH_REFRESH_ALL,$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" $(MAKE) -C "$(FRAMEWORK_ROOT)" test-no-mrts)

test-with-mrts: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(call RUN_WITH_REFRESH_ALL,$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" $(MAKE) -C "$(FRAMEWORK_ROOT)" test-with-mrts)

test-with-mrts-feature-demo: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(call RUN_WITH_REFRESH_ALL,$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" $(MAKE) -C "$(FRAMEWORK_ROOT)" test-with-mrts-feature-demo)

test-mrts-matrix: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(call RUN_WITH_REFRESH_ALL,$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" $(MAKE) -C "$(FRAMEWORK_ROOT)" test-mrts-matrix)

mrts-ftw: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" $(MAKE) -C "$(FRAMEWORK_ROOT)" mrts-ftw

runtime-matrix: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" sh "$(FRAMEWORK_ROOT)/ci/runtime/run-runtime-matrix.sh"

runtime-matrix-all: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(call RUN_WITH_REFRESH_ALL,$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FORCE_ALL_CASES=1 sh "$(FRAMEWORK_ROOT)/ci/runtime/run-runtime-matrix.sh")

runtime-matrix-all-runtime: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FORCE_ALL_CASES=1 sh "$(FRAMEWORK_ROOT)/ci/runtime/run-runtime-matrix.sh"

runtime-matrix-haproxy: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" HAPROXY_MATRIX_VARIANT=all sh "$(FRAMEWORK_ROOT)/ci/runtime/run-haproxy-runtime-matrix.sh"

full-mrts-runtime-matrix: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(call RUN_WITH_REFRESH_ALL,$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-full-mrts-runtime-matrix.sh)

mrts-only-full-run: full-mrts-runtime-matrix

full-runtime-matrix: full-matrix-parallel

full-matrix-parallel: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(call RUN_WITH_REFRESH_ALL,$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-full-matrix-parallel.sh)

full-matrix-parallel-runtime: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-full-matrix-parallel.sh

full-matrix-single-job-runtime: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	@test -n "$(CONNECTOR)" || { echo "CONNECTOR is required, e.g. CONNECTOR=nginx"; exit 2; }
	@test -n "$(CRS)" || { echo "CRS is required, e.g. CRS=with-crs"; exit 2; }
	@test -n "$(MRTS)" || { echo "MRTS is required, e.g. MRTS=with-mrts"; exit 2; }
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-full-matrix-job.py --connector "$(CONNECTOR)" --crs "$(CRS)" --mrts "$(MRTS)" --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --timeout-seconds "$(VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS)"

full-matrix-resume-runtime: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" "$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-full-matrix-resume.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --job-timeout-seconds "$(VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS)" --total-timeout-seconds "$(VERIFIED_RUN_FULL_MATRIX_TOTAL_TIMEOUT_SECONDS)"

generate-full-runtime-matrix: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-full-runtime-matrix.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --log-root "$(LOG_ROOT)"

generate-full-matrix-job-completeness: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-full-matrix-job-completeness.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --output-dir "$(CURDIR)/reports/testing/generated/manifest" --rewrite-manifest

generate-nginx-mrts-http500-cluster-analysis: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-nginx-mrts-http500-cluster-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --build-root "$(BUILD_ROOT)" --output-dir "$(CURDIR)/reports/testing/generated/manifest"

generate-work-queue: check-framework
	"$(FRAMEWORK_PYTHON)" "$(FRAMEWORK_ROOT)/ci/reporting/generate-connector-work-queue.py" --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --output-root "$(CURDIR)" --full-runtime-matrix "$(CURDIR)/reports/testing/generated/canonical/full-runtime-matrix.generated.json"
	"$(FRAMEWORK_PYTHON)" "$(FRAMEWORK_ROOT)/ci/reporting/generate-phase-work-queue.py" --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --output-root "$(CURDIR)" --connector-work-queue "$(CURDIR)/reports/testing/generated/work-queues/connector-work-queue.generated.json" --phase-coverage "$(CURDIR)/reports/testing/generated/coverage/phase-coverage.generated.md" --full-runtime-matrix "$(CURDIR)/reports/testing/generated/canonical/full-runtime-matrix.generated.json"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-nolog-audit-evidence-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-response-header-hook-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-phase4-hard-abort-capability.py --connector-root "$(CURDIR)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-remaining-failure-analysis.py --connector-root "$(CURDIR)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-intervention-blocking-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-no-mrts-intervention-nomatch-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-body-processor-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-rule-chain-semantics-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-final-consistency-audit.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"

generate-phase-work-queue: check-framework
	"$(FRAMEWORK_PYTHON)" "$(FRAMEWORK_ROOT)/ci/reporting/generate-phase-work-queue.py" --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)" --output-root "$(CURDIR)" --connector-work-queue "$(CURDIR)/reports/testing/generated/work-queues/connector-work-queue.generated.json" --phase-coverage "$(CURDIR)/reports/testing/generated/coverage/phase-coverage.generated.md" --full-runtime-matrix "$(CURDIR)/reports/testing/generated/canonical/full-runtime-matrix.generated.json"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-nolog-audit-evidence-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-response-header-hook-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-phase4-hard-abort-capability.py --connector-root "$(CURDIR)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-remaining-failure-analysis.py --connector-root "$(CURDIR)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-intervention-blocking-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-no-mrts-intervention-nomatch-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-body-processor-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-rule-chain-semantics-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-final-consistency-audit.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"

generate-nolog-audit-evidence-analysis: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-nolog-audit-evidence-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"

generate-response-header-hook-analysis: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-response-header-hook-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"

generate-phase4-hard-abort-capability: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-phase4-hard-abort-capability.py --connector-root "$(CURDIR)"

generate-intervention-blocking-analysis: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-intervention-blocking-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"

generate-no-mrts-intervention-nomatch-analysis: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-no-mrts-intervention-nomatch-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"

generate-body-processor-analysis: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-body-processor-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"

generate-rule-chain-semantics-analysis: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-rule-chain-semantics-analysis.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"

generate-final-consistency-audit: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-final-consistency-audit.py --connector-root "$(CURDIR)" --framework-root "$(FRAMEWORK_ROOT)"

generate-remaining-failure-analysis: check-framework
	"$(FRAMEWORK_PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/reports/generate-remaining-failure-analysis.py --connector-root "$(CURDIR)"

mrts-native-full-run: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(call RUN_WITH_REFRESH_ALL,$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-mrts-native-full.sh)

mrts-native-full-run-runtime: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-mrts-native-full.sh

mrts-native-apache-full: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env MRTS_NATIVE_TARGETS=apache2_ubuntu PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-mrts-native-full.sh

mrts-native-nginx-pr24-full: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env MRTS_NATIVE_TARGETS=nginx-pr24 PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-mrts-native-full.sh

mrts-upstream-infra-check: check-framework
	@sh -eu -c ' \
		MRTS_ROOT="$${MRTS_ROOT:-$(FRAMEWORK_ROOT)/tools/MRTS}"; \
		test -d "$$MRTS_ROOT/config_infra/apache2_ubuntu" || { echo "BLOCKED: missing $$MRTS_ROOT/config_infra/apache2_ubuntu"; exit 77; }; \
		test -d "$(FRAMEWORK_ROOT)/tests/mrts/infra-overlays/nginx-pr24" || { echo "BLOCKED: missing Framework NGINX PR24 overlay"; exit 77; }; \
		test -f "$(FRAMEWORK_ROOT)/tests/mrts/infra-overlays/nginx-pr24/metadata.yaml" || { echo "BLOCKED: missing NGINX PR24 overlay metadata"; exit 77; }; \
		echo "MRTS upstream/native infrastructure inputs present"; \
	'

test-haproxy-no-crs: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" HAPROXY_MATRIX_VARIANT=no-crs sh "$(FRAMEWORK_ROOT)/ci/runtime/run-haproxy-runtime-matrix.sh"

test-haproxy-with-crs: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" HAPROXY_MATRIX_VARIANT=with-crs sh "$(FRAMEWORK_ROOT)/ci/runtime/run-haproxy-runtime-matrix.sh"

probe-response-body: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env PYTHON="$(FRAMEWORK_PYTHON)" sh "$(FRAMEWORK_ROOT)/ci/runtime/probe-response-body-blocking.sh"

connector-starter-checks: check-framework prepare-runtime-components
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	$(WITH_RUNTIME_COMPONENTS) env SOURCE_ROOT="$(SOURCE_ROOT)" BUILD_ROOT="$(BUILD_ROOT)" TMP_ROOT="$(TMP_ROOT)" LOG_ROOT="$(LOG_ROOT)" CONNECTOR_ROOT="$(CURDIR)" sh "$(FRAMEWORK_ROOT)/ci/runtime/run-connector-starter-checks.sh"

# Canonical connector stages. These targets deliberately keep build,
# retained Envoy/Traefik configuration checks and minimal runtime traffic.
# Separate configuration/start diagnostics remain available only on demand.
build-apache build-nginx build-haproxy build-envoy build-traefik build-lighttpd: build-%: check-framework
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-connector-stage.sh "$*" build

check-config-apache check-config-nginx check-config-haproxy check-config-lighttpd: check-config-%: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error standalone configuration diagnostics are archived; explicit ON_DEMAND_TESTS=1 is required))
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-connector-stage.sh "$*" config_load

check-config-envoy check-config-traefik: check-config-%: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-connector-stage.sh "$*" config_load
else
	$(ACTIVE_TEST_RUNNER) --group runtime-config-$*
endif

start-smoke-apache start-smoke-nginx start-smoke-haproxy: start-smoke-%: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-connector-stage.sh "$*" start_smoke
else
	$(error standalone request-free startup diagnostics are archived; explicit ON_DEMAND_TESTS=1 is required)
endif

runtime-smoke-apache runtime-smoke-nginx runtime-smoke-haproxy: runtime-smoke-%: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	EVIDENCE_ROOT="$(RUNTIME_EVIDENCE_ROOT)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh "$*" minimal_runtime_smoke
else
	$(ACTIVE_TEST_RUNNER) --group runtime-no-crs-$*
endif

capabilities-apache capabilities-nginx capabilities-haproxy capabilities-envoy capabilities-traefik capabilities-lighttpd: capabilities-%: check-framework
	@run_id="$${NO_CRS_RUN_ID:-$(DEFAULT_VERIFIED_RUN_ID)}"; \
	case "$$run_id" in [A-Za-z0-9]*) ;; *) echo "FAIL: unsafe capability-plan run id: $$run_id" >&2; exit 1 ;; esac; \
	case "$$run_id" in *[!A-Za-z0-9._-]*) echo "FAIL: unsafe capability-plan run id: $$run_id" >&2; exit 1 ;; esac; \
	[ "$${#run_id}" -le 128 ] || { echo "FAIL: capability-plan run id is too long" >&2; exit 1; }; \
	run_dir="$(CAPABILITY_PLAN_ROOT)/$*/$$run_id"; \
	mkdir -p "$$run_dir"; \
	"$(FRAMEWORK_PYTHON)" "$(FRAMEWORK_ROOT)/ci/checks/catalog/no_crs_baseline.py" select \
		--connector "$*" \
		--capabilities "connectors/$*/capabilities.json" \
		--output "$$run_dir/plan.json"

no-crs-baseline-apache no-crs-baseline-nginx no-crs-baseline-haproxy no-crs-baseline-envoy no-crs-baseline-traefik no-crs-baseline-lighttpd: no-crs-baseline-%: check-framework
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh "$*"

# The strict profile requires the complete canonical artifact set, including
# sanitized host logs.  Every target carries an explicit selected host profile
# and target identity into the run manifest.  In particular, the four legacy
# compatibility routes below can no longer be mislabeled as full-lifecycle
# evidence merely because they share a connector name.
full-lifecycle-apache: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	NO_CRS_ARTIFACT_PROFILE=full_lifecycle FULL_LIFECYCLE_HOST_PROFILE=native-httpd-module FULL_LIFECYCLE_EXECUTED_TARGET=full-lifecycle-apache sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh apache no_crs_baseline

full-lifecycle-nginx: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	NO_CRS_ARTIFACT_PROFILE=full_lifecycle FULL_LIFECYCLE_HOST_PROFILE=native-nginx-http-module FULL_LIFECYCLE_EXECUTED_TARGET=full-lifecycle-nginx sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh nginx no_crs_baseline

full-lifecycle-haproxy-htx: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	NO_CRS_ARTIFACT_PROFILE=full_lifecycle FULL_LIFECYCLE_HOST_PROFILE=native-htx-filter FULL_LIFECYCLE_EXECUTED_TARGET=full-lifecycle-haproxy-htx sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh haproxy no_crs_baseline

full-lifecycle-envoy-ext-proc: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	NO_CRS_ARTIFACT_PROFILE=full_lifecycle FULL_LIFECYCLE_HOST_PROFILE=ext_proc FULL_LIFECYCLE_EXECUTED_TARGET=full-lifecycle-envoy-ext-proc sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh envoy no_crs_baseline

full-lifecycle-traefik-native: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	NO_CRS_ARTIFACT_PROFILE=full_lifecycle FULL_LIFECYCLE_HOST_PROFILE=native-middleware FULL_LIFECYCLE_EXECUTED_TARGET=full-lifecycle-traefik-native sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh traefik no_crs_baseline

full-lifecycle-lighttpd-patched: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	NO_CRS_ARTIFACT_PROFILE=full_lifecycle FULL_LIFECYCLE_HOST_PROFILE=patched-native FULL_LIFECYCLE_EXECUTED_TARGET=full-lifecycle-lighttpd-patched sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh lighttpd no_crs_baseline

# Preserve the historical user-facing names, but route them only to their
# selected native profile.  Compatibility smoke remains under runtime-smoke-*
# and no-crs-baseline-* and is never full-lifecycle evidence.
full-lifecycle-haproxy: full-lifecycle-haproxy-htx
full-lifecycle-envoy: full-lifecycle-envoy-ext-proc
full-lifecycle-traefik: full-lifecycle-traefik-native
full-lifecycle-lighttpd: full-lifecycle-lighttpd-patched

full-lifecycle-all-connectors: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	NO_CRS_ARTIFACT_PROFILE=full_lifecycle sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-full-lifecycle-all-connectors.sh

evidence-check-apache evidence-check-nginx evidence-check-haproxy evidence-check-envoy evidence-check-traefik evidence-check-lighttpd: evidence-check-%: check-framework
	@run_id="$(NO_CRS_RUN_ID)"; \
	if [ -z "$$run_id" ]; then \
		latest="$(EVIDENCE_ROOT)/$*/latest-run-id"; \
		[ -f "$$latest" ] || { echo "FAIL: no latest canonical run for $*: $$latest" >&2; exit 1; }; \
		IFS= read -r run_id < "$$latest"; \
	fi; \
	[ -n "$$run_id" ] || { echo "FAIL: empty canonical run id for $*" >&2; exit 1; }; \
	case "$$run_id" in [A-Za-z0-9]*) ;; *) echo "FAIL: unsafe canonical run id for $*: $$run_id" >&2; exit 1 ;; esac; \
	case "$$run_id" in *[!A-Za-z0-9._-]*) echo "FAIL: unsafe canonical run id for $*: $$run_id" >&2; exit 1 ;; esac; \
	[ "$${#run_id}" -le 128 ] || { echo "FAIL: canonical run id is too long for $*" >&2; exit 1; }; \
	"$(FRAMEWORK_PYTHON)" "$(FRAMEWORK_ROOT)/ci/checks/catalog/no_crs_baseline.py" validate \
		--evidence-root "$(EVIDENCE_ROOT)/$*/$$run_id" \
		--connector "$*" \
		--check all

build-all-connectors: check-framework
	@status=0; blocked=0; \
	for connector in $(NO_CRS_CONNECTORS); do \
		sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-connector-stage.sh "$$connector" build || { rc=$$?; if [ "$$rc" -eq 77 ]; then blocked=1; else status=1; fi; }; \
	done; \
	[ "$$status" -eq 0 ] || exit 1; \
	[ "$$blocked" -eq 0 ] || exit 77

check-config-all-connectors: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	@status=0; blocked=0; \
	for connector in $(NO_CRS_CONNECTORS); do \
		sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-connector-stage.sh "$$connector" config_load || { rc=$$?; if [ "$$rc" -eq 77 ]; then blocked=1; else status=1; fi; }; \
	done; \
	[ "$$status" -eq 0 ] || exit 1; \
	[ "$$blocked" -eq 0 ] || exit 77
else
	$(error all-connector standalone configuration diagnostics are archived; explicit ON_DEMAND_TESTS=1 is required)
endif

start-smoke-all-connectors: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	@status=0; blocked=0; \
	for connector in $(NO_CRS_CONNECTORS); do \
		sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-connector-stage.sh "$$connector" start_smoke || { rc=$$?; if [ "$$rc" -eq 77 ]; then blocked=1; else status=1; fi; }; \
	done; \
	[ "$$status" -eq 0 ] || exit 1; \
	[ "$$blocked" -eq 0 ] || exit 77
else
	$(error standalone request-free startup diagnostics are archived; explicit ON_DEMAND_TESTS=1 is required)
endif

runtime-smoke-all-connectors: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	@status=0; blocked=0; run_id="$(NO_CRS_RUN_ID)"; \
	if [ -z "$$run_id" ]; then run_id="$$(date -u +%Y-%m-%dT%H-%M-%SZ)-$$(git rev-parse --short=8 HEAD 2>/dev/null || printf unknown)"; fi; \
	for connector in $(NO_CRS_CONNECTORS); do \
		NO_CRS_RUN_ID="$$run_id" EVIDENCE_ROOT="$(RUNTIME_EVIDENCE_ROOT)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh "$$connector" minimal_runtime_smoke || { rc=$$?; if [ "$$rc" -eq 77 ]; then blocked=1; else status=1; fi; }; \
	done; \
	[ "$$status" -eq 0 ] || exit 1; \
	[ "$$blocked" -eq 0 ] || exit 77
else
	$(ACTIVE_TEST_RUNNER) --group runtime-no-crs
endif

no-crs-baseline-all-connectors: check-framework
	@status=0; blocked=0; run_id="$(NO_CRS_RUN_ID)"; \
	if [ -z "$$run_id" ]; then run_id="$$(date -u +%Y-%m-%dT%H-%M-%SZ)-$$(git rev-parse --short=8 HEAD 2>/dev/null || printf unknown)"; fi; \
	for connector in $(NO_CRS_CONNECTORS); do \
		NO_CRS_RUN_ID="$$run_id" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh "$$connector" || { rc=$$?; if [ "$$rc" -eq 77 ]; then blocked=1; else status=1; fi; }; \
	done; \
	[ "$$status" -eq 0 ] || exit 1; \
	[ "$$blocked" -eq 0 ] || exit 77

capabilities-all-connectors: capabilities-apache capabilities-nginx capabilities-haproxy capabilities-envoy capabilities-traefik capabilities-lighttpd
	"$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/collectors/connector_capabilities.py check
	"$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/collectors/connector_capabilities.py generate \
		--output-dir "$(CURDIR)/reports/testing/generated/canonical"

# Keep the checked-in catalog source-contract-only.  This separate target
# renders a disposable report view from one explicit, fully validated current
# canonical No-CRS run, so local/stale latest-run-id files are never selected.
capabilities-all-connectors-evidence: check-framework
	@run_id="$(CAPABILITY_REPORT_RUN_ID)"; \
	[ -n "$$run_id" ] || { echo "FAIL: CAPABILITY_REPORT_RUN_ID (or NO_CRS_RUN_ID) is required" >&2; exit 1; }; \
	"$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/collectors/connector_capabilities.py check; \
	"$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/collectors/connector_capabilities.py generate \
		--evidence-root "$(CAPABILITY_REPORT_EVIDENCE_ROOT)" \
		--run-id "$$run_id" \
		--output-dir "$(CAPABILITY_REPORT_OUTPUT_DIR)"

evidence-check-all-connectors: evidence-check-apache evidence-check-nginx evidence-check-haproxy evidence-check-envoy evidence-check-traefik evidence-check-lighttpd

define RUN_NO_CRS_EVIDENCE_CHECK
	@set -eu; \
	for connector in $(NO_CRS_CONNECTORS); do \
		run_id="$(NO_CRS_RUN_ID)"; \
		if [ -z "$$run_id" ]; then \
			latest="$(EVIDENCE_ROOT)/$$connector/latest-run-id"; \
			[ -f "$$latest" ] || { echo "FAIL: no latest canonical run for $$connector: $$latest" >&2; exit 1; }; \
			IFS= read -r run_id < "$$latest"; \
		fi; \
		[ -n "$$run_id" ] || { echo "FAIL: empty canonical run id for $$connector" >&2; exit 1; }; \
		case "$$run_id" in [A-Za-z0-9]*) ;; *) echo "FAIL: unsafe canonical run id for $$connector: $$run_id" >&2; exit 1 ;; esac; \
		case "$$run_id" in *[!A-Za-z0-9._-]*) echo "FAIL: unsafe canonical run id for $$connector: $$run_id" >&2; exit 1 ;; esac; \
		[ "$${#run_id}" -le 128 ] || { echo "FAIL: canonical run id is too long for $$connector" >&2; exit 1; }; \
		"$(FRAMEWORK_PYTHON)" "$(FRAMEWORK_ROOT)/ci/checks/catalog/no_crs_baseline.py" validate \
			--evidence-root "$(EVIDENCE_ROOT)/$$connector/$$run_id" \
			--connector "$$connector" --check $(1); \
	done
endef

check-no-crs-result-schema: check-framework
	$(call RUN_NO_CRS_EVIDENCE_CHECK,schema)

check-no-crs-evidence-completeness: check-framework
	$(call RUN_NO_CRS_EVIDENCE_CHECK,completeness)

check-no-crs-capability-consistency: check-framework
	$(call RUN_NO_CRS_EVIDENCE_CHECK,capability)

check-no-crs-claim-policy: check-framework
	$(call RUN_NO_CRS_EVIDENCE_CHECK,claim-policy)

check-no-crs-artifact-layout: check-framework
	$(call RUN_NO_CRS_EVIDENCE_CHECK,layout)

check-no-crs-body-payload-absence: check-framework
	$(call RUN_NO_CRS_EVIDENCE_CHECK,body-payload)

check-no-crs-protocol-client: check-framework
	$(call RUN_NO_CRS_EVIDENCE_CHECK,protocol-client)

check-no-crs-status-consistency: check-framework
	$(call RUN_NO_CRS_EVIDENCE_CHECK,status)

define RUN_PARENT_FULL_LIFECYCLE_EVIDENCE_CHECK
	"$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/evidence/check-full-lifecycle-evidence.py \
		--connector-root "$(CURDIR)" --evidence-root "$(EVIDENCE_ROOT)" \
		--run-id "$(NO_CRS_RUN_ID)" --check $(1) --connectors $(NO_CRS_CONNECTORS)
endef

define RUN_STRICT_FULL_LIFECYCLE_EVIDENCE_CHECK
	@set -eu; \
	for connector in $(NO_CRS_CONNECTORS); do \
		"$(FRAMEWORK_PYTHON)" "$(FRAMEWORK_ROOT)/ci/checks/evidence/check_full_lifecycle_evidence.py" \
			--run-dir "$(EVIDENCE_ROOT)/$$connector/$(NO_CRS_RUN_ID)" --check $(1); \
	done; \
	$(call RUN_PARENT_FULL_LIFECYCLE_EVIDENCE_CHECK,profile)
endef

# Transport sidecars are inventory only until a case is promoted.  The
# Framework's dedicated checker is nevertheless always part of the selected
# full-lifecycle promotion gate, so a future PASS cannot bypass its causal
# event/observation/lifecycle correlation requirements.
define RUN_TRANSPORT_HARDENING_EVIDENCE_CHECK
	@set -eu; \
	for connector in $(NO_CRS_CONNECTORS); do \
		$(MAKE) -C "$(FRAMEWORK_ROOT)" check-transport-hardening-evidence \
			PYTHON="$(FRAMEWORK_PYTHON)" \
			CONNECTOR="$$connector" \
			NO_CRS_RUN_DIR="$(EVIDENCE_ROOT)/$$connector/$(NO_CRS_RUN_ID)"; \
	done
endef

check-first-byte-before-response-end: check-framework
	@test -n "$(NO_CRS_RUN_ID)" || { echo "NO_CRS_RUN_ID is required" >&2; exit 2; }
	$(call RUN_STRICT_FULL_LIFECYCLE_EVIDENCE_CHECK,first-byte)
	$(call RUN_PARENT_FULL_LIFECYCLE_EVIDENCE_CHECK,first-byte)

check-no-full-response-buffering: check-framework
	@test -n "$(NO_CRS_RUN_ID)" || { echo "NO_CRS_RUN_ID is required" >&2; exit 2; }
	$(call RUN_STRICT_FULL_LIFECYCLE_EVIDENCE_CHECK,no-full-response-buffering)
	$(call RUN_PARENT_FULL_LIFECYCLE_EVIDENCE_CHECK,no-full-buffer)

check-full-lifecycle-event-privacy: check-framework
	@test -n "$(NO_CRS_RUN_ID)" || { echo "NO_CRS_RUN_ID is required" >&2; exit 2; }
	$(call RUN_STRICT_FULL_LIFECYCLE_EVIDENCE_CHECK,event-privacy)

check-full-lifecycle-transport: check-framework
	@test -n "$(NO_CRS_RUN_ID)" || { echo "NO_CRS_RUN_ID is required" >&2; exit 2; }
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/evidence/check-full-lifecycle-evidence.py \
		--connector-root "$(CURDIR)" --evidence-root "$(EVIDENCE_ROOT)" \
		--run-id "$(NO_CRS_RUN_ID)" --check transport --connectors $(NO_CRS_CONNECTORS)
	$(call RUN_TRANSPORT_HARDENING_EVIDENCE_CHECK)

check-full-lifecycle-lifecycle: check-framework
	@test -n "$(NO_CRS_RUN_ID)" || { echo "NO_CRS_RUN_ID is required" >&2; exit 2; }
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/evidence/check-full-lifecycle-evidence.py \
		--connector-root "$(CURDIR)" --evidence-root "$(EVIDENCE_ROOT)" \
		--run-id "$(NO_CRS_RUN_ID)" --check lifecycle --connectors $(NO_CRS_CONNECTORS)

check-full-lifecycle-transport-hardening: check-framework
	@test -n "$(NO_CRS_RUN_ID)" || { echo "NO_CRS_RUN_ID is required" >&2; exit 2; }
	$(call RUN_TRANSPORT_HARDENING_EVIDENCE_CHECK)

check-full-lifecycle-promotion: check-framework
	@test -n "$(NO_CRS_RUN_ID)" || { echo "NO_CRS_RUN_ID is required" >&2; exit 2; }
	$(call RUN_STRICT_FULL_LIFECYCLE_EVIDENCE_CHECK,promotion)
	$(call RUN_PARENT_FULL_LIFECYCLE_EVIDENCE_CHECK,promotion)
	$(call RUN_TRANSPORT_HARDENING_EVIDENCE_CHECK)

# Read-only compact acceptance gate.  It consumes one already finalized
# canonical run and cannot change capability manifests or case outcomes.
check-six-connector-core-completion:
	@test -n "$(NO_CRS_RUN_ID)" || { echo "NO_CRS_RUN_ID is required" >&2; exit 2; }
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/evidence/check-six-connector-core-completion.py \
		--connector-root "$(CURDIR)" --evidence-root "$(EVIDENCE_ROOT)" \
		--run-id "$(NO_CRS_RUN_ID)"

check-no-crs-doc-consistency:
	"$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/documentation/check-no-crs-doc-consistency.py

check-no-crs-source-normalization:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v \
		modsecurity_connector_tests.test_collect_no_crs_source \
		modsecurity_connector_tests.test_full_lifecycle_evidence \
		modsecurity_connector_tests.test_prepare_runtime_components \
		modsecurity_connector_tests.test_runtime_component_cache_identity
else
	$(ACTIVE_TEST_RUNNER) --group common
endif

.PHONY: check-apache-common-adoption check-apache-c-standard-wiring check-apache-c-standards check-apache-c17 check-apache-c17-lint check-apache-c23 check-apache-future-c check-apache-c20 check-apache-c26 check-apache-request-transaction-cleanup check-apache-request-transaction-cleanup-lint check-optional-prerequisite-status check-nginx-common-adoption check-nginx-c-standard-wiring check-nginx-c-standards check-nginx-c17 check-nginx-c17-lint check-nginx-c23 check-nginx-future-c check-nginx-c20 check-nginx-c26 check-haproxy-common-adoption check-haproxy-c-standard-wiring check-haproxy-c-standards check-haproxy-c17 check-haproxy-c17-lint check-haproxy-c23 check-haproxy-future-c check-haproxy-c20 check-haproxy-c26 check-haproxy-htx-overlay check-common-helpers check-common-helpers-c17 check-common-helpers-c23 check-common-helpers-future-c check-common-helpers-c20 check-common-helpers-c26 check-common-http-header-fuzz check-common-sdk-contract check-common-security-contract check-common-memory-safety check-common-flow-integrity check-adapter-contracts check-directive-parity check-python-version-contract check-remaining-connectors-common-adoption check-envoy-common-adoption check-traefik-common-adoption check-lighttpd-common-adoption check-remaining-connectors-host-integration check-remaining-connectors-build-wiring check-remaining-connectors-start-wiring check-remaining-connectors-claim-policy check-remaining-connectors-c-standard-wiring check-remaining-connectors-c-standards check-remaining-connectors-c17 check-remaining-connectors-c17-lint check-remaining-connectors-c23 check-remaining-connectors-future-c check-block-status-generator build-envoy-connector check-envoy-config start-smoke-envoy runtime-smoke-envoy build-traefik-connector check-traefik-config start-smoke-traefik runtime-smoke-traefik build-lighttpd-connector build-lighttpd-bridge self-test-lighttpd-bridge check-lighttpd-config start-smoke-lighttpd runtime-smoke-lighttpd build-remaining-connectors start-smoke-remaining-connectors runtime-smoke-remaining-connectors readiness-remaining-connectors

.PHONY: check-http-authorization-service-timeout

build-envoy-connector:
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-remaining-connector-target.sh envoy build-envoy-connector

check-envoy-config: build-envoy-connector
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-remaining-connector-target.sh envoy check-envoy-config
else
	$(ACTIVE_TEST_RUNNER) --group runtime-config-envoy
endif

start-smoke-envoy: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-connector-stage.sh envoy start_smoke
else
	$(error standalone request-free startup diagnostics are archived; explicit ON_DEMAND_TESTS=1 is required)
endif

runtime-smoke-envoy: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	EVIDENCE_ROOT="$(RUNTIME_EVIDENCE_ROOT)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh envoy minimal_runtime_smoke
else
	$(ACTIVE_TEST_RUNNER) --group runtime-no-crs-envoy
endif

build-traefik-connector:
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-remaining-connector-target.sh traefik build-traefik-connector

check-traefik-config: build-traefik-connector
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-remaining-connector-target.sh traefik check-traefik-config
else
	$(ACTIVE_TEST_RUNNER) --group runtime-config-traefik
endif

start-smoke-traefik: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-connector-stage.sh traefik start_smoke
else
	$(error standalone request-free startup diagnostics are archived; explicit ON_DEMAND_TESTS=1 is required)
endif

runtime-smoke-traefik: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	EVIDENCE_ROOT="$(RUNTIME_EVIDENCE_ROOT)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh traefik minimal_runtime_smoke
else
	$(ACTIVE_TEST_RUNNER) --group runtime-no-crs-traefik
endif

build-lighttpd-connector:
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-remaining-connector-target.sh lighttpd build-lighttpd-connector

build-lighttpd-bridge:
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-remaining-connector-target.sh lighttpd build-lighttpd-bridge

self-test-lighttpd-bridge: build-lighttpd-bridge
	@test "$(ON_DEMAND_TESTS)" = 1 || { echo "FAIL: specialist self-test is archived; explicit ON_DEMAND_TESTS=1 is required" >&2; exit 2; }
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-remaining-connector-target.sh lighttpd self-test-lighttpd-bridge

check-lighttpd-config: build-lighttpd-connector
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-remaining-connector-target.sh lighttpd check-lighttpd-config
else
	$(error standalone configuration diagnostics are archived; explicit ON_DEMAND_TESTS=1 is required)
endif

start-smoke-lighttpd: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-connector-stage.sh lighttpd start_smoke
else
	$(error standalone request-free startup diagnostics are archived; explicit ON_DEMAND_TESTS=1 is required)
endif

runtime-smoke-lighttpd: check-framework
ifeq ($(ON_DEMAND_TESTS),1)
	EVIDENCE_ROOT="$(RUNTIME_EVIDENCE_ROOT)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh lighttpd minimal_runtime_smoke
else
	$(ACTIVE_TEST_RUNNER) --group runtime-no-crs-lighttpd
endif

build-remaining-connectors: build-envoy-connector build-traefik-connector build-lighttpd-connector

start-smoke-remaining-connectors: start-smoke-envoy start-smoke-traefik start-smoke-lighttpd

runtime-smoke-remaining-connectors: runtime-smoke-envoy runtime-smoke-traefik runtime-smoke-lighttpd

readiness-remaining-connectors: check-envoy-common-adoption check-traefik-common-adoption check-lighttpd-common-adoption check-remaining-connectors-host-integration check-remaining-connectors-build-wiring check-remaining-connectors-start-wiring check-remaining-connectors-claim-policy
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/documentation/check-bilingual-docs.py

check-remaining-connectors-common-adoption:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-common-adoption.py

check-envoy-common-adoption:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-common-adoption.py --connector envoy

check-traefik-common-adoption:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-common-adoption.py --connector traefik

check-lighttpd-common-adoption:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-common-adoption.py --connector lighttpd

check-remaining-connectors-host-integration:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-host-integration.py

check-remaining-connectors-build-wiring:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-build-wiring.py

check-remaining-connectors-start-wiring:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-start-wiring.py
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest -v modsecurity_connector_tests.test_legacy_open_connector_smoke modsecurity_connector_tests.test_envoy_legacy_smoke_evidence
else
	$(ACTIVE_TEST_RUNNER) --group common
endif

check-remaining-connectors-claim-policy:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-claim-policy.py

check-remaining-connectors-c-standard-wiring:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-c-standard-wiring.py

check-remaining-connectors-c-standards:
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-c-standards.sh

check-remaining-connectors-c17:
	CONNECTOR_C_STD_PROFILE=c17 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-c-standards.sh

check-remaining-connectors-c17-lint:
	@CONNECTOR_C_STD_PROFILE=c17 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-c-standards.sh || { rc="$$?"; if [ "$$rc" = "77" ]; then echo "SKIPPED: remaining connector C17 check blocked in lint environment"; exit 0; fi; exit "$$rc"; }

check-remaining-connectors-c23:
	CONNECTOR_C_STD_PROFILE=c23 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-c-standards.sh

check-remaining-connectors-future-c:
	CONNECTOR_C_STD_PROFILE=c2y sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/all/check-remaining-connectors-c-standards.sh

check-block-status-generator:
ifeq ($(ON_DEMAND_TESTS),1)
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-block-status-generator.py
else
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-common-sdk-contract.py
endif

.PHONY: check-apache-autotools-bootstrap
check-apache-autotools-bootstrap:
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/apache/check-apache-autotools-bootstrap.sh
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif

check-apache-common-adoption:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/apache/check-apache-common-adoption.py
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest -v modsecurity_connector_tests.test_apache_common_adoption
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif

check-apache-c-standard-wiring:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/apache/check-apache-c-standard-wiring.py

check-apache-c-standards:
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/apache/check-apache-c-standards.sh

check-apache-c17:
	APACHE_C_STD_PROFILE=c17 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/apache/check-apache-c-standards.sh

.PHONY: check-apache-intervention-cleanup
check-apache-intervention-cleanup:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_apache_intervention_cleanup
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif

.PHONY: check-apache-native-response-limit
check-apache-native-response-limit:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_apache_native_response_limit
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif

.PHONY: check-apache-event-sink check-haproxy-spop-event-sink
check-apache-event-sink:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_apache_event_sink_failures
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif

check-haproxy-spop-event-sink:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_haproxy_spop_event_sink_failures
else
	$(ACTIVE_TEST_RUNNER) --group haproxy
endif

check-apache-c17-lint:
	@APACHE_C_STD_PROFILE=c17 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/apache/check-apache-c-standards.sh || { rc="$$?"; if [ "$$rc" = "77" ]; then echo "SKIPPED: apache C17 compile check blocked in lint environment"; exit 0; fi; exit "$$rc"; }

check-apache-request-transaction-cleanup:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_apache_request_transaction_cleanup
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/apache/check-apache-request-transaction-cleanup.sh
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif

check-apache-request-transaction-cleanup-lint:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_apache_request_transaction_cleanup
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif
ifeq ($(ON_DEMAND_TESTS),1)
	"$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/tools/run-check-status.py --check apache_request_transaction_cleanup --allow-blocked-reason apache_development_prerequisite --blocked-if-missing-apache-development -- sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/apache/check-apache-request-transaction-cleanup.sh
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif

.PHONY: check-apache-ruleset-cleanup check-apache-ruleset-cleanup-lint
check-apache-ruleset-cleanup:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_apache_rules_set_cleanup
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/apache/check-apache-rules-set-cleanup.sh
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif

check-apache-ruleset-cleanup-lint:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_apache_rules_set_cleanup
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif
ifeq ($(ON_DEMAND_TESTS),1)
	"$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/tools/run-check-status.py --check apache_rules_set_cleanup --allow-blocked-reason apache_development_prerequisite --blocked-if-missing-apache-development -- sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/apache/check-apache-rules-set-cleanup.sh
else
	$(ACTIVE_TEST_RUNNER) --group apache
endif

check-optional-prerequisite-status:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_optional_prerequisite_status
else
	$(ACTIVE_TEST_RUNNER) --group supply-chain
endif

check-apache-c23:
	APACHE_C_STD_PROFILE=c23 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/apache/check-apache-c-standards.sh

check-apache-future-c:
	APACHE_C_STD_PROFILE=c2y sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/apache/check-apache-c-standards.sh

check-apache-c20:
	@echo "SKIPPED: c20 is not a C standard mode; use c23/c2x for C or c++20 for C++."

check-apache-c26:
	@echo "SKIPPED: c26 is not a C standard mode; use c2y/gnu2y for future C or c++26 for C++."

check-nginx-common-adoption:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/nginx/check-nginx-common-adoption.py

check-nginx-c-standard-wiring:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/nginx/check-nginx-c-standard-wiring.py

check-nginx-c-standards:
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/nginx/check-nginx-c-standards.sh

check-nginx-c17:
	NGINX_C_STD_PROFILE=c17 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/nginx/check-nginx-c-standards.sh

check-nginx-c17-lint:
	@NGINX_C_STD_PROFILE=c17 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/nginx/check-nginx-c-standards.sh || { rc="$$?"; if [ "$$rc" = "77" ]; then echo "SKIPPED: nginx C17 compile check blocked in lint environment"; exit 0; fi; exit "$$rc"; }

check-nginx-c23:
	NGINX_C_STD_PROFILE=c23 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/nginx/check-nginx-c-standards.sh

check-nginx-future-c:
	NGINX_C_STD_PROFILE=c2y sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/nginx/check-nginx-c-standards.sh

check-nginx-c20:
	@echo "SKIPPED: c20 is not a C standard mode; use c23/c2x for C or c++20 for C++."

check-nginx-c26:
	@echo "SKIPPED: c26 is not a C standard mode; use c2y/gnu2y for future C or c++26 for C++."

check-haproxy-common-adoption:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/haproxy/check-haproxy-common-adoption.py

check-haproxy-c-standard-wiring:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/haproxy/check-haproxy-c-standard-wiring.py

check-haproxy-c-standards:
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/haproxy/check-haproxy-c-standards.sh

check-haproxy-htx-overlay:
	$(MAKE) -C connectors/haproxy check-htx-overlay

check-haproxy-c17:
	HAPROXY_C_STD_PROFILE=c17 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/haproxy/check-haproxy-c-standards.sh

check-haproxy-c17-lint:
	@HAPROXY_C_STD_PROFILE=c17 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/haproxy/check-haproxy-c-standards.sh || { rc="$$?"; if [ "$$rc" = "77" ]; then echo "SKIPPED: haproxy C17 compile check blocked in lint environment"; exit 0; fi; exit "$$rc"; }

check-haproxy-c23:
	HAPROXY_C_STD_PROFILE=c23 sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/haproxy/check-haproxy-c-standards.sh

check-haproxy-future-c:
	HAPROXY_C_STD_PROFILE=c2y sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/connectors/haproxy/check-haproxy-c-standards.sh

check-haproxy-c20:
	@echo "SKIPPED: c20 is not a C standard mode; use c23/c2x for C or c++20 for C++."

check-haproxy-c26:
	@echo "SKIPPED: c26 is not a C standard mode; use c2y/gnu2y for future C or c++26 for C++."

.PHONY: check-i10-adapter-errors check-i10-common-callers check-i10-haproxy-callers check-i10-envoy-callers check-i10-traefik-callers check-i10-lighttpd-callers

check-i10-adapter-errors: check-i10-common-callers check-i10-haproxy-callers check-i10-envoy-callers check-i10-traefik-callers check-i10-lighttpd-callers

check-i10-common-callers:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_i10_service_callers modsecurity_connector_tests.test_runtime_rule_delivery_failure
else
	$(ACTIVE_TEST_RUNNER) --group common
endif

check-i10-haproxy-callers:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_haproxy_i10_host_callers modsecurity_connector_tests.test_haproxy_i10_binding_callers
else
	$(ACTIVE_TEST_RUNNER) --group haproxy
endif

check-i10-envoy-callers:
ifeq ($(ON_DEMAND_TESTS),1)
	cd connectors/envoy/ext_proc && GOTOOLCHAIN=local go test -mod=readonly -count=1 -race ./...
else
	$(ACTIVE_TEST_RUNNER) --group envoy
endif
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_i10_envoy_mutations modsecurity_connector_tests.test_i10_envoy_finish
else
	$(ACTIVE_TEST_RUNNER) --group envoy
endif

check-i10-traefik-callers:
ifeq ($(ON_DEMAND_TESTS),1)
	cd connectors/traefik/native_middleware && GOTOOLCHAIN=local go test -mod=readonly -count=1 -race ./... && GOTOOLCHAIN=local go vet -mod=readonly ./...
else
	$(ACTIVE_TEST_RUNNER) --group traefik
endif
	cd connectors/traefik/native_middleware && GOTOOLCHAIN=local go vet -mod=readonly ./...
ifeq ($(ON_DEMAND_TESTS),1)
	cd connectors/traefik/response_observer && GOTOOLCHAIN=local go test -mod=readonly -count=1 -race ./... && GOTOOLCHAIN=local go vet -mod=readonly ./...
else
	$(ACTIVE_TEST_RUNNER) --group traefik
endif
	cd connectors/traefik/response_observer && GOTOOLCHAIN=local go vet -mod=readonly ./...
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_traefik_i10_dispatcher modsecurity_connector_tests.test_traefik_i10_mutations
else
	$(ACTIVE_TEST_RUNNER) --group traefik
endif

check-i10-lighttpd-callers:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_lighttpd_i10_adapter_errors
else
	$(ACTIVE_TEST_RUNNER) --group lighttpd
endif

check-common-helpers:
ifeq ($(ON_DEMAND_TESTS),1)
	MSCONNECTOR_C_STD="$(MSCONNECTOR_C_STD)" MSCONNECTOR_CFLAGS="$(MSCONNECTOR_CFLAGS)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-common-helpers.sh
else
	$(ACTIVE_TEST_RUNNER) --group common
endif

check-common-helpers-c17:
	$(MAKE) check-common-helpers MSCONNECTOR_C_STD=c17

.PHONY: check-native-engine-body-inspection
check-native-engine-body-inspection:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_engine_response_limits
else
	$(ACTIVE_TEST_RUNNER) --group common
endif

.PHONY: check-native-lifecycle-observer
check-native-lifecycle-observer:
	@test -n "$$NATIVE_OBSERVER_TEST_OUT" && test -n "$$MODSECURITY_INCLUDE_DIR" && test -n "$$MODSECURITY_LIB_DIR" || { echo "BLOCKED: native lifecycle observer requires an explicit output root and SDK include/library directories"; exit 77; }
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_native_lifecycle_observer
else
	$(ACTIVE_TEST_RUNNER) --group common
endif

.PHONY: check-i09-native-routes
check-i09-native-routes:
ifeq ($(ON_DEMAND_TESTS),1)
	PYTHONDONTWRITEBYTECODE=1 "$(PYTHON)" -m unittest -v modsecurity_connector_tests.test_i09_common_routes modsecurity_connector_tests.test_i09_native_decision modsecurity_connector_tests.test_i09_body_phase modsecurity_connector_tests.test_apache_i09_filter_events modsecurity_connector_tests.test_haproxy_native_results modsecurity_connector_tests.test_haproxy_host_native_results connectors.traefik.modsecurity_connector_tests.test_i09_api_returns connectors.lighttpd.modsecurity_connector_tests.test_i09_api_returns
else
	$(ACTIVE_TEST_RUNNER) --group common
endif

check-common-http-header-fuzz:
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-common-http-header-fuzz.sh
else
	@echo "FAIL: randomized fuzzing is on-demand; use ON_DEMAND_TESTS=1 for an explicitly authorized campaign" >&2
	@exit 2
endif

.PHONY: build-codeql-common-scope check-active-inventory test-active
build-codeql-common-scope:
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/analysis/build-codeql-common-scope.sh

check-active-inventory:
	$(ACTIVE_TEST_RUNNER) --check
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/tools/update-test-archive.py --check

test-active:
	$(ACTIVE_TEST_RUNNER)

# The clean-combination verifier reaches this through the Parent thin dispatcher.
.PHONY: test-framework-integration-probe
test-framework-integration-probe:
	$(ACTIVE_TEST_RUNNER) --check
	$(ACTIVE_TEST_RUNNER) --execution common.header-valid-length --strict-skips

check-common-helpers-c23:
	@flag="$$(python3 ci/provisioning/toolchains/detect-c-standard.py --profile c23 --compiler "$(MSCONNECTOR_COMPILER_ID)")" || { rc="$$?"; if [ "$$rc" = "77" ]; then echo "SKIPPED: optional C23 check — compiler does not support c23 or c2x"; exit 0; fi; exit "$$rc"; }; \
	$(MAKE) check-common-helpers CC="$(MSCONNECTOR_COMPILER_ID)" MSCONNECTOR_C_STD=c23 MSCONNECTOR_CFLAGS="$$flag -Wall -Wextra -Werror"

check-common-helpers-future-c:
	@flag="$$(python3 ci/provisioning/toolchains/detect-c-standard.py --profile c2y --compiler "$(MSCONNECTOR_COMPILER_ID)")" || { rc="$$?"; if [ "$$rc" = "77" ]; then echo "SKIPPED: optional future C check — compiler does not support c2y or gnu2y"; exit 0; fi; exit "$$rc"; }; \
	$(MAKE) check-common-helpers CC="$(MSCONNECTOR_COMPILER_ID)" MSCONNECTOR_C_STD=c2y MSCONNECTOR_CFLAGS="$$flag -Wall -Wextra -Werror"

check-common-helpers-c20:
	@echo "SKIPPED: c20 is not a C standard mode; use c23/c2x for C or c++20 for C++."

check-common-helpers-c26:
	@echo "SKIPPED: c26 is not a C standard mode; use c2y/gnu2y for future C or c++26 for C++."

check-http-authorization-service-timeout:
ifeq ($(ON_DEMAND_TESTS),1)
	MSCONNECTOR_C_STD="$(MSCONNECTOR_C_STD)" MSCONNECTOR_CFLAGS="$(MSCONNECTOR_CFLAGS)" sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-http-authorization-service-timeout.sh
else
	$(ACTIVE_TEST_RUNNER) --group authorization-timeout
endif

check-common-sdk-contract:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-common-sdk-contract.py

check-common-security-contract:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-common-security-contract.py

check-common-memory-safety:
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-common-memory-safety.sh
else
	$(ACTIVE_TEST_RUNNER) --group memory-safety
endif

check-common-flow-integrity:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-common-flow-integrity.py

check-adapter-contracts:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-adapter-contracts.py

check-directive-parity:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-directive-parity.py

check-python-version-contract:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-python-version-contract.py

check-go-version-contract:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-go-version-contract.py

.PHONY: check-project-versions sync-project-versions
check-project-versions:
	$(PYTHON) ci/tools/sync-project-versions.py --check

sync-project-versions:
	$(PYTHON) ci/tools/sync-project-versions.py --sync

# Read-only host-runtime gate. Connector workflows set the reviewed runtime
# identity and any profile-specific prerequisite arguments.
HOSTRUNTIME_CONNECTOR ?= generic
HOSTRUNTIME_PROFILE ?= default
HOSTRUNTIME_EXPECTED_VERSION ?=
HOSTRUNTIME_BINARY ?=
HOSTRUNTIME_LOCK ?=
HOSTRUNTIME_LOCK_ROOT ?=
HOSTRUNTIME_LOCK_PROFILE ?=
HOSTRUNTIME_BINARY_ROOT ?=
HOSTRUNTIME_RUNTIME_ROOT ?= $(BUILD_ROOT)/hostruntime-evidence
HOSTRUNTIME_PREFLIGHT_OUTPUT_DIR ?= $(BUILD_ROOT)/hostruntime-evidence/$(HOSTRUNTIME_CONNECTOR)
HOSTRUNTIME_HEADER ?=
HOSTRUNTIME_SOURCE ?=
HOSTRUNTIME_TOOL ?=
HOSTRUNTIME_PORT ?=
HOSTRUNTIME_WRITE_DIR ?=
HOSTRUNTIME_DISK_PATH ?=
HOSTRUNTIME_MIN_FREE_BYTES ?=
HOSTRUNTIME_CONFIG ?=
HOSTRUNTIME_FIXTURE ?=

# Quote every caller-provided preflight value as one POSIX-shell argument.
# The nested connector targets pass these variables through a recipe, so
# double-quoting alone would allow a quote in a Make override to escape the
# intended argument boundary before the Python validation is reached.
hostruntime_shell_quote = '$(subst ','"'"',$(value 1))'

hostruntime-preflight:
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/runtime/common/hostruntime_preflight.py \
		--connector $(call hostruntime_shell_quote,$(value HOSTRUNTIME_CONNECTOR)) \
		--profile $(call hostruntime_shell_quote,$(value HOSTRUNTIME_PROFILE)) \
		--runtime-root $(call hostruntime_shell_quote,$(value HOSTRUNTIME_RUNTIME_ROOT)) \
		--output-dir $(call hostruntime_shell_quote,$(value HOSTRUNTIME_PREFLIGHT_OUTPUT_DIR)) \
		--expected-version $(call hostruntime_shell_quote,$(value HOSTRUNTIME_EXPECTED_VERSION)) \
		$(if $(value HOSTRUNTIME_BINARY),--binary $(call hostruntime_shell_quote,$(value HOSTRUNTIME_BINARY)),) \
		$(if $(value HOSTRUNTIME_BINARY_ROOT),--binary-root $(call hostruntime_shell_quote,$(value HOSTRUNTIME_BINARY_ROOT)),) \
		$(if $(value HOSTRUNTIME_LOCK),--runtime-lock $(call hostruntime_shell_quote,$(value HOSTRUNTIME_LOCK)),) \
		$(if $(value HOSTRUNTIME_LOCK_ROOT),--runtime-lock-root $(call hostruntime_shell_quote,$(value HOSTRUNTIME_LOCK_ROOT)),) \
		$(if $(value HOSTRUNTIME_LOCK_PROFILE),--lock-profile $(call hostruntime_shell_quote,$(value HOSTRUNTIME_LOCK_PROFILE)),) \
		$(if $(value HOSTRUNTIME_HEADER),--header $(call hostruntime_shell_quote,$(value HOSTRUNTIME_HEADER)),) \
		$(if $(value HOSTRUNTIME_SOURCE),--source $(call hostruntime_shell_quote,$(value HOSTRUNTIME_SOURCE)),) \
		$(if $(value HOSTRUNTIME_TOOL),--tool $(call hostruntime_shell_quote,$(value HOSTRUNTIME_TOOL)),) \
		$(if $(value HOSTRUNTIME_PORT),--port $(call hostruntime_shell_quote,$(value HOSTRUNTIME_PORT)),) \
		$(if $(value HOSTRUNTIME_WRITE_DIR),--write-dir $(call hostruntime_shell_quote,$(value HOSTRUNTIME_WRITE_DIR)),) \
		$(if $(value HOSTRUNTIME_DISK_PATH),--disk-path $(call hostruntime_shell_quote,$(value HOSTRUNTIME_DISK_PATH)),) \
		$(if $(value HOSTRUNTIME_MIN_FREE_BYTES),--min-free-bytes $(call hostruntime_shell_quote,$(value HOSTRUNTIME_MIN_FREE_BYTES)),) \
		$(if $(value HOSTRUNTIME_CONFIG),--config $(call hostruntime_shell_quote,$(value HOSTRUNTIME_CONFIG)),) \
		$(if $(value HOSTRUNTIME_FIXTURE),--fixture $(call hostruntime_shell_quote,$(value HOSTRUNTIME_FIXTURE)),)

test-hostruntime-preflight:
ifeq ($(ON_DEMAND_TESTS),1)
	$(PYTHON) -m unittest -v modsecurity_connector_tests.test_hostruntime_preflight
else
	$(ACTIVE_TEST_RUNNER) --group common
endif

lint: check-framework
	$(MAKE) check-active-inventory
	$(MAKE) check-project-versions
	$(MAKE) test-hostruntime-preflight
	find ci "$(TEST_ROOT)/connector_suite/modsecurity_connector_ci" -type f -name '*.sh' -print0 | xargs -0 -r -n 1 sh -n
	find connectors/envoy connectors/traefik connectors/lighttpd "$(TEST_ROOT)/connector_suite/adapters/envoy" "$(TEST_ROOT)/connector_suite/adapters/traefik" "$(TEST_ROOT)/connector_suite/adapters/lighttpd" -type f -name '*.sh' -print0 | xargs -0 -r -n 1 sh -n
	if command -v bash >/dev/null 2>&1; then find ci "$(TEST_ROOT)/connector_suite/modsecurity_connector_ci" -type f -name '*.sh' -print0 | xargs -0 -r -n 1 bash -n; find connectors/envoy connectors/traefik connectors/lighttpd "$(TEST_ROOT)/connector_suite/adapters/envoy" "$(TEST_ROOT)/connector_suite/adapters/traefik" "$(TEST_ROOT)/connector_suite/adapters/lighttpd" -type f -name '*.sh' -print0 | xargs -0 -r -n 1 bash -n; else echo "bash unavailable"; fi
	find ci "$(TEST_ROOT)/connector_suite/modsecurity_connector_ci" -type f -name '*.py' -print0 | xargs -0 -r env PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -P -m py_compile
	$(MAKE) check-no-crs-source-normalization
	$(MAKE) check-apache-common-adoption
	$(MAKE) check-apache-c-standard-wiring
	$(MAKE) check-apache-c17-lint
	$(MAKE) check-apache-intervention-cleanup
	$(MAKE) check-apache-request-transaction-cleanup-lint
	$(MAKE) check-apache-ruleset-cleanup-lint
	$(MAKE) check-optional-prerequisite-status
	$(MAKE) check-nginx-common-adoption
	$(MAKE) check-nginx-c-standard-wiring
	$(MAKE) check-nginx-c17-lint
	$(MAKE) check-haproxy-common-adoption
	$(MAKE) check-haproxy-c-standard-wiring
	$(MAKE) check-haproxy-c17-lint
	$(MAKE) check-haproxy-htx-overlay
	$(MAKE) check-remaining-connectors-common-adoption
	$(MAKE) check-remaining-connectors-host-integration
	$(MAKE) check-remaining-connectors-build-wiring
	$(MAKE) check-remaining-connectors-start-wiring
	$(MAKE) check-remaining-connectors-claim-policy
	"$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/evidence/collectors/connector_capabilities.py check
	"$(PYTHON)" $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/documentation/check-no-crs-doc-consistency.py
	"$(FRAMEWORK_PYTHON)" "$(FRAMEWORK_ROOT)/ci/checks/catalog/no_crs_baseline.py" catalog-check
	$(MAKE) check-remaining-connectors-c-standard-wiring
	$(MAKE) check-remaining-connectors-c17-lint
	$(MAKE) check-common-sdk-contract
	$(MAKE) check-common-security-contract
	$(MAKE) check-common-memory-safety
	$(MAKE) check-http-authorization-service-timeout
	$(MAKE) check-common-flow-integrity
	$(MAKE) check-adapter-contracts
	$(MAKE) check-directive-parity
	$(MAKE) check-framework-fixture-syntax
	$(MAKE) report-governance
	$(PYTHON) -m json.tool "$(TEST_ROOT)/connector_suite/config/testing/import-status.json" >/dev/null
	CONNECTOR_ROOT="$(CURDIR)" $(PYTHON) "$(FRAMEWORK_ROOT)/ci/tools/check-python-deps.py"
	CONNECTOR_ROOT="$(CURDIR)" $(PYTHON) "$(FRAMEWORK_ROOT)/ci/checks/documentation/check-workflow-yaml.py"
	$(MAKE) check-doc-links
	$(MAKE) check-bilingual-docs
	$(MAKE) check-variable-documentation
	$(MAKE) check-compiler-guides
	$(MAKE) check-connector-guides
	$(MAKE) check-connector-config-reference
	sh "$(FRAMEWORK_ROOT)/ci/checks/catalog/check-crs-version-pinning.sh"
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-common-helpers.sh
else
	$(ACTIVE_TEST_RUNNER) --group common
endif
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-adapter-helpers.sh
else
	$(ACTIVE_TEST_RUNNER) --group common
endif
ifeq ($(ON_DEMAND_TESTS),1)
	sh $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/common/check-adapter-metadata-drift.sh
else
	$(ACTIVE_TEST_RUNNER) --group common
endif
	if command -v actionlint >/dev/null 2>&1; then $(PYTHON) -m ci.tools.lint_installed_workflows; else echo "actionlint unavailable"; fi
	git diff --check

summary: check-framework
	$(PYTHON) "$(FRAMEWORK_ROOT)/ci/reporting/summarize-results.py" "$(BUILD_ROOT)/results/connector-summary.json"

case-matrix: generate-test-matrix
	@echo "case matrix: reports/testing/generated/coverage/case-matrix.generated.md"

install-dev-deps: check-framework
	sh "$(FRAMEWORK_ROOT)/ci/tools/bootstrap-python.sh"

setup-dev: install-dev-deps
	@echo "setup-dev: using PYTHON=$(PYTHON)"
	@echo "setup-dev: test framework -> $(FRAMEWORK_ROOT)"
	@echo "setup-dev: next steps -> make lint; make fetch-deps; make doctor; make smoke-all"

fetch-modsecurity-v3: check-framework
	sh "$(FRAMEWORK_ROOT)/ci/provisioning/fetch-smoke-sources.sh" v3

fetch-deps bootstrap-runtime: prepare-runtime-components
	@echo "fetch-deps: runtime components prepared in CONNECTOR_COMPONENT_CACHE=$${CONNECTOR_COMPONENT_CACHE:-auto}"

fetch-crs: check-framework
	sh "$(FRAMEWORK_ROOT)/ci/provisioning/fetch-crs.sh"

prepare-crs: check-framework
	sh "$(FRAMEWORK_ROOT)/ci/provisioning/prepare-crs.sh"

doctor env-check: check-framework
	sh "$(FRAMEWORK_ROOT)/ci/tools/doctor.sh"

print-python:
	@echo "make: using PYTHON=$(PYTHON)"

bootstrap-all: setup-dev fetch-deps doctor
	@echo "bootstrap-all complete (smoke not run)"

quick-check codex-check: lint
	find "$(FRAMEWORK_ROOT)"/tests/normalizers "$(FRAMEWORK_ROOT)"/tests/runners "$(FRAMEWORK_ROOT)"/ci -type f -name '*.py' -print0 | xargs -0 -r env PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -P -m py_compile
	git diff --check

smoke-installed installed-readiness: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	sh "$(FRAMEWORK_ROOT)/ci/runtime/smoke-installed.sh"

doctor-install-hints:
	@echo "Install hints (Debian/Ubuntu example):"
	@echo "  sudo apt-get update"
	@echo "  sudo apt-get install -y git make gcc clang autoconf automake libtool pkg-config apache2-dev nginx libmodsecurity-dev"
	@echo "Install hints (RHEL/Fedora example):"
	@echo "  sudo dnf install -y git make gcc clang autoconf automake libtool pkgconf-pkg-config httpd-devel nginx mod_security"
	@echo "Install hints (Alpine example):"
	@echo "  sudo apk add git make gcc clang autoconf automake libtool pkgconf apache2-dev nginx modsecurity"

doctor-quick: check-framework
	DOCTOR_MODE=quick sh "$(FRAMEWORK_ROOT)/ci/tools/doctor.sh"

quick-all: check-framework
	$(if $(filter 1,$(ON_DEMAND_TESTS)),,$(error specialist catalog is archived; explicit ON_DEMAND_TESTS=1 authorization is required))
	sh "$(FRAMEWORK_ROOT)/ci/tools/quick-all.sh"

cloud-quick-check: setup-dev lint generate-test-matrix check-test-matrix quick-check
	find "$(FRAMEWORK_ROOT)"/tests/normalizers "$(FRAMEWORK_ROOT)"/tests/runners "$(FRAMEWORK_ROOT)"/ci -type f -name '*.py' -print0 | xargs -0 -r env PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -P -m py_compile
	git diff --check
	@echo "INFO: Cloud check is framework/generator only and not runtime compatibility evidence."

generate-test-matrix: check-framework
	PYTHON="$(FRAMEWORK_PYTHON)" FRAMEWORK_ROOT="$(FRAMEWORK_ROOT)" CONNECTOR_ROOT="$(CURDIR)" OUTPUT_ROOT="$(CURDIR)" SKIP_ROOT_SUMMARY=1 $(MAKE) -C "$(FRAMEWORK_ROOT)" generate-test-matrix
	$(PYTHON) $(TEST_ROOT)/connector_suite/modsecurity_connector_ci/checks/documentation/ensure-test-matrix-language-switches.py

TEST_MATRIX_DIFF_PATHS = reports/testing/generated/coverage reports/testing/generated/runtime reports/testing/test-coverage-overview.md

check-test-matrix: check-framework
	@test ! -f TEST-COVERAGE-SUMMARY.md || { \
		echo "Generated root coverage summary moved to $(FRAMEWORK_ROOT)/TEST-COVERAGE-SUMMARY.md; remove parent TEST-COVERAGE-SUMMARY.md"; \
		exit 1; \
	}
	@mkdir -p "$(BUILD_ROOT)/check-test-matrix"
	@before="$(BUILD_ROOT)/check-test-matrix/before.diff"; \
	after="$(BUILD_ROOT)/check-test-matrix/after.diff"; \
	framework_before="$(BUILD_ROOT)/check-test-matrix/framework-before.diff"; \
	framework_after="$(BUILD_ROOT)/check-test-matrix/framework-after.diff"; \
	git diff --binary -- $(TEST_MATRIX_DIFF_PATHS) > "$$before"; \
	git -C "$(FRAMEWORK_ROOT)" diff --binary -- TEST-COVERAGE-SUMMARY.md > "$$framework_before"; \
	$(MAKE) generate-test-matrix; \
	git diff --binary -- $(TEST_MATRIX_DIFF_PATHS) > "$$after"; \
	git -C "$(FRAMEWORK_ROOT)" diff --binary -- TEST-COVERAGE-SUMMARY.md > "$$framework_after"; \
	if ! cmp -s "$$before" "$$after" || ! cmp -s "$$framework_before" "$$framework_after"; then \
		echo "Generated test matrix docs are out of date. Run make generate-test-matrix"; \
		exit 1; \
	fi

export PYTHONSAFEPATH := 1
