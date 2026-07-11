PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
STATE_HOME ?= $(if $(XDG_STATE_HOME),$(XDG_STATE_HOME),$(HOME)/.local/state)
SOURCE_ROOT ?= $(STATE_HOME)/ModSecurity-conector-src
BUILD_ROOT ?= $(STATE_HOME)/ModSecurity-conector-build
TMP_ROOT ?= $(BUILD_ROOT)/tmp
LOG_ROOT ?= $(BUILD_ROOT)/logs
MRTS_BUILD_ROOT ?= $(BUILD_ROOT)/mrts
FRAMEWORK_ROOT ?= $(CURDIR)
CONNECTOR_ROOT ?= $(CURDIR)
OUTPUT_ROOT ?= $(CONNECTOR_ROOT)
PYTHONDONTWRITEBYTECODE ?= 1
NO_CRS_TOOL ?= $(FRAMEWORK_ROOT)/ci/no_crs_baseline.py
NO_CRS_RUN_ID ?= local
CONNECTOR ?=
CAPABILITIES_FILE ?= $(CONNECTOR_ROOT)/connectors/$(CONNECTOR)/capabilities.json
EVIDENCE_ROOT ?= $(BUILD_ROOT)/no-crs-evidence
NO_CRS_RUN_DIR ?= $(EVIDENCE_ROOT)/$(CONNECTOR)/$(NO_CRS_RUN_ID)
PLAN_FILE ?= $(BUILD_ROOT)/no-crs-plans/$(CONNECTOR)/$(NO_CRS_RUN_ID).json
NO_CRS_STAGE_RC ?= 0
NO_CRS_STAGE_REASON ?=
NO_CRS_FINALIZE_ARGS ?=
EVIDENCE_STAGE ?= no_crs_baseline
NO_CRS_SUMMARY_ROOT ?= $(EVIDENCE_ROOT)/summary/$(NO_CRS_RUN_ID)

export BUILD_ROOT
export SOURCE_ROOT
export TMP_ROOT
export LOG_ROOT
export FRAMEWORK_ROOT
export CONNECTOR_ROOT
export OUTPUT_ROOT
export PYTHON
export PYTHONDONTWRITEBYTECODE
export REFRESH
export SMOKE_CASES
export CASE_SCOPE
export FORCE_ALL_CASES
export MODSECURITY_REPO_URL
export MODSECURITY_GIT_REF
export MODSECURITY_SOURCE_DIR
export MODSECURITY_V3_SOURCE_DIR
export MODSECURITY_V3_ROOT
export MODSECURITY_TEST_VARIANT
export MODSECURITY_MRTS_VARIANT
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
export CRS_REPO_URL
export CRS_GIT_REF
export CRS_SOURCE_DIR
export CRS_RUNTIME_DIR
export MODSECURITY_RULE_PREAMBLE_FILE

.PHONY: lint quick-check codex-check setup-dev install-dev-deps check-security-data-flow-cases check-security-data-flow-normalizers generate-test-matrix refresh-framework-reports check-test-matrix runtime-matrix runtime-matrix-all runtime-matrix-haproxy runtime-matrix-haproxy-all smoke-apache smoke-nginx smoke-haproxy smoke-all test test-no-crs test-with-crs fetch-deps fetch-modsecurity-v3 fetch-crs prepare-crs prepare-haproxy-runtime mrts-generate mrts-load mrts-import test-no-mrts test-with-mrts test-with-mrts-feature-demo test-mrts-matrix mrts-ftw check-no-crs-catalog test-no-crs-contract no-crs-plan no-crs-init no-crs-finalize no-crs-summary check-no-crs-evidence check-no-crs-result-schema check-no-crs-evidence-completeness check-no-crs-capability-consistency check-no-crs-claim-policy check-no-crs-artifact-layout check-no-crs-body-payload-absence check-no-crs-status-consistency check-no-crs-doc-consistency

define RUN_WITH_FRAMEWORK_REPORT_REFRESH
	@set +e; \
	$(1); \
	runtime_rc=$$?; \
	set -e; \
	refresh_rc=0; \
	$(MAKE) refresh-framework-reports || refresh_rc=$$?; \
	if [ "$$runtime_rc" -ne 0 ]; then exit "$$runtime_rc"; fi; \
	exit "$$refresh_rc"
endef

setup-dev install-dev-deps:
	sh ci/bootstrap-python.sh

lint:
	sh -n ci/*.sh
	if command -v bash >/dev/null 2>&1; then bash -n ci/*.sh; else echo "bash unavailable"; fi
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m py_compile tests/normalizers/*.py tests/runners/*.py ci/*.py
	$(PYTHON) ci/check-python-deps.py
	$(PYTHON) ci/check-workflow-yaml.py
	$(PYTHON) ci/check-response-body-promotion.py --framework-root "$(FRAMEWORK_ROOT)" --connector-root "$(CONNECTOR_ROOT)" --output-root "$(OUTPUT_ROOT)"
	$(PYTHON) ci/check-security-data-flow-cases.py
	$(PYTHON) ci/check-security-data-flow-normalizers.py
	$(PYTHON) ci/no_crs_baseline.py catalog-check
	sh ci/check-crs-version-pinning.sh
	sh ci/check-open-runtime-provisioning-contract.sh
	git diff --check

check-security-data-flow-cases:
	$(PYTHON) ci/check-security-data-flow-cases.py

check-security-data-flow-normalizers:
	$(PYTHON) ci/check-security-data-flow-normalizers.py

test-no-crs-contract:
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m unittest discover -s tests/no_crs -v

check-no-crs-catalog:
	$(PYTHON) "$(NO_CRS_TOOL)" catalog-check

no-crs-plan: check-no-crs-catalog
	@test -n "$(CONNECTOR)" || { echo "CONNECTOR is required" >&2; exit 2; }
	$(PYTHON) "$(NO_CRS_TOOL)" select --connector "$(CONNECTOR)" --capabilities "$(CAPABILITIES_FILE)" --evidence-stage "$(EVIDENCE_STAGE)" --output "$(PLAN_FILE)"

no-crs-init: no-crs-plan
	$(PYTHON) "$(NO_CRS_TOOL)" init --connector "$(CONNECTOR)" --capabilities "$(CAPABILITIES_FILE)" --evidence-stage "$(EVIDENCE_STAGE)" --plan "$(PLAN_FILE)" --run-dir "$(NO_CRS_RUN_DIR)" --run-id "$(NO_CRS_RUN_ID)" --connector-root "$(CONNECTOR_ROOT)" --executed-target "$(EVIDENCE_STAGE)-$(CONNECTOR)"

no-crs-finalize:
	@test -n "$(CONNECTOR)" || { echo "CONNECTOR is required" >&2; exit 2; }
	$(PYTHON) "$(NO_CRS_TOOL)" finalize --run-dir "$(NO_CRS_RUN_DIR)" --connector-root "$(CONNECTOR_ROOT)" --capabilities "$(CAPABILITIES_FILE)" --stage-rc "$(NO_CRS_STAGE_RC)" --stage-reason "$(NO_CRS_STAGE_REASON)" $(NO_CRS_FINALIZE_ARGS)

no-crs-summary:
	mkdir -p "$(NO_CRS_SUMMARY_ROOT)"
	$(PYTHON) "$(NO_CRS_TOOL)" summarize --evidence-root "$(EVIDENCE_ROOT)" --run-id "$(NO_CRS_RUN_ID)" --output-json "$(NO_CRS_SUMMARY_ROOT)/all-connectors-no-crs-summary.json" --output-md "$(NO_CRS_SUMMARY_ROOT)/all-connectors-no-crs-summary.md" --output-md-de "$(NO_CRS_SUMMARY_ROOT)/all-connectors-no-crs-summary.de.md" $(if $(REPORTS_DIR),--reports-dir "$(REPORTS_DIR)",)

define RUN_NO_CRS_CHECK
	@test -n "$(CONNECTOR)" || { echo "CONNECTOR is required" >&2; exit 2; }
	$(PYTHON) "$(NO_CRS_TOOL)" validate --evidence-root "$(NO_CRS_RUN_DIR)" --connector "$(CONNECTOR)" --connector-root "$(CONNECTOR_ROOT)" --capabilities "$(CAPABILITIES_FILE)" --check "$(1)"
endef

check-no-crs-result-schema:
	$(call RUN_NO_CRS_CHECK,schema)

check-no-crs-evidence-completeness:
	$(call RUN_NO_CRS_CHECK,completeness)

check-no-crs-capability-consistency:
	$(call RUN_NO_CRS_CHECK,capability)

check-no-crs-claim-policy:
	$(call RUN_NO_CRS_CHECK,claim-policy)

check-no-crs-artifact-layout:
	$(call RUN_NO_CRS_CHECK,layout)

check-no-crs-body-payload-absence:
	$(call RUN_NO_CRS_CHECK,body-payload)

check-no-crs-status-consistency:
	$(call RUN_NO_CRS_CHECK,status)

check-no-crs-evidence:
	$(call RUN_NO_CRS_CHECK,all)

# Repository-owned bilingual reports are checked at the root.  Framework-side
# document consistency starts by validating the one canonical source catalog.
check-no-crs-doc-consistency: check-no-crs-catalog

quick-check codex-check: lint
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m py_compile tests/normalizers/*.py tests/runners/*.py ci/*.py
	$(PYTHON) ci/check-mrts-importer.py
	git diff --check

generate-test-matrix:
	sh -eu -c '. ci/common.sh; . ci/mrts-common.sh; validate_mrts_variant; prepare_mrts_variant; if [ "$$MODSECURITY_MRTS_VARIANT" = "with-mrts" ]; then mrts_import_cases; fi; "$(PYTHON)" ci/generate-case-matrix.py --framework-root "$(FRAMEWORK_ROOT)" --connector-root "$(CONNECTOR_ROOT)" --output-root "$(OUTPUT_ROOT)" $(if $(SKIP_ROOT_SUMMARY),--skip-root-summary,)'

refresh-framework-reports:
	MODSECURITY_MRTS_VARIANT=with-mrts $(MAKE) generate-test-matrix CONNECTOR_ROOT="$(FRAMEWORK_ROOT)" OUTPUT_ROOT="$(FRAMEWORK_ROOT)"

check-test-matrix: refresh-framework-reports
	@git -C "$(OUTPUT_ROOT)" diff --exit-code -- reports/testing docs/testing >/dev/null || { \
		echo "Generated test matrix docs are out of date for OUTPUT_ROOT=$(OUTPUT_ROOT)"; \
		exit 1; \
	}
	@git -C "$(FRAMEWORK_ROOT)" diff --exit-code -- TEST-COVERAGE-SUMMARY.md >/dev/null || { \
		echo "Framework coverage summary is out of date. Run make generate-test-matrix"; \
		exit 1; \
	}

runtime-matrix:
	sh ci/run-runtime-matrix.sh

runtime-matrix-all:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,FORCE_ALL_CASES=1 sh ci/run-runtime-matrix.sh)

runtime-matrix-haproxy:
	sh ci/run-haproxy-runtime-matrix.sh

runtime-matrix-haproxy-all:
	FORCE_ALL_CASES=1 sh ci/run-haproxy-runtime-matrix.sh

smoke-apache:
	CASE_SCOPE=all sh ci/run-apache-smoke.sh

smoke-nginx:
	CASE_SCOPE=all sh ci/run-nginx-smoke.sh

smoke-haproxy:
	CASE_SCOPE=all sh ci/run-haproxy-smoke.sh

smoke-all:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,CASE_SCOPE=all sh ci/run-connector-smokes.sh)

test: test-no-crs test-with-crs

test-no-crs:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,MODSECURITY_TEST_VARIANT=no-crs MODSECURITY_RULE_PREAMBLE_FILE= sh -eu -c '. ci/common.sh; RESULTS_DIR="$$BUILD_ROOT/results/no-crs"; export RESULTS_DIR; CASE_SCOPE=all sh ci/run-connector-smokes.sh')

test-with-crs:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,MODSECURITY_TEST_VARIANT=with-crs sh -eu -c '. ci/common.sh; sh ci/fetch-crs.sh; sh ci/prepare-crs.sh; MODSECURITY_RULE_PREAMBLE_FILE="$$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf"; RESULTS_DIR="$$BUILD_ROOT/results/with-crs"; export MODSECURITY_RULE_PREAMBLE_FILE RESULTS_DIR; CASE_SCOPE=all sh ci/run-connector-smokes.sh')

mrts-generate:
	sh -eu -c '. ci/common.sh; . ci/mrts-common.sh; mrts_generate_all_corpora'

mrts-load:
	sh ci/write-mrts-load.sh

mrts-import:
	sh -eu -c '. ci/common.sh; . ci/mrts-common.sh; mrts_generate_all_corpora; MRTS_RULES_OUT="$$MRTS_UPSTREAM_RULES_OUT" sh ci/write-mrts-load.sh >/dev/null; mrts_import_cases'

test-no-mrts:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,MODSECURITY_MRTS_VARIANT=no-mrts sh -eu -c '. ci/common.sh; . ci/mrts-common.sh; validate_mrts_variant; prepare_mrts_variant; set_mrts_results_dir; CASE_SCOPE=all sh ci/run-connector-smokes.sh')

test-with-mrts:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,MODSECURITY_MRTS_VARIANT=with-mrts sh -eu -c '. ci/common.sh; . ci/mrts-common.sh; validate_mrts_variant; prepare_mrts_runtime_variant; set_mrts_results_dir; CASE_SCOPE=all sh ci/run-connector-smokes.sh')

test-with-mrts-feature-demo:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,MODSECURITY_MRTS_VARIANT=with-mrts MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1 sh -eu -c '. ci/common.sh; . ci/mrts-common.sh; validate_mrts_variant; prepare_mrts_runtime_variant; set_mrts_results_dir; CASE_SCOPE=all sh ci/run-connector-smokes.sh')

test-mrts-matrix:
	MODSECURITY_TEST_VARIANT=no-crs MODSECURITY_MRTS_VARIANT=no-mrts $(MAKE) test-no-mrts
	MODSECURITY_TEST_VARIANT=no-crs MODSECURITY_MRTS_VARIANT=with-mrts $(MAKE) test-with-mrts
	MODSECURITY_TEST_VARIANT=with-crs MODSECURITY_MRTS_VARIANT=no-mrts $(MAKE) test-no-mrts
	MODSECURITY_TEST_VARIANT=with-crs MODSECURITY_MRTS_VARIANT=with-mrts $(MAKE) test-with-mrts

mrts-ftw: mrts-generate
	@sh -eu -c ' \
		FRAMEWORK_ROOT="$${FRAMEWORK_ROOT:-$(FRAMEWORK_ROOT)}"; \
		MRTS_FTW_CONFIG="$${MRTS_FTW_CONFIG:-$$FRAMEWORK_ROOT/tests/mrts/ftw.mrts.config.yaml}"; \
		BUILD_ROOT="$${BUILD_ROOT:-$(BUILD_ROOT)}"; \
		MRTS_BUILD_ROOT="$${MRTS_BUILD_ROOT:-$$BUILD_ROOT/mrts}"; \
		MRTS_FTW_OUT="$${MRTS_FTW_OUT:-$$MRTS_BUILD_ROOT/upstream-config-tests/ftw}"; \
		if ! command -v go-ftw >/dev/null 2>&1; then echo "BLOCKED: go-ftw missing" >&2; exit 77; fi; \
		if [ ! -f "$$MRTS_FTW_CONFIG" ]; then echo "BLOCKED: MRTS_FTW_CONFIG missing: $$MRTS_FTW_CONFIG" >&2; exit 77; fi; \
		go-ftw run --config "$$MRTS_FTW_CONFIG" --dir "$$MRTS_FTW_OUT" --wait-for-expect-status-code 200 --fail-fast; \
	'

fetch-modsecurity-v3:
	sh ci/fetch-smoke-sources.sh v3

fetch-deps:
	sh ci/fetch-smoke-sources.sh all

fetch-crs:
	sh ci/fetch-crs.sh

prepare-crs:
	sh ci/prepare-crs.sh

prepare-haproxy-runtime:
	sh ci/prepare-haproxy-runtime.sh
