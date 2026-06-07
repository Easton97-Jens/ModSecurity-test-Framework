PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
STATE_HOME ?= $(if $(XDG_STATE_HOME),$(XDG_STATE_HOME),$(HOME)/.local/state)
SOURCE_ROOT ?= /src
BUILD_ROOT ?= /src/ModSecurity-conector-build
TMP_ROOT ?= $(BUILD_ROOT)/tmp
LOG_ROOT ?= $(BUILD_ROOT)/logs
FRAMEWORK_ROOT ?= $(CURDIR)
CONNECTOR_ROOT ?= $(CURDIR)
OUTPUT_ROOT ?= $(CONNECTOR_ROOT)
PYTHONDONTWRITEBYTECODE ?= 1

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
export EXTRA_CASE_ROOTS
export MRTS_ROOT
export MRTS_DEFINITIONS
export MRTS_RULES_OUT
export MRTS_FTW_OUT
export MRTS_LOAD_FILE
export MRTS_CASE_ROOT
export CRS_REPO_URL
export CRS_GIT_REF
export CRS_SOURCE_DIR
export CRS_RUNTIME_DIR
export MODSECURITY_RULE_PREAMBLE_FILE

.PHONY: lint quick-check codex-check generate-test-matrix check-test-matrix runtime-matrix runtime-matrix-all smoke-apache smoke-nginx smoke-all test test-no-crs test-with-crs fetch-deps fetch-modsecurity-v3 fetch-crs prepare-crs mrts-generate mrts-load mrts-import test-no-mrts test-with-mrts test-with-mrts-feature-demo test-mrts-matrix mrts-ftw

lint:
	sh -n ci/*.sh
	if command -v bash >/dev/null 2>&1; then bash -n ci/*.sh; else echo "bash unavailable"; fi
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m py_compile tests/normalizers/*.py tests/runners/*.py ci/*.py
	$(PYTHON) ci/check-python-deps.py
	$(PYTHON) ci/check-workflow-yaml.py
	$(PYTHON) ci/check-response-body-promotion.py --framework-root "$(FRAMEWORK_ROOT)" --connector-root "$(CONNECTOR_ROOT)" --output-root "$(OUTPUT_ROOT)"
	sh ci/check-crs-version-pinning.sh
	git diff --check

quick-check codex-check: lint
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m py_compile tests/normalizers/*.py tests/runners/*.py ci/*.py
	$(PYTHON) ci/check-mrts-importer.py
	git diff --check

generate-test-matrix:
	sh -eu -c '. ci/common.sh; . ci/mrts-common.sh; validate_mrts_variant; prepare_mrts_variant; if [ "$$MODSECURITY_MRTS_VARIANT" = "with-mrts" ]; then mrts_import_cases; fi; "$(PYTHON)" ci/generate-case-matrix.py --framework-root "$(FRAMEWORK_ROOT)" --connector-root "$(CONNECTOR_ROOT)" --output-root "$(OUTPUT_ROOT)"'

check-test-matrix: generate-test-matrix
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
	FORCE_ALL_CASES=1 sh ci/run-runtime-matrix.sh

smoke-apache:
	CASE_SCOPE=all sh ci/run-apache-smoke.sh

smoke-nginx:
	CASE_SCOPE=all sh ci/run-nginx-smoke.sh

smoke-all:
	CASE_SCOPE=all sh ci/run-connector-smokes.sh

test: test-no-crs test-with-crs

test-no-crs:
	MODSECURITY_TEST_VARIANT=no-crs MODSECURITY_RULE_PREAMBLE_FILE= sh -eu -c '. ci/common.sh; RESULTS_DIR="$$BUILD_ROOT/results/no-crs"; export RESULTS_DIR; CASE_SCOPE=all sh ci/run-connector-smokes.sh'

test-with-crs:
	MODSECURITY_TEST_VARIANT=with-crs sh -eu -c '. ci/common.sh; sh ci/fetch-crs.sh; sh ci/prepare-crs.sh; MODSECURITY_RULE_PREAMBLE_FILE="$$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf"; RESULTS_DIR="$$BUILD_ROOT/results/with-crs"; export MODSECURITY_RULE_PREAMBLE_FILE RESULTS_DIR; CASE_SCOPE=all sh ci/run-connector-smokes.sh'

mrts-generate:
	sh -eu -c '. ci/common.sh; . ci/mrts-common.sh; mrts_generate_all_corpora'

mrts-load:
	sh ci/write-mrts-load.sh

mrts-import:
	sh -eu -c '. ci/common.sh; . ci/mrts-common.sh; mrts_generate_all_corpora; MRTS_RULES_OUT="$$MRTS_UPSTREAM_RULES_OUT" sh ci/write-mrts-load.sh >/dev/null; mrts_import_cases'

test-no-mrts:
	MODSECURITY_MRTS_VARIANT=no-mrts sh -eu -c '. ci/common.sh; . ci/mrts-common.sh; validate_mrts_variant; prepare_mrts_variant; set_mrts_results_dir; CASE_SCOPE=all sh ci/run-connector-smokes.sh'

test-with-mrts:
	MODSECURITY_MRTS_VARIANT=with-mrts sh -eu -c '. ci/common.sh; . ci/mrts-common.sh; validate_mrts_variant; prepare_mrts_runtime_variant; set_mrts_results_dir; CASE_SCOPE=all sh ci/run-connector-smokes.sh'

test-with-mrts-feature-demo:
	MODSECURITY_MRTS_VARIANT=with-mrts MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1 sh -eu -c '. ci/common.sh; . ci/mrts-common.sh; validate_mrts_variant; prepare_mrts_runtime_variant; set_mrts_results_dir; CASE_SCOPE=all sh ci/run-connector-smokes.sh'

test-mrts-matrix:
	MODSECURITY_TEST_VARIANT=no-crs MODSECURITY_MRTS_VARIANT=no-mrts $(MAKE) test-no-mrts
	MODSECURITY_TEST_VARIANT=no-crs MODSECURITY_MRTS_VARIANT=with-mrts $(MAKE) test-with-mrts
	MODSECURITY_TEST_VARIANT=with-crs MODSECURITY_MRTS_VARIANT=no-mrts $(MAKE) test-no-mrts
	MODSECURITY_TEST_VARIANT=with-crs MODSECURITY_MRTS_VARIANT=with-mrts $(MAKE) test-with-mrts

mrts-ftw: mrts-generate
	@sh -eu -c ' \
		FRAMEWORK_ROOT="$${FRAMEWORK_ROOT:-$(FRAMEWORK_ROOT)}"; \
		MRTS_FTW_CONFIG="$${MRTS_FTW_CONFIG:-$$FRAMEWORK_ROOT/tests/mrts/ftw.mrts.config.yaml}"; \
		MRTS_FTW_OUT="$${MRTS_FTW_OUT:-$$FRAMEWORK_ROOT/tests/mrts/generated/ftw}"; \
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
