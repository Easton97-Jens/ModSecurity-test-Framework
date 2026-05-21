PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
STATE_HOME ?= $(if $(XDG_STATE_HOME),$(XDG_STATE_HOME),$(HOME)/.local/state)
BUILD_ROOT ?= $(STATE_HOME)/ModSecurity-test-framework-build
FRAMEWORK_ROOT ?= $(CURDIR)
CONNECTOR_ROOT ?= $(CURDIR)
PYTHONDONTWRITEBYTECODE ?= 1

export BUILD_ROOT
export FRAMEWORK_ROOT
export CONNECTOR_ROOT
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
export SOURCE_ROOT

.PHONY: lint generate-test-matrix check-test-matrix runtime-matrix runtime-matrix-all smoke-apache smoke-nginx smoke-all fetch-deps fetch-modsecurity-v3

lint:
	sh -n ci/*.sh
	if command -v bash >/dev/null 2>&1; then bash -n ci/*.sh; else echo "bash unavailable"; fi
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m py_compile tests/normalizers/*.py tests/runners/*.py ci/*.py
	$(PYTHON) ci/check-python-deps.py
	$(PYTHON) ci/check-workflow-yaml.py
	git diff --check

generate-test-matrix:
	$(PYTHON) ci/generate-case-matrix.py --framework-root "$(FRAMEWORK_ROOT)" --connector-root "$(CONNECTOR_ROOT)" --output-root "$(CONNECTOR_ROOT)"

check-test-matrix:
	$(PYTHON) ci/generate-case-matrix.py --framework-root "$(FRAMEWORK_ROOT)" --connector-root "$(CONNECTOR_ROOT)" --output-root "$(CONNECTOR_ROOT)"
	@git -C "$(CONNECTOR_ROOT)" diff --exit-code -- docs/testing/generated docs/testing/test-coverage-overview.md TEST-COVERAGE-SUMMARY.md >/dev/null || { \
		echo "Generated test matrix docs are out of date for CONNECTOR_ROOT=$(CONNECTOR_ROOT)"; \
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

fetch-modsecurity-v3:
	sh ci/fetch-smoke-sources.sh v3

fetch-deps:
	sh ci/fetch-smoke-sources.sh all
