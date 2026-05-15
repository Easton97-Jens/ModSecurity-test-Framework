BUILD_ROOT ?= /src/ModSecurity-test-Framework-build
PYTHONDONTWRITEBYTECODE ?= 1

export BUILD_ROOT
export PYTHONDONTWRITEBYTECODE
export REFRESH
export SMOKE_CASES
export CASE_SCOPE
export MODSECURITY_V3_SOURCE_DIR
export MODSECURITY_APACHE_SOURCE_DIR
export MODSECURITY_NGINX_SOURCE_DIR
export BUILD_HTTPD_FROM_SOURCE
export BUILD_PCRE2_FROM_SOURCE
export BUILD_NGINX_FROM_SOURCE
export NGINX_SOURCE_MODE
export NGINX_GITHUB_REPO
export NGINX_RELEASE_TAG
export RESPONSE_BODY_PROBE_REPEAT
export RESPONSE_BODY_PROBE_ROOT
export RESPONSE_BODY_PROBE_CASE

.PHONY: smoke-common smoke-apache smoke-nginx smoke-all probe-response-body lint summary case-matrix

smoke-common:
	CASE_SCOPE=common sh ci/run-connector-smokes.sh

smoke-apache:
	CASE_SCOPE=all sh ci/run-apache-smoke.sh

smoke-nginx:
	CASE_SCOPE=all sh ci/run-nginx-smoke.sh

smoke-all:
	CASE_SCOPE=all sh ci/run-connector-smokes.sh

probe-response-body:
	sh ci/probe-response-body-blocking.sh

lint:
	sh -n ci/*.sh connectors/apache/harness/*.sh connectors/nginx/harness/*.sh
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" python3 -m py_compile tests/normalizers/*.py tests/runners/*.py ci/*.py
	python3 -m json.tool tests/import-status.json >/dev/null
	python3 ci/check-workflow-yaml.py
	if command -v actionlint >/dev/null 2>&1; then actionlint .github/workflows/*.yml; else echo "actionlint unavailable"; fi
	git diff --check

summary:
	python3 ci/summarize-results.py "$(BUILD_ROOT)/results/connector-summary.json"

case-matrix:
	python3 ci/write-case-matrix.py "$(BUILD_ROOT)/results/connector-summary.json" docs/case-matrix.md
