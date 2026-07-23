# A command-line or inherited recursive Make variable is automatically exposed
# to early $(shell ...) calls. Escape dollars before the first such call so
# finalizer inputs can become only wrapper argv data, never Make functions.
no_crs_literal_dollar := $$
ifneq ($(origin NO_CRS_TOOL),undefined)
override NO_CRS_TOOL := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value NO_CRS_TOOL))
endif
ifneq ($(origin CONNECTOR),undefined)
override CONNECTOR := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value CONNECTOR))
endif
ifneq ($(origin NO_CRS_RUN_DIR),undefined)
override NO_CRS_RUN_DIR := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value NO_CRS_RUN_DIR))
endif
ifneq ($(origin CONNECTOR_ROOT),undefined)
override CONNECTOR_ROOT := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value CONNECTOR_ROOT))
endif
ifneq ($(origin CAPABILITIES_FILE),undefined)
override CAPABILITIES_FILE := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value CAPABILITIES_FILE))
endif
ifneq ($(origin NO_CRS_STAGE_RC),undefined)
override NO_CRS_STAGE_RC := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value NO_CRS_STAGE_RC))
endif
ifneq ($(origin NO_CRS_STAGE_REASON),undefined)
override NO_CRS_STAGE_REASON := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value NO_CRS_STAGE_REASON))
endif
ifneq ($(origin NO_CRS_FINALIZE_ARGS),undefined)
override NO_CRS_FINALIZE_ARGS := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value NO_CRS_FINALIZE_ARGS))
endif
ifneq ($(origin NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR),undefined)
override NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR))
endif
ifneq ($(origin STATE_HOME),undefined)
override STATE_HOME := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value STATE_HOME))
endif
ifneq ($(origin BUILD_ROOT),undefined)
override BUILD_ROOT := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value BUILD_ROOT))
endif
ifneq ($(origin EVIDENCE_ROOT),undefined)
override EVIDENCE_ROOT := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value EVIDENCE_ROOT))
endif
ifneq ($(origin NO_CRS_RUN_ID),undefined)
override NO_CRS_RUN_ID := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value NO_CRS_RUN_ID))
endif
ifneq ($(origin CI_ROOT),undefined)
override CI_ROOT := $(subst $(no_crs_literal_dollar),$(no_crs_literal_dollar)$(no_crs_literal_dollar),$(value CI_ROOT))
endif

PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
STATE_HOME ?= $(if $(XDG_STATE_HOME),$(XDG_STATE_HOME),$(HOME)/.local/state)
SOURCE_ROOT ?= $(STATE_HOME)/ModSecurity-conector-src
BUILD_ROOT ?= $(STATE_HOME)/ModSecurity-conector-build
PYTHONPYCACHEPREFIX := $(if $(strip $(PYTHONPYCACHEPREFIX)),$(PYTHONPYCACHEPREFIX),$(BUILD_ROOT)/pycache)
TMP_ROOT ?= $(BUILD_ROOT)/tmp
LOG_ROOT ?= $(BUILD_ROOT)/logs
MRTS_BUILD_ROOT ?= $(BUILD_ROOT)/mrts
FRAMEWORK_ROOT ?= $(CURDIR)
CONNECTOR_ROOT ?= $(CURDIR)
OUTPUT_ROOT ?= $(CONNECTOR_ROOT)
CI_ROOT ?= $(FRAMEWORK_ROOT)/ci
CI_SHELL_FILES := $(shell find ci -type f -name '*.sh' -print | sort)
CI_PYTHON_FILES := $(shell find ci -type f -name '*.py' -print | sort)
PYTHONDONTWRITEBYTECODE ?= 1
NO_CRS_TOOL ?= $(CI_ROOT)/checks/catalog/no_crs_baseline.py
WORKFLOW_SECURITY_TOOL ?= $(CURDIR)/ci/checks/security/check-github-actions-workflows.py
PYTHON_VERSION_CONTRACT_TOOL ?= $(CURDIR)/ci/checks/security/check-python-version.py
FULL_LIFECYCLE_EVIDENCE_TOOL ?= $(CI_ROOT)/checks/evidence/check_full_lifecycle_evidence.py
TRANSPORT_HARDENING_EVIDENCE_TOOL ?= $(CI_ROOT)/checks/evidence/check_transport_hardening_evidence.py
PROTOCOL_CLIENT_TOOL ?= $(CI_ROOT)/checks/protocol/protocol_client.py
PROTOCOL_EVIDENCE_TOOL ?= $(CI_ROOT)/checks/protocol/check_protocol_evidence.py
PROTOCOL_URL ?=
PROTOCOL_PROFILE ?= http1
PROTOCOL_ARTIFACT_DIR ?= $(BUILD_ROOT)/protocol-client/$(PROTOCOL_PROFILE)
PROTOCOL_STRICT ?= 0
PROTOCOL_CONNECTOR ?=
PROTOCOL_INTEGRATION_MODE ?=
PROTOCOL_RUN_ID ?=
PROTOCOL_TRANSACTION_ID ?=
PROTOCOL_TRANSPORT_CASE_ID ?=
PROTOCOL_RULE_ID ?=
PROTOCOL_PHASE ?=
PROTOCOL_FOLLOWUP_URL ?=
PROTOCOL_INSECURE ?= 0
PROTOCOL_CACERT ?=
PROTOCOL_STREAM_ID ?=
PROTOCOL_UPSTREAM_PROTOCOL ?=
PROTOCOL_QUIC_UDP_OBSERVED ?= 0
PROTOCOL_OBSERVATION_SIDECAR ?=
NO_CRS_RUN_ID ?= local
CONNECTOR ?=
CAPABILITIES_FILE ?= $(CONNECTOR_ROOT)/connectors/$(CONNECTOR)/capabilities.json
EVIDENCE_ROOT ?= $(BUILD_ROOT)/no-crs-evidence
NO_CRS_RUN_DIR ?= $(EVIDENCE_ROOT)/$(CONNECTOR)/$(NO_CRS_RUN_ID)
PLAN_FILE ?= $(BUILD_ROOT)/no-crs-plans/$(CONNECTOR)/$(NO_CRS_RUN_ID).json
NO_CRS_STAGE_RC ?= 0
NO_CRS_STAGE_REASON ?=
NO_CRS_FINALIZE_ARGS ?=
# A managed, payload-free protocol-client bundle can be promoted only through
# the full-lifecycle finalizer, which copies and binds it to protocol cases.
NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR ?=
NO_CRS_ARTIFACT_PROFILE ?= generic
EVIDENCE_STAGE ?= no_crs_baseline
NO_CRS_SUMMARY_ROOT ?= $(EVIDENCE_ROOT)/summary/$(NO_CRS_RUN_ID)

export BUILD_ROOT
export SOURCE_ROOT
export TMP_ROOT
export LOG_ROOT
export FRAMEWORK_ROOT
export CI_ROOT
export CONNECTOR_ROOT
export OUTPUT_ROOT
export PYTHON
export PYTHONDONTWRITEBYTECODE
export PYTHONPYCACHEPREFIX
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
# Finalizer inputs cross the Make-to-Python boundary through the environment.
# ci/tools/run-no-crs-finalize.py turns them into an argv vector without
# reinterpreting any caller-controlled value as shell syntax.
export NO_CRS_TOOL
export CONNECTOR
export NO_CRS_RUN_DIR
export CAPABILITIES_FILE
export NO_CRS_STAGE_RC
export NO_CRS_STAGE_REASON
export NO_CRS_FINALIZE_ARGS
export NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR

.PHONY: lint quick-check codex-check setup-dev install-dev-deps check-security-data-flow-cases check-security-data-flow-normalizers check-python-version check-github-actions-workflows check-github-actions-pins check-github-actions-permissions test-workflow-security-contract check-doc-links check-bilingual-docs check-variable-documentation check-repository-path-references check-change-records check-documentation generate-test-matrix refresh-framework-reports check-test-matrix runtime-matrix runtime-matrix-all runtime-matrix-haproxy runtime-matrix-haproxy-all smoke-apache smoke-nginx smoke-haproxy smoke-all test test-no-crs test-with-crs fetch-deps fetch-modsecurity-v3 fetch-crs prepare-crs prepare-haproxy-runtime mrts-generate mrts-load mrts-import test-no-mrts test-with-mrts test-with-mrts-feature-demo test-mrts-matrix mrts-ftw check-no-crs-catalog test-makefile-contract test-ci-security-contract test-change-record-contract test-crs-provenance-contract test-workflow-action-pins test-workflow-contract test-no-crs-contract no-crs-plan no-crs-init no-crs-finalize no-crs-summary check-no-crs-evidence check-no-crs-result-schema check-no-crs-evidence-completeness check-no-crs-capability-consistency check-no-crs-claim-policy check-no-crs-artifact-layout check-no-crs-body-payload-absence check-no-crs-status-consistency check-no-crs-protocol-client check-no-crs-doc-consistency check-first-byte-before-response-end check-no-full-response-buffering check-full-lifecycle-event-privacy check-full-lifecycle-promotion check-transport-hardening-evidence protocol-client check-protocol-evidence test-protocol-client
.PHONY: test-modsecurity-v3-provenance-contract test-nginx-archive-digest

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
	sh ci/tools/bootstrap-python.sh

lint:
	sh -n $(CI_SHELL_FILES)
	if command -v bash >/dev/null 2>&1; then bash -n $(CI_SHELL_FILES); else echo "bash unavailable"; fi
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m py_compile tests/normalizers/*.py tests/runners/*.py $(CI_PYTHON_FILES)
	$(MAKE) test-makefile-contract
	$(MAKE) test-ci-security-contract
	$(MAKE) test-change-record-contract
	$(MAKE) test-crs-provenance-contract
	$(MAKE) test-modsecurity-v3-provenance-contract
	$(MAKE) test-nginx-archive-digest
	$(MAKE) test-workflow-action-pins
	$(MAKE) test-workflow-contract
	$(PYTHON) ci/tools/check-python-deps.py
	$(PYTHON) ci/checks/documentation/check-workflow-yaml.py
	$(MAKE) check-python-version
	$(MAKE) check-github-actions-workflows
	$(MAKE) test-workflow-security-contract
	$(PYTHON) ci/checks/security/check-workflow-action-pins.py
	$(PYTHON) ci/checks/evidence/check-response-body-promotion.py --framework-root "$(FRAMEWORK_ROOT)" --connector-root "$(CONNECTOR_ROOT)" --output-root "$(OUTPUT_ROOT)"
	$(PYTHON) ci/checks/security/check-security-data-flow-cases.py
	$(PYTHON) ci/checks/security/check-security-data-flow-normalizers.py
	$(PYTHON) ci/checks/catalog/no_crs_baseline.py catalog-check
	sh ci/checks/catalog/check-crs-version-pinning.sh
	sh ci/checks/catalog/check-open-runtime-provisioning-contract.sh
	$(MAKE) check-documentation
	git diff --check

check-security-data-flow-cases:
	$(PYTHON) ci/checks/security/check-security-data-flow-cases.py

check-security-data-flow-normalizers:
	$(PYTHON) ci/checks/security/check-security-data-flow-normalizers.py

check-python-version:
	$(PYTHON) "$(PYTHON_VERSION_CONTRACT_TOOL)"

check-github-actions-workflows: check-python-version check-github-actions-pins check-github-actions-permissions

check-github-actions-pins:
	$(PYTHON) "$(WORKFLOW_SECURITY_TOOL)" --check pins

check-github-actions-permissions:
	$(PYTHON) "$(WORKFLOW_SECURITY_TOOL)" --check permissions

test-workflow-security-contract:
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m unittest discover -s tests/security_regression -p 'test_workflow_security_contract.py' -v

check-doc-links:
	$(PYTHON) ci/checks/documentation/check-doc-links.py

check-bilingual-docs:
	$(PYTHON) ci/checks/documentation/check-variable-documentation.py

check-variable-documentation: check-bilingual-docs

check-repository-path-references:
	$(PYTHON) ci/checks/documentation/check-repository-path-references.py

check-change-records:
	$(PYTHON) ci/checks/documentation/check-change-records.py

check-documentation: check-doc-links check-bilingual-docs check-repository-path-references check-change-records

test-makefile-contract:
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m unittest discover -s tests/makefile_contract -v

test-ci-security-contract:
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m unittest discover -s tests/ci_security -v

test-change-record-contract:
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m unittest tests.ci_security.test_change_record_contract -v

test-crs-provenance-contract:
	mkdir -p "$(TMP_ROOT)"
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" TMPDIR="$(TMP_ROOT)" $(PYTHON) -m unittest discover -s tests/security_regression -p 'test_crs_git_ref_provenance.py' -v

test-modsecurity-v3-provenance-contract:
	mkdir -p "$(TMP_ROOT)"
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" TMPDIR="$(TMP_ROOT)" $(PYTHON) -m unittest discover -s tests/security_regression -p 'test_modsecurity_v3_git_ref_provenance.py' -v

test-nginx-archive-digest:
	mkdir -p "$(TMP_ROOT)"
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" TMPDIR="$(TMP_ROOT)" $(PYTHON) -m unittest discover -s tests/security_regression -p 'test_nginx_archive_digest.py' -v

test-workflow-action-pins:
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m unittest discover -s tests/security_regression -p test_workflow_action_pins.py -v

test-no-crs-contract:
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m unittest discover -s tests/no_crs -v

test-workflow-contract:
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m unittest discover -s tests/workflow_contract -v

check-no-crs-catalog:
	$(PYTHON) "$(NO_CRS_TOOL)" catalog-check

no-crs-plan: check-no-crs-catalog
	@test -n "$(CONNECTOR)" || { echo "CONNECTOR is required" >&2; exit 2; }
	$(PYTHON) "$(NO_CRS_TOOL)" select --connector "$(CONNECTOR)" --capabilities "$(CAPABILITIES_FILE)" --evidence-stage "$(EVIDENCE_STAGE)" --artifact-profile "$(NO_CRS_ARTIFACT_PROFILE)" --output "$(PLAN_FILE)"

no-crs-init: no-crs-plan
	$(PYTHON) "$(NO_CRS_TOOL)" init --connector "$(CONNECTOR)" --capabilities "$(CAPABILITIES_FILE)" --evidence-stage "$(EVIDENCE_STAGE)" --artifact-profile "$(NO_CRS_ARTIFACT_PROFILE)" --plan "$(PLAN_FILE)" --run-dir "$(NO_CRS_RUN_DIR)" --run-id "$(NO_CRS_RUN_ID)" --connector-root "$(CONNECTOR_ROOT)" --executed-target "$(EVIDENCE_STAGE)-$(CONNECTOR)"

no-crs-finalize:
	$(PYTHON) "$(dir $(abspath $(lastword $(MAKEFILE_LIST))))ci/tools/run-no-crs-finalize.py"

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

check-no-crs-protocol-client:
	$(call RUN_NO_CRS_CHECK,protocol-client)

check-no-crs-status-consistency:
	$(call RUN_NO_CRS_CHECK,status)

check-no-crs-evidence:
	$(call RUN_NO_CRS_CHECK,all)

define RUN_FULL_LIFECYCLE_EVIDENCE_CHECK
	@test -n "$(CONNECTOR)" || { echo "CONNECTOR is required" >&2; exit 2; }
	$(PYTHON) "$(FULL_LIFECYCLE_EVIDENCE_TOOL)" --run-dir "$(NO_CRS_RUN_DIR)" --check "$(1)"
endef

check-first-byte-before-response-end:
	$(call RUN_FULL_LIFECYCLE_EVIDENCE_CHECK,first-byte)

check-no-full-response-buffering:
	$(call RUN_FULL_LIFECYCLE_EVIDENCE_CHECK,no-full-response-buffering)

check-full-lifecycle-event-privacy:
	$(call RUN_FULL_LIFECYCLE_EVIDENCE_CHECK,event-privacy)

check-full-lifecycle-promotion:
	$(call RUN_FULL_LIFECYCLE_EVIDENCE_CHECK,promotion)

check-transport-hardening-evidence:
	@test -n "$(CONNECTOR)" || { echo "CONNECTOR is required" >&2; exit 2; }
	$(PYTHON) "$(TRANSPORT_HARDENING_EVIDENCE_TOOL)" --run-dir "$(NO_CRS_RUN_DIR)" --check all

# The managed client is intentionally opt-in: callers name an explicit target
# and profile, and the emitted artifacts are suitable for a later canonical
# case/event correlation.  H3 uses only --http3-only inside the helper.
protocol-client:
	@test -n "$(PROTOCOL_URL)" || { echo "PROTOCOL_URL is required" >&2; exit 2; }
	@case "$(PROTOCOL_STRICT)" in 1|true|yes) test -n "$(PROTOCOL_FOLLOWUP_URL)" || { echo "PROTOCOL_FOLLOWUP_URL is required for strict evidence" >&2; exit 2; } ;; esac
	@set +e; \
	"$(PYTHON)" "$(PROTOCOL_CLIENT_TOOL)" --url "$(PROTOCOL_URL)" --protocol "$(PROTOCOL_PROFILE)" --artifact-dir "$(PROTOCOL_ARTIFACT_DIR)" $(if $(filter 1 true yes,$(PROTOCOL_STRICT)),--followup-url "$(PROTOCOL_FOLLOWUP_URL)",) $(if $(filter 1 true yes,$(PROTOCOL_INSECURE)),--insecure,) $(if $(PROTOCOL_CACERT),--cacert "$(PROTOCOL_CACERT)",) $(if $(PROTOCOL_CONNECTOR),--connector "$(PROTOCOL_CONNECTOR)",) $(if $(PROTOCOL_INTEGRATION_MODE),--integration-mode "$(PROTOCOL_INTEGRATION_MODE)",) $(if $(PROTOCOL_RUN_ID),--run-id "$(PROTOCOL_RUN_ID)",) $(if $(PROTOCOL_TRANSACTION_ID),--transaction-id "$(PROTOCOL_TRANSACTION_ID)",) $(if $(PROTOCOL_TRANSPORT_CASE_ID),--transport-case-id "$(PROTOCOL_TRANSPORT_CASE_ID)",) $(if $(PROTOCOL_RULE_ID),--rule-id "$(PROTOCOL_RULE_ID)",) $(if $(PROTOCOL_PHASE),--phase "$(PROTOCOL_PHASE)",) $(if $(PROTOCOL_STREAM_ID),--stream-id "$(PROTOCOL_STREAM_ID)",) $(if $(PROTOCOL_UPSTREAM_PROTOCOL),--upstream-protocol "$(PROTOCOL_UPSTREAM_PROTOCOL)",) $(if $(filter 1 true yes,$(PROTOCOL_QUIC_UDP_OBSERVED)),--quic-udp-observed,) $(if $(PROTOCOL_OBSERVATION_SIDECAR),--observation-sidecar "$(PROTOCOL_OBSERVATION_SIDECAR)",); \
	client_rc=$$?; \
	case "$(PROTOCOL_STRICT)" in \
		1|true|yes) "$(PYTHON)" "$(PROTOCOL_EVIDENCE_TOOL)" --artifact-dir "$(PROTOCOL_ARTIFACT_DIR)" --protocol "$(PROTOCOL_PROFILE)" --strict $(if $(PROTOCOL_CONNECTOR),--connector "$(PROTOCOL_CONNECTOR)",) $(if $(PROTOCOL_INTEGRATION_MODE),--integration-mode "$(PROTOCOL_INTEGRATION_MODE)",) $(if $(PROTOCOL_RUN_ID),--run-id "$(PROTOCOL_RUN_ID)",) $(if $(PROTOCOL_TRANSACTION_ID),--transaction-id "$(PROTOCOL_TRANSACTION_ID)",) $(if $(PROTOCOL_TRANSPORT_CASE_ID),--expected-transport-case-id "$(PROTOCOL_TRANSPORT_CASE_ID)",) $(if $(PROTOCOL_RULE_ID),--rule-id "$(PROTOCOL_RULE_ID)",) $(if $(PROTOCOL_PHASE),--phase "$(PROTOCOL_PHASE)",) $(if $(PROTOCOL_STREAM_ID),--expected-stream-id "$(PROTOCOL_STREAM_ID)",) $(if $(PROTOCOL_UPSTREAM_PROTOCOL),--expected-upstream-protocol "$(PROTOCOL_UPSTREAM_PROTOCOL)",); exit $$? ;; \
		*) exit $$client_rc ;; \
	esac

check-protocol-evidence:
	@test -d "$(PROTOCOL_ARTIFACT_DIR)" || { echo "PROTOCOL_ARTIFACT_DIR is required" >&2; exit 2; }
	$(PYTHON) "$(PROTOCOL_EVIDENCE_TOOL)" --artifact-dir "$(PROTOCOL_ARTIFACT_DIR)" --protocol "$(PROTOCOL_PROFILE)" $(if $(filter 1 true yes,$(PROTOCOL_STRICT)),--strict,) $(if $(PROTOCOL_CONNECTOR),--connector "$(PROTOCOL_CONNECTOR)",) $(if $(PROTOCOL_INTEGRATION_MODE),--integration-mode "$(PROTOCOL_INTEGRATION_MODE)",) $(if $(PROTOCOL_RUN_ID),--run-id "$(PROTOCOL_RUN_ID)",) $(if $(PROTOCOL_TRANSACTION_ID),--transaction-id "$(PROTOCOL_TRANSACTION_ID)",) $(if $(PROTOCOL_TRANSPORT_CASE_ID),--expected-transport-case-id "$(PROTOCOL_TRANSPORT_CASE_ID)",) $(if $(PROTOCOL_RULE_ID),--rule-id "$(PROTOCOL_RULE_ID)",) $(if $(PROTOCOL_PHASE),--phase "$(PROTOCOL_PHASE)",) $(if $(PROTOCOL_STREAM_ID),--expected-stream-id "$(PROTOCOL_STREAM_ID)",) $(if $(PROTOCOL_UPSTREAM_PROTOCOL),--expected-upstream-protocol "$(PROTOCOL_UPSTREAM_PROTOCOL)",)

test-protocol-client:
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m unittest discover -s tests/protocol_client -v

# Repository-owned bilingual reports are checked at the root.  Framework-side
# document consistency starts by validating the one canonical source catalog.
check-no-crs-doc-consistency: check-no-crs-catalog

quick-check codex-check: lint
	PYTHONPYCACHEPREFIX="$(BUILD_ROOT)/pycache" $(PYTHON) -m py_compile tests/normalizers/*.py tests/runners/*.py $(CI_PYTHON_FILES)
	$(PYTHON) ci/checks/catalog/check-mrts-importer.py
	git diff --check

generate-test-matrix:
	sh -eu -c '. ci/lib/common.sh; . ci/lib/mrts-common.sh; validate_mrts_variant; prepare_mrts_variant; if [ "$$MODSECURITY_MRTS_VARIANT" = "with-mrts" ]; then mrts_import_cases; fi; "$(PYTHON)" ci/reporting/generate-case-matrix.py --framework-root "$(FRAMEWORK_ROOT)" --connector-root "$(CONNECTOR_ROOT)" --output-root "$(OUTPUT_ROOT)" $(if $(SKIP_ROOT_SUMMARY),--skip-root-summary,)'

refresh-framework-reports:
	MODSECURITY_MRTS_VARIANT=with-mrts $(MAKE) generate-test-matrix CONNECTOR_ROOT="$(FRAMEWORK_ROOT)" OUTPUT_ROOT="$(FRAMEWORK_ROOT)"

check-test-matrix: refresh-framework-reports
	@framework_root=$$(CDPATH= cd "$(FRAMEWORK_ROOT)" && pwd -P) || { \
		echo "FRAMEWORK_ROOT cannot be resolved: $(FRAMEWORK_ROOT)"; \
		exit 2; \
	}; \
	output_root=$$(CDPATH= cd "$(OUTPUT_ROOT)" && pwd -P) || { \
		echo "OUTPUT_ROOT cannot be resolved: $(OUTPUT_ROOT)"; \
		exit 2; \
	}; \
	[ "$$output_root" = "$$framework_root" ] || { \
		echo "OUTPUT_ROOT must resolve to FRAMEWORK_ROOT for canonical generated-report freshness checks"; \
		exit 2; \
	}; \
	git -C "$$framework_root" diff --exit-code -- reports/testing docs/testing >/dev/null || { \
		echo "Generated test matrix docs are out of date for FRAMEWORK_ROOT=$(FRAMEWORK_ROOT)"; \
		exit 1; \
	}
	@git -C "$(FRAMEWORK_ROOT)" diff --exit-code -- TEST-COVERAGE-SUMMARY.md >/dev/null || { \
		echo "Framework coverage summary is out of date. Run make generate-test-matrix"; \
		exit 1; \
	}

runtime-matrix:
	sh ci/runtime/run-runtime-matrix.sh

runtime-matrix-all:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,FORCE_ALL_CASES=1 sh ci/runtime/run-runtime-matrix.sh)

runtime-matrix-haproxy:
	sh ci/runtime/run-haproxy-runtime-matrix.sh

runtime-matrix-haproxy-all:
	FORCE_ALL_CASES=1 sh ci/runtime/run-haproxy-runtime-matrix.sh

smoke-apache:
	CASE_SCOPE=all sh ci/runtime/run-apache-smoke.sh

smoke-nginx:
	CASE_SCOPE=all sh ci/runtime/run-nginx-smoke.sh

smoke-haproxy:
	CASE_SCOPE=all sh ci/runtime/run-haproxy-smoke.sh

smoke-all:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,CASE_SCOPE=all sh ci/runtime/run-connector-smokes.sh)

test: test-no-crs test-with-crs

test-no-crs:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,MODSECURITY_TEST_VARIANT=no-crs MODSECURITY_RULE_PREAMBLE_FILE= sh -eu -c '. ci/lib/common.sh; RESULTS_DIR="$$BUILD_ROOT/results/no-crs"; export RESULTS_DIR; CASE_SCOPE=all sh ci/runtime/run-connector-smokes.sh')

test-with-crs:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,MODSECURITY_TEST_VARIANT=with-crs sh -eu -c '. ci/lib/common.sh; sh ci/provisioning/fetch-crs.sh; sh ci/provisioning/prepare-crs.sh; MODSECURITY_RULE_PREAMBLE_FILE="$$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf"; RESULTS_DIR="$$BUILD_ROOT/results/with-crs"; export MODSECURITY_RULE_PREAMBLE_FILE RESULTS_DIR; CASE_SCOPE=all sh ci/runtime/run-connector-smokes.sh')

mrts-generate:
	sh -eu -c '. ci/lib/common.sh; . ci/lib/mrts-common.sh; mrts_generate_all_corpora'

mrts-load:
	sh ci/provisioning/write-mrts-load.sh

mrts-import:
	sh -eu -c '. ci/lib/common.sh; . ci/lib/mrts-common.sh; mrts_generate_all_corpora; MRTS_RULES_OUT="$$MRTS_UPSTREAM_RULES_OUT" sh ci/provisioning/write-mrts-load.sh >/dev/null; mrts_import_cases'

test-no-mrts:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,MODSECURITY_MRTS_VARIANT=no-mrts sh -eu -c '. ci/lib/common.sh; . ci/lib/mrts-common.sh; validate_mrts_variant; prepare_mrts_variant; set_mrts_results_dir; CASE_SCOPE=all sh ci/runtime/run-connector-smokes.sh')

test-with-mrts:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,MODSECURITY_MRTS_VARIANT=with-mrts sh -eu -c '. ci/lib/common.sh; . ci/lib/mrts-common.sh; validate_mrts_variant; prepare_mrts_runtime_variant; set_mrts_results_dir; CASE_SCOPE=all sh ci/runtime/run-connector-smokes.sh')

test-with-mrts-feature-demo:
	$(call RUN_WITH_FRAMEWORK_REPORT_REFRESH,MODSECURITY_MRTS_VARIANT=with-mrts MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1 sh -eu -c '. ci/lib/common.sh; . ci/lib/mrts-common.sh; validate_mrts_variant; prepare_mrts_runtime_variant; set_mrts_results_dir; CASE_SCOPE=all sh ci/runtime/run-connector-smokes.sh')

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
	sh ci/provisioning/fetch-smoke-sources.sh v3

fetch-deps:
	sh ci/provisioning/fetch-smoke-sources.sh all

fetch-crs:
	sh ci/provisioning/fetch-crs.sh

prepare-crs:
	sh ci/provisioning/prepare-crs.sh

prepare-haproxy-runtime:
	sh ci/provisioning/prepare-haproxy-runtime.sh
