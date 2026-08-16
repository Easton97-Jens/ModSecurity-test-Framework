MODSECURITY_V3_DIR ?= /src/ModSecurity_V3_build
BUILD_ROOT ?= /src/ModSecurity-test-Framework-build
BUILD_DIR ?= $(BUILD_ROOT)/v3-api-smoke
CC ?= cc
CXX ?= c++

# Command-line/environment values are untrusted. GNU Make expands $(shell ...)
# before recipe-level validation, so inspect their raw form and reject Make
# variable syntax before any derived variable can expand it.
v3_open_paren := (
v3_close_paren := )
v3_double_quote := "
v3_backslash := \\
v3_unsafe_chars := $$ ` ' $(v3_double_quote) ; & | < > $(v3_open_paren) $(v3_close_paren) $(v3_backslash)
define v3_first_unsafe_char
$(foreach ch,$(v3_unsafe_chars),$(if $(findstring $(ch),$(value $(1))),$(ch)))
endef
$(foreach v,MODSECURITY_V3_DIR BUILD_ROOT BUILD_DIR CC CXX,$(if $(filter-out file default,$(origin $(v))),$(if $(strip $(call v3_first_unsafe_char,$(v))),$(error $(v) contains unsupported shell syntax))))

ifeq ($(origin CC),default)
CC := cc
endif

ifeq ($(origin CXX),default)
CXX := c++
endif

SRC := v3_api_smoke.c
OBJ := $(BUILD_DIR)/v3_api_smoke.o
BIN := $(BUILD_DIR)/v3_api_smoke
HEADER := $(MODSECURITY_V3_DIR)/headers/modsecurity/modsecurity.h
LIB := $(MODSECURITY_V3_DIR)/src/.libs/libmodsecurity.so
# These are derived trust-boundary values, not caller configuration.  The
# override assignment also defeats command-line variables before recipes can
# use them to weaken the checkout-containment check.
override REPO_ROOT := $(abspath $(CURDIR)/../..)
override BUILD_DIR_ABS := $(abspath $(BUILD_DIR))

.PHONY: all run check-prereqs clean
.NOTPARALLEL:

all: $(BIN)

check-prereqs:
	@realpath_tool=/usr/bin/realpath; \
	if [ ! -x "$$realpath_tool" ]; then realpath_tool=/bin/realpath; fi; \
	if [ ! -x "$$realpath_tool" ]; then echo "v3_api_smoke: blocked missing trusted realpath" >&2; exit 77; fi; \
	repo_real=$$($$realpath_tool -m -- "$(REPO_ROOT)") || { echo "v3_api_smoke: blocked repository path resolution" >&2; exit 77; }; \
	build_root_real=$$($$realpath_tool -m -- "$(BUILD_ROOT)") || { echo "v3_api_smoke: blocked BUILD_ROOT path resolution" >&2; exit 77; }; \
	build_dir_real=$$($$realpath_tool -m -- "$(BUILD_DIR)") || { echo "v3_api_smoke: blocked BUILD_DIR path resolution" >&2; exit 77; }; \
	modsecurity_real=$$($$realpath_tool -m -- "$(MODSECURITY_V3_DIR)") || { echo "v3_api_smoke: blocked ModSecurity path resolution" >&2; exit 77; }; \
	case "$$build_root_real" in "$$repo_real"|"$$repo_real"/*) echo "v3_api_smoke: blocked resolved BUILD_ROOT is inside the checkout: $$build_root_real" >&2; exit 77;; esac; \
	case "$$build_dir_real" in "$$repo_real"|"$$repo_real"/*) echo "v3_api_smoke: blocked resolved BUILD_DIR is inside the checkout: $$build_dir_real" >&2; exit 77;; esac; \
	case "$$modsecurity_real" in "$$repo_real"|"$$repo_real"/*) echo "v3_api_smoke: blocked resolved ModSecurity path is inside the checkout: $$modsecurity_real" >&2; exit 77;; esac
	@case "$(CC)" in \
		''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./+-]*) \
			echo "v3_api_smoke: blocked CC contains shell metacharacters: $(CC)" >&2; exit 77 ;; \
		esac
	@command -v -- "$(CC)" >/dev/null 2>&1 || { echo "v3_api_smoke: blocked CC is not executable: $(CC)" >&2; exit 77; }
	@case "$(CXX)" in \
		''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./+-]*) \
			echo "v3_api_smoke: blocked CXX contains shell metacharacters: $(CXX)" >&2; exit 77 ;; \
		esac
	@command -v -- "$(CXX)" >/dev/null 2>&1 || { echo "v3_api_smoke: blocked CXX is not executable: $(CXX)" >&2; exit 77; }
	@case "$(BUILD_DIR)" in \
		/*) ;; \
		*) echo "v3_api_smoke: blocked BUILD_DIR must be absolute and outside the checkout: $(BUILD_DIR)" >&2; exit 77 ;; \
	esac
	@case "$(BUILD_DIR_ABS)" in \
		"$(REPO_ROOT)"|"$(REPO_ROOT)"/*) \
			echo "v3_api_smoke: blocked BUILD_DIR is inside the checkout: $(BUILD_DIR_ABS)" >&2; \
			exit 77 ;; \
	esac
	@if [ ! -f "$(HEADER)" ]; then \
		echo "v3_api_smoke: blocked missing header: $(HEADER)" >&2; \
		exit 77; \
	fi
	@if [ ! -f "$(LIB)" ]; then \
		echo "v3_api_smoke: blocked missing library: $(LIB)" >&2; \
		echo "v3_api_smoke: not building ModSecurity_V3 from this Makefile" >&2; \
		exit 77; \
	fi

$(BUILD_DIR):
	mkdir -p "$(BUILD_DIR)"

$(OBJ): check-prereqs $(SRC) | $(BUILD_DIR)
	$(CC) -std=c99 -Wall -Wextra -Werror \
		-I"$(MODSECURITY_V3_DIR)/headers" \
		-c "$(SRC)" \
		-o "$(OBJ)"

$(BIN): check-prereqs $(OBJ)
	$(CXX) "$(OBJ)" \
		-L"$(MODSECURITY_V3_DIR)/src/.libs" \
		-Wl,-rpath,"$(MODSECURITY_V3_DIR)/src/.libs" \
		-lmodsecurity \
		-o "$(BIN)"

run: $(BIN)
	"$(BIN)"

clean:
	rm -rf "$(BUILD_DIR)"
