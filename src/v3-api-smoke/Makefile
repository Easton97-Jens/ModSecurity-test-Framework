MODSECURITY_V3_DIR ?= /src/ModSecurity_V3_build
BUILD_ROOT ?= /src/ModSecurity-test-Framework-build
BUILD_DIR ?= $(BUILD_ROOT)/v3-api-smoke
CC ?= cc
CXX ?= c++

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
REPO_ROOT := $(abspath $(CURDIR)/../..)
BUILD_DIR_ABS := $(abspath $(BUILD_DIR))

.PHONY: all run check-prereqs clean
.NOTPARALLEL:

all: $(BIN)

check-prereqs:
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

$(OBJ): $(SRC) | $(BUILD_DIR)
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
