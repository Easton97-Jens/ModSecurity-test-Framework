#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
set -eu
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
BUILD_ROOT="${BUILD_ROOT:-${TMPDIR:-/var/tmp}/ModSecurity-conector-verified/build}"
case "$BUILD_ROOT" in
    /*)
        ;;
    *)
        echo "BLOCKED: memory_safety BUILD_ROOT must be absolute"
        exit 77
        ;;
esac
case "$(CDPATH= cd "$BUILD_ROOT" 2>/dev/null && pwd 2>/dev/null || printf '%s' "$BUILD_ROOT")" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        echo "BLOCKED: memory_safety BUILD_ROOT inside checkout"
        exit 77
        ;;
    *)
        ;;
esac
CC_BIN="${CC:-cc}"
command -v "$CC_BIN" >/dev/null 2>&1 || { echo "BLOCKED: memory_safety missing compiler: $CC_BIN"; exit 77; }
OUT="$BUILD_ROOT/common-memory-safety"; mkdir -p "$OUT"
cat > "$OUT/smoke.c" <<'C'
#include "msconnector/memory.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

typedef struct wipe_observation {
    size_t size;
    int all_zero;
} wipe_observation;

static void inspect_wiped_allocation(void *ptr, void *userdata)
{
    wipe_observation *observation = userdata;
    const unsigned char *bytes = ptr;
    size_t index;

    observation->all_zero = 1;
    for (index = 0U; index < observation->size; ++index) {
        if (bytes[index] != 0U) {
            observation->all_zero = 0;
        }
    }
    free(ptr);
}

int main(void)
{
    msconnector_allocator allocator;
    wipe_observation observation = {4U, 0};
    void *pointer = 0;
    void *too_large = 0;
    unsigned char *bytes;

    msconnector_allocator_init(&allocator, 8U);
    assert(msconnector_alloc_checked(&allocator, 4U, &pointer));
    assert(pointer != 0);
    assert(allocator.bytes_allocated == 4U);
    bytes = pointer;
    bytes[0] = 0xA5U;
    bytes[1] = 0x5AU;
    bytes[2] = 0xFFU;
    bytes[3] = 0x01U;
    allocator.free = inspect_wiped_allocation;
    allocator.userdata = &observation;
    msconnector_secure_zero(pointer, observation.size);
    assert(!msconnector_alloc_checked(&allocator, 9U, &too_large));
    assert(too_large == 0);
    msconnector_free_checked(&allocator, &pointer, observation.size);
    assert(observation.all_zero);
    assert(pointer == 0);
    assert(allocator.bytes_allocated == 0U);
    msconnector_secure_zero(0, 0U);
    msconnector_free_checked(&allocator, &pointer, observation.size);
    assert(pointer == 0);
    assert(allocator.bytes_allocated == 0U);
    assert(msconnector_allocator_within_limit(&allocator));
    return 0;
}
C
FLAGS="${MSCONNECTOR_CFLAGS:--std=c17 -Wall -Wextra -Werror}"
"$CC_BIN" $FLAGS -I"$REPO_ROOT/common/include" "$OUT/smoke.c" "$REPO_ROOT/common/src/memory.c" -o "$OUT/smoke"
"$OUT/smoke"
if "$CC_BIN" $FLAGS -fsanitize=address,undefined -I"$REPO_ROOT/common/include" "$OUT/smoke.c" "$REPO_ROOT/common/src/memory.c" -o "$OUT/smoke-asan" >/dev/null 2>&1; then
    "$OUT/smoke-asan"
else
    echo "SKIPPED: optional sanitizer build unavailable; base memory_safety smoke passed"
fi
