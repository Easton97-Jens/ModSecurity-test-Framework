"""On-demand self-tests for the product compiler profile detector."""
import os
import sys

from modsecurity_test_framework.connector_context import load_source, source_path

DETECTOR = load_source(source_path("ci/provisioning/toolchains/detect-c-standard.py"))
validate_standard_flag = DETECTOR.validate_standard_flag
validate_compiler_id = DETECTOR.validate_compiler_id
resolve_compiler_id = DETECTOR.resolve_compiler_id
CompilerValidationError = DETECTOR.CompilerValidationError
STD_C17 = DETECTOR.STD_C17
STD_C2X = DETECTOR.STD_C2X
COMPILER_GCC = DETECTOR.COMPILER_GCC
COMPILER_CLANG = DETECTOR.COMPILER_CLANG
COMPILER_CC = DETECTOR.COMPILER_CC


def run_self_test() -> int:
    validate_standard_flag(STD_C17)
    validate_standard_flag(STD_C2X)
    validate_compiler_id(COMPILER_GCC)
    validate_compiler_id(COMPILER_CLANG)
    validate_compiler_id("gcc-13")
    validate_compiler_id("clang-18")

    for rejected_flag in ("-std=c20", "-std=c26"):
        try:
            validate_standard_flag(rejected_flag)
        except ValueError:
            pass
        else:
            print(f"self-test failed: accepted {rejected_flag}", file=sys.stderr)
            return 1

    for rejected_compiler in (
        "sh",
        "bash",
        "cc;rm -rf /",
        "cc -bad",
        "clang -bad",
        "/bin/sh",
        "/usr/bin/clang",
        "python3",
        "../cc",
        "",
    ):
        try:
            validate_compiler_id(rejected_compiler)
        except CompilerValidationError:
            pass
        else:
            print(f"self-test failed: accepted compiler {rejected_compiler!r}", file=sys.stderr)
            return 1

    try:
        resolve_compiler_id(COMPILER_CC)
    except CompilerValidationError as exc:
        print(f"self-test notice: cc unavailable: {exc}", file=sys.stderr)

    print("detect-c-standard self-test: pass")
    return 0



if __name__ == "__main__":
    if os.environ.get("ON_DEMAND_TESTS") != "1":
        raise SystemExit("explicit ON_DEMAND_TESTS=1 is required")
    raise SystemExit(run_self_test())
