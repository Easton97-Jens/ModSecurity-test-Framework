#!/usr/bin/env python3
"""Compile native Framework sources and record successful real compiler commands."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


def record_compile(fragment: Path, compiler: str, arguments: list[str]) -> None:
    """Write evidence only after the actual unmodified compiler argv succeeds."""
    if fragment.is_symlink():
        raise ValueError("refusing symlinked compiler evidence")
    fragment.unlink(missing_ok=True)
    subprocess.run([compiler, *arguments], check=True)
    if arguments.count("-c") != 1:
        raise ValueError("expected one compile-only source argument")
    source = arguments[arguments.index("-c") + 1]
    record = {"directory": str(Path.cwd()), "file": source,
              "arguments": [compiler, *arguments]}
    fragment.write_text(json.dumps(record) + "\n", encoding="utf-8")


def prepare(root: Path, output: Path, sdk: Path, compiler_name: str) -> Path:
    if output.is_symlink():
        raise ValueError("refusing symlinked analysis output")
    root, output, sdk = root.resolve(), output.resolve(), sdk.resolve()
    if output == root or root in output.parents:
        raise ValueError("analysis output must be outside the checkout")
    compiler = shutil.which(compiler_name)
    if compiler is None:
        raise ValueError("a real native C compiler is required")
    header = sdk / "include/modsecurity/modsecurity.h"
    library_dir = sdk / "lib"
    if not (library_dir / "libmodsecurity.so").is_file():
        library_dir = sdk / "lib/x86_64-linux-gnu"
    library = library_dir / "libmodsecurity.so"
    if not header.is_file() or not library.is_file():
        raise ValueError("ModSecurity SDK requires include/modsecurity and lib/libmodsecurity.so")
    # Keep the native Makefile's prerequisite and flag contracts unchanged.
    # Reuse its historical SDK layout through task-owned external symlinks.
    output.mkdir(parents=True, exist_ok=True)
    # The caller owns this private directory (runner.temp in CI). Reject
    # preseeded symlinks before writing or asking a compiler to write outputs.
    output.chmod(0o700)
    for filename in ("compile_commands.json", "compilation-evidence.json",
                     "compiler-command.json", "capture-compiler", "v3_api_smoke.o"):
        if (output / filename).is_symlink():
            raise ValueError("refusing symlinked analysis output file")
    for stale in ("compile_commands.json", "compilation-evidence.json"):
        (output / stale).unlink(missing_ok=True)
    stage = output / "sdk"
    if stage.is_symlink() or (stage / "src").is_symlink():
        raise ValueError("refusing symlinked SDK staging directory")
    (stage / "src").mkdir(parents=True, exist_ok=True)
    for destination, source in ((stage / "headers", sdk / "include"),
                                (stage / "src/.libs", library_dir)):
        if destination.is_symlink() and destination.resolve() == source.resolve():
            continue
        if destination.exists() or destination.is_symlink():
            raise ValueError(f"refusing to replace existing SDK path: {destination}")
        destination.symlink_to(source, target_is_directory=True)
    fragment = output / "compiler-command.json"
    wrapper = output / "capture-compiler"
    invocation = [sys.executable, str(Path(__file__).resolve()), "--record-compile",
                  str(fragment), compiler]
    wrapper.write_text("#!/bin/sh\nexec " + shlex.join(invocation)
                       + ' "$@"\n', encoding="utf-8")
    wrapper.chmod(0o700)
    native = root / "src/v3-api-smoke"
    obj = output / "v3_api_smoke.o"
    # Always compile, even on a repeated invocation. This is compile-only:
    # neither the smoke executable nor connector/runtime checks are run.
    subprocess.run(["make", "--always-make", "-C", str(native), str(obj),
                    f"MODSECURITY_V3_DIR={stage}", f"BUILD_ROOT={output}",
                    f"BUILD_DIR={output}", f"CC={wrapper}"], check=True)
    record = json.loads(fragment.read_text(encoding="utf-8"))
    tracked = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "-z"], text=True
    ).split("\0")
    units = {root / name for name in tracked
             if Path(name).suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}}
    captured = (Path(record["directory"]) / record["file"]).resolve()
    if units != {captured}:
        raise ValueError("native source inventory does not match actual compilation; update native build capture")
    if not obj.is_file() or obj.stat().st_size == 0:
        raise ValueError("native compilation did not produce an object")
    database = output / "compile_commands.json"
    database.write_text(json.dumps([record], indent=2) + "\n", encoding="utf-8")
    evidence = {"source": str(captured.relative_to(root)),
                "source_sha256": hashlib.sha256(captured.read_bytes()).hexdigest(),
                "compiler": compiler, "sdk": str(sdk), "compiled_units": len(units)}
    (output / "compilation-evidence.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"Validated {len(units)} compiled native unit: {database}")
    return database


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--record-compile":
        record_compile(Path(sys.argv[2]), sys.argv[3], sys.argv[4:])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--compiler", default="gcc")
    args = parser.parse_args()
    prepare(Path(__file__).resolve().parents[3], args.output, args.sdk, args.compiler)


if __name__ == "__main__":
    main()
