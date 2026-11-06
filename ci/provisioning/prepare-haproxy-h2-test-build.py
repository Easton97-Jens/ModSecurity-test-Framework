#!/usr/bin/env python3
"""Build the native HTX host plus an explicit test-only lifecycle observer.

The observer records actual request admission and the state after the existing
native detach cleanup. It does not replace cleanup, decisions or host actions.
The production and observed filter hashes are retained separately.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def parent_source_hashes(parent: Path) -> dict[str, str]:
    """Closed native build inputs, including recipes and versioned overlays."""
    result = {}
    for directory in (parent / "common", parent / "connectors/haproxy"):
        for path in sorted(directory.rglob("*")):
            if path.is_file() and (path.suffix in (".c", ".h", ".sh", ".json", ".py", ".patch")
                                   or path.name == "Makefile"):
                if path.is_symlink():
                    raise ValueError("symlink in native product input")
                result[str(path.relative_to(parent))] = digest(path)
    for name in ("connectors/profile_registry.c", "connectors/profile_registry.h"):
        result[name] = digest(parent / name)
    if not result or "connectors/haproxy/Makefile" not in result:
        raise ValueError("native product source map incomplete")
    return result


def observe_filter(source: str) -> str:
    admission = '''    snprintf(ctx->lifecycle.transaction_id, sizeof(ctx->lifecycle.transaction_id),
        "haproxy-htx-%u", s->uniq_id);
    return 0;'''
    admission_observer = '''    snprintf(ctx->lifecycle.transaction_id, sizeof(ctx->lifecycle.transaction_id),
        "haproxy-htx-%u", s->uniq_id);
    ha_warning("modsecurity-htx-test: admitted transaction_id=%s\\n",
        ctx->lifecycle.transaction_id);
    return 0;'''
    detach = '''    haproxy_modsecurity_htx_abort_context(ctx);
    free(ctx);
    filter->ctx = NULL;'''
    detach_observer = '''    haproxy_modsecurity_htx_abort_context(ctx);
    ha_warning("modsecurity-htx-test: cleanup transaction_id=%s native_released=%d companion_closed=%d\\n",
        ctx->lifecycle.transaction_id, ctx->transaction == NULL,
        !ctx->companion.mode || ctx->companion.terminal_result);
    ha_warning("modsecurity-htx-test: context_detached host_stream_id=%u handle_present=%d native_released=%d companion_closed=%d\\n",
        s->uniq_id, ctx->response.handle_present, ctx->transaction == NULL,
        !ctx->companion.mode || ctx->companion.terminal_result);
    free(ctx);
    filter->ctx = NULL;'''
    claim = '''    haproxy_modsecurity_htx_companion_result_reset(&result);
    if (ok != 1) {
        haproxy_modsecurity_htx_companion_cancel_and_close(ctx, &error);
    }
    return ok == 1;'''
    claim_observer = '''    haproxy_modsecurity_htx_companion_result_reset(&result);
    if (ok != 1) {
        haproxy_modsecurity_htx_companion_cancel_and_close(ctx, &error);
    } else {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        char hex[SHA256_DIGEST_LENGTH * 2 + 1];
        size_t index;
        if (SHA256((const unsigned char *)ctx->response.handle,
                strlen(ctx->response.handle), hash) == NULL) {
            ha_warning("modsecurity-htx-test: claim observer hash failed\\n");
        } else {
            for (index = 0; index < SHA256_DIGEST_LENGTH; ++index) {
                (void)snprintf(hex + index * 2, 3, "%02x", hash[index]);
            }
            ha_warning("modsecurity-htx-test: claim transaction_id=%s handle_sha256=%s\\n",
                ctx->lifecycle.transaction_id, hex);
        }
    }
    return ok == 1;'''
    claim_start = source.index("static int haproxy_modsecurity_htx_companion_open_and_claim(")
    claim_end = source.index("\nstatic int haproxy_modsecurity_htx_companion_commit(", claim_start)
    claim_function = source[claim_start:claim_end]
    if source.count(admission) != 1 or source.count(detach) != 1 or claim_function.count(claim) != 1:
        raise ValueError("native observer anchors changed; manual review required")
    return ("#include <openssl/sha.h>\n" + source.replace(claim_function, claim_function.replace(claim, claim_observer))
            .replace(admission, admission_observer).replace(detach, detach_observer))


def verify_source_archive(archive: Path, source: Path) -> dict[str, str]:
    """Prove every supplied upstream source byte belongs to the pinned archive."""
    expected = {}
    total = 0
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            parts = Path(member.name).parts
            if member.name.startswith("/") or ".." in parts or not parts:
                raise ValueError("unsafe source archive member")
            relative = Path(*parts[1:])
            if member.isdir():
                continue
            if str(relative) in expected:
                raise ValueError("duplicate source archive member")
            if member.issym():
                path = source / relative
                if (not path.is_symlink() or os.readlink(path) != member.linkname
                        or not path.resolve(strict=True).is_relative_to(source)):
                    raise ValueError("prepared source symlink differs/escapes: " + str(relative))
                expected[str(relative)] = hashlib.sha256(("symlink:" + member.linkname).encode()).hexdigest()
                continue
            if not member.isfile() or member.size > 16 * 1024 * 1024:
                raise ValueError("unexpected nonregular/large source archive member")
            total += member.size
            if total > 128 * 1024 * 1024 or len(expected) >= 20000:
                raise ValueError("source archive bound exceeded")
            path = source / relative
            if any(value.is_symlink() for value in (path, *path.parents)):
                raise ValueError("symlink in prepared source")
            with bundle.extractfile(member) as stream:
                archived_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            if not path.is_file() or digest(path) != archived_hash or str(relative) in expected:
                raise ValueError("prepared source differs from verified archive: " + str(relative))
            expected[str(relative)] = archived_hash
    actual = {str(path.relative_to(source)) for path in source.rglob("*") if not path.is_dir()}
    if not expected or actual != set(expected) | {".haproxy-source-provenance"}:
        raise ValueError("foreign or missing prepared source file")
    return expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", type=Path, required=True)
    parser.add_argument("--framework-root", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--modsecurity-prefix", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    parent = args.connector_root.resolve(strict=True)
    framework = args.framework_root.resolve(strict=True)
    prefix = args.modsecurity_prefix.resolve(strict=True)
    source = args.source_dir.resolve(strict=True)
    root = args.build_root.absolute()
    if not 1 <= args.jobs <= (os.cpu_count() or 1):
        parser.error("jobs must fit available CPUs")
    if (not root.is_relative_to(Path("/var/tmp/codex/ModSecurity-conector"))
            or any(path.is_symlink() for path in (root, *root.parents))
            or parent in root.parents or framework in root.parents):
        parser.error("private external build root required")
    contract = json.loads((parent / "connectors/haproxy/htx-overlay/version-contract.json").read_text())
    provenance = dict(line.split("=", 1) for line in
                      (source / ".haproxy-source-provenance").read_text().splitlines() if "=" in line)
    for key, value in (("haproxy_version", contract["version"]),
                       ("haproxy_source_url", contract["source_url"]),
                       ("haproxy_sha256", contract["sha256"])):
        if provenance.get(key) != value:
            raise ValueError(f"source provenance mismatch: {key}")
    archive = Path(provenance["haproxy_archive"])
    if digest(archive) != contract["sha256"]:
        raise ValueError("native source archive hash mismatch")
    upstream_hashes = verify_source_archive(archive, source)
    product_hashes = parent_source_hashes(parent)
    builder_hash = digest(Path(__file__))
    product_filter = parent / "connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c"
    product_source = product_filter.read_text()
    instrumented = observe_filter(product_source)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    overlay = root / "overlay"
    environment = os.environ.copy()
    environment.update(CONNECTOR_ROOT=str(parent), FRAMEWORK_ROOT=str(framework), TEST_ROOT=str(framework),
                       MAKE_JOBS=str(args.jobs))
    command = ["make", "-C", str(parent / "connectors/haproxy"), "build-htx-overlay",
               f"FRAMEWORK_ROOT={framework}", f"PYTHON={os.environ.get('PYTHON', 'python3')}",
               f"REPO_ROOT={parent}", f"BUILD_ROOT={root}",
               f"HAPROXY_MODSECURITY_BINDING_DIR={root / 'binding'}",
               f"MODSECURITY_RESOLUTION_FILE={root / 'binding/resolution.env'}",
               f"MODSECURITY_INCLUDE_DIR={prefix / 'include'}", f"MODSECURITY_LIB_DIR={prefix / 'lib'}",
               f"HAPROXY_HTX_SOURCE_DIR={source}", f"HAPROXY_HTX_BUILD_DIR={overlay}", "ON_DEMAND_TESTS=1"]
    with (root / "native-build.log").open("xb") as log:
        subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    worktree = overlay / "worktree"
    filter_source = worktree / "src/haproxy_modsecurity_htx_filter.c"
    original = filter_source.read_text()
    if original != product_source:
        raise ValueError("native staged filter differs from admitted product source")
    production_hash = digest(filter_source)
    filter_source.write_text(instrumented)
    binding = dict(line.split("=", 1) for line in (root / "binding/paths.env").read_text().splitlines())
    flags = binding.get("HAPROXY_MODSECURITY_BINDING_CPPFLAGS", "")
    if flags not in ("", "-DHAPROXY_HAVE_MSC_GET_RULES_MESSAGES_RULE_IDS=1"):
        raise ValueError("unexpected native binding flags")
    rebuild = ["make", "-C", str(worktree), "TARGET=linux-glibc", "USE_OPENSSL=1", "-j", str(args.jobs),
               f"CFLAGS=-I{worktree / 'src/connectors'} -I{prefix / 'include'} {flags}",
               f"ADDLIB={binding['MODSECURITY_LIBRARY']} -Wl,-rpath,{prefix / 'lib'} -lstdc++", "haproxy"]
    with (root / "observer-build.log").open("xb") as log:
        subprocess.run(rebuild, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    witness = {"schema_version": 1, "test_only_observer": True,
               "parent_sha": subprocess.check_output(["git", "-C", str(parent), "rev-parse", "HEAD"], text=True).strip(),
               "framework_sha": subprocess.check_output(["git", "-C", str(framework), "rev-parse", "HEAD"], text=True).strip(),
               "version_contract": contract, "verified_archive": str(archive),
               "production_filter_sha256": production_hash, "observed_filter_sha256": digest(filter_source),
               "observer_source_sha256": builder_hash,
               "binary": str(worktree / "haproxy"), "binary_sha256": digest(worktree / "haproxy"),
               "modsecurity_library": str(Path(binding["MODSECURITY_LIBRARY"]).resolve(strict=True)),
               "modsecurity_library_sha256": digest(Path(binding["MODSECURITY_LIBRARY"])),
               "native_command": command, "observer_command": rebuild}
    if verify_source_archive(archive, source) != upstream_hashes:
        raise ValueError("upstream source changed during build")
    witness["upstream_source_sha256"] = upstream_hashes
    if parent_source_hashes(parent) != product_hashes or digest(Path(__file__)) != builder_hash:
        raise ValueError("native product/builder inputs changed during build")
    witness["parent_source_sha256"] = product_hashes
    (root / "h2-test-build.json").write_text(json.dumps(witness, indent=2) + "\n")
    print(json.dumps(witness))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
