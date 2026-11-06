#!/usr/bin/env python3
"""Build actual native SPOP plus logging-only handoff/claim/cleanup witnesses."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


HANDLE_OBSERVER = r'''
#include <stdio.h>
#include <openssl/sha.h>
static void spop_h2_observe_handle(const char *event, const char *transaction_id,
                                 const char *handle, unsigned long long lease) {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  char hex[SHA256_DIGEST_LENGTH * 2U + 1U];
  if (handle == NULL || SHA256((const unsigned char *)handle, strlen(handle), digest) == NULL) return;
  for (size_t i = 0U; i < sizeof(digest); ++i) snprintf(hex + i * 2U, 3U, "%02x", digest[i]);
  fprintf(stderr, "spop-h2-test: event=%s transaction_id=%s handle_sha256=%s lease=%llu\n",
          event, transaction_id != NULL ? transaction_id : "none", hex, lease);
  fflush(stderr);
}
'''


def observe_backend(source):
    handoff = '''  memcpy(handle, backend->slots[i].handle, sizeof(backend->slots[i].handle));
  pthread_mutex_unlock(&backend->lock);'''
    claim = '''  pthread_mutex_unlock(&backend->lock);
  return result;
}

typedef struct haproxy_spop_response_companion_invoke_state'''
    if source.count(handoff) != 1 or source.count(claim) != 1:
        raise ValueError("native SPOP observer anchors changed")
    source = source.replace("#define HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_ATTEMPTS 4U", HANDLE_OBSERVER + "\n#define HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_ATTEMPTS 4U")
    source = source.replace(handoff, '''  memcpy(handle, backend->slots[i].handle, sizeof(backend->slots[i].handle));
  spop_h2_observe_handle("handoff", haproxy_modsecurity_transaction_id(transaction),
                         handle, (unsigned long long)backend->slots[i].lease);
  pthread_mutex_unlock(&backend->lock);''')
    return source.replace(claim, '''  if (result) spop_h2_observe_handle("claim", NULL, handle, (unsigned long long)lease);
  pthread_mutex_unlock(&backend->lock);
  return result;
}

typedef struct haproxy_spop_response_companion_invoke_state''')


def observe_binding(source):
    cleanup = '''        transaction->contract_initialized = 0;
    }
    free(transaction);
}

static int validate_common_mapped_request'''
    observed = '''        transaction->contract_initialized = 0;
    }
    fprintf(stderr, "spop-h2-test: event=cleanup transaction_id=%s native_cleanup_returned=1 contract_cleared=%d\\n",
        transaction->request_id, transaction->contract_initialized == 0);
    fflush(stderr);
    free(transaction);
}

static int validate_common_mapped_request'''
    if source.count(cleanup) != 1:
        raise ValueError("native SPOP binding cleanup observer anchor changed")
    return source.replace(cleanup, observed)



def observe_runtime(source):
    anchor = """        context->success = haproxy_modsecurity_transaction_finish_response_body(
            context->transaction, native_decision) == 0;
        break;"""
    observed = """        context->success = haproxy_modsecurity_transaction_finish_response_body(
            context->transaction, native_decision) == 0;
        if (context->success) {
            fprintf(stderr, "spop-h2-test: event=owner_eos transaction_id=%s phase=%d rule_id=%d status=%d disruptive=%d\\n",
                context->transaction_id, native_decision->phase, native_decision->rule_id,
                native_decision->status, native_decision->disruptive);
            fflush(stderr);
        }
        break;"""
    if source.count(anchor) != 1:
        raise ValueError("native SPOP owner EOS observer anchor changed")
    return source.replace(anchor, observed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", type=Path, required=True)
    parser.add_argument("--framework-root", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--modsecurity-prefix", type=Path, required=True)
    args = parser.parse_args()
    parent, framework, prefix = [path.resolve(strict=True) for path in
                                (args.connector_root, args.framework_root, args.modsecurity_prefix)]
    root = args.build_root.absolute()
    if ".." in root.parts or not root.is_relative_to(Path("/var/tmp/codex/ModSecurity-conector")) or root.exists() or any(path.is_symlink() for path in root.parents):
        parser.error("fresh private external build root required")
    from modsecurity_connector_ci.lib.runtime_path_utils import verified_runtime_artifact_root
    previous_mask = os.umask(0o077)
    try:
        verified_runtime_artifact_root(root)
    finally:
        os.umask(previous_mask)
    materialized = root / "source/connectors/haproxy"
    # Preserve product-relative include topology without pointing any copied
    # source at writable product files or altering native include contracts.
    shutil.copytree(parent / "common", root / "source/common")
    shutil.copytree(parent / "connectors/haproxy", materialized)
    before = {str(path.relative_to(materialized)): digest(path) for path in sorted(materialized.rglob("*"))
              if path.is_file() and not path.is_symlink()}
    for name, observer in (("haproxy_spop_response_companion_backend.c", observe_backend),
                            ("haproxy_modsecurity_binding.c", observe_binding),
                            ("haproxy_spop_diagnostic_runtime.c", observe_runtime)):
        path = materialized / "src" / name
        path.write_text(observer(path.read_text()))
    parent_revision = subprocess.check_output(["git", "-C", str(parent), "rev-parse", "HEAD"], text=True).strip()
    framework_revision = subprocess.check_output(["git", "-C", str(framework), "rev-parse", "HEAD"], text=True).strip()
    command = ["make", "-C", str(materialized), f"REPO_ROOT={parent}", f"CONNECTOR_ROOT={parent}",
               f"CONNECTOR_REVISION={parent_revision}", f"FRAMEWORK_ROOT={framework}",
               f"BUILD_ROOT={root / 'build'}", f"MODSECURITY_INCLUDE_DIR={prefix / 'include'}",
               f"MODSECURITY_LIB_DIR={prefix / 'lib'}", f"MODSECURITY_LIBRARY={prefix / 'lib/libmodsecurity.so.3.0.17'}",
               "LDLIBS=-lcrypto", "build-modsecurity-binding", "build-spoa-runtime"]
    with (root / "native-observer-build.log").open("xb") as log:
        subprocess.run(command, env=os.environ.copy(), check=True, stdout=log, stderr=subprocess.STDOUT)
    binary = root / "build/haproxy-spoa-runtime/haproxy-modsecurity-spoa"
    for name, expected in before.items():
        if Path(name).suffix in (".c", ".h", ".sh", ".py") or name == "Makefile":
            if digest(parent / "connectors/haproxy" / name) != expected:
                raise ValueError("product source changed during observed build")
    receipt = {"test_only_observer": True, "parent_sha": parent_revision, "framework_sha": framework_revision,
               "observer_source_sha256": digest(Path(__file__)), "production_source_sha256": before,
               "observed_source_sha256": {str(path.relative_to(materialized)): digest(path) for path in
                    (materialized / 'src/haproxy_spop_response_companion_backend.c', materialized / 'src/haproxy_modsecurity_binding.c', materialized / 'src/haproxy_spop_diagnostic_runtime.c')},
               "binary": str(binary), "binary_sha256": digest(binary), "native_command": command,
               "modsecurity_library": str(prefix / "lib/libmodsecurity.so.3.0.17"),
               "modsecurity_library_sha256": digest(prefix / "lib/libmodsecurity.so.3.0.17"),
               "shared_source_sha256": {str(path.relative_to(parent)): digest(path) for path in
                   [*sorted((parent / "common").rglob("*")), parent / "connectors/profile_registry.c", parent / "connectors/profile_registry.h"]
                   if path.is_file() and not path.is_symlink()},
               "observer_semantics": "logging only after actual native handoff/claim, successful native owner EOS before serialization, and actual native cleanup; no decision, pointer, host action, lifetime, or cancellation changes"}
    (root / "spop-h2-test-build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"binary": str(binary), "receipt": str(root / 'spop-h2-test-build.json')}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
