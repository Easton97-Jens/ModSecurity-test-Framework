# Physical file-backed HTTP supplement for Traefik I12

**Language:** English | [Deutsch](README.de.md)

For the current source-checkout commands below, select both checkouts, a
compatible interpreter and existing approved external storage explicitly.
Replace these illustrative paths with actual physical paths; source preparation
still requires the stated independent admission and does not authorize a host run.

```sh
export CONNECTOR_ROOT="/absolute/product/checkout"
export CONNECTOR_REVISION="$(git -C "$CONNECTOR_ROOT" rev-parse HEAD)"
export TEST_ROOT="/absolute/framework/checkout"
export FRAMEWORK_ROOT="$TEST_ROOT"
export FRAMEWORK_PYTHON="/absolute/framework-venv/bin/python"
export CODEX_TEMP_ROOT="/absolute/approved/external/storage"
export I12_TEST_ROOT="$CODEX_TEMP_ROOT"
export CONNECTOR_TEST_OUTPUT_ROOT="$CODEX_TEMP_ROOT"
export PYTHONSAFEPATH=1
export PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite"
```

This producer measures a regular file read by the actual HTTP client or target
backend, then streams those bytes through the existing Traefik byte APIs. It does
not call or prove a native SDK File-Body API. All four original IDs in
[supplement-plan.json](supplement-plan.json) remain unqualified. The physical
HTTP supplement leaves the native File-API obligation open. An independent
review must approve the frozen rules, phases and expected outcomes before a host run.

`acceptance.py` declares nine separate executions for the four original IDs:
benign and marker for each, plus the ForwardAuth request capacity control. Each
has distinct file and transaction keys, exact file size/hash, complete generated
rules and rule/expectation hashes. The request marker expects P2 rule 1100101
and 403. ForwardAuth requires backend exclusion; Native measures actual backend
accept, headers and body prefix because dispatch begins before P2 completes.
The response marker expects P4 rule 1100301 and Safe client
200 with the exact file entity. The default-MRC1 4199-byte ForwardAuth capacity
control expects host 401 with no sample/native transaction/backend. These are
pre-run expectations, not observations or automatic qualifications. Bind the
actual generated rules and this contract to the immutable admission ledger.
Both Traefik profiles expose `strict_post_commit_action=0`; Strict is only a
configuration/startup negative with no target transaction.

`source.py` opens a reader-owned mode 0700 private root and a single relative
mode 0600 regular file using `O_NOFOLLOW`. It rejects hard links, symlinks,
nonregular files, wrong owners/modes, wrong size/hash, short reads, path
replacement and observable size/mtime/ctime/inode changes. A complete receipt
records PID, monotonic timestamps, device/inode/owner/mode, pre/post stat, every
offset/request/result/chunk hash, aggregate bytes/hash, physical EOF and the
actual close results. Reads and callbacks happen synchronously with at most one
24-byte fixture chunk in the source reader. A failed source preserves its
incomplete receipt and closes both descriptors. No complete body is preloaded or
decoded from hexadecimal in the actual source path.

Manifests cap input files at 512 KiB, individual reads at 64 KiB and receipts at
4096 physical reads. HTTP request and response wire observations are bounded at
1 MiB, including request chunk framing.

Each physical read becomes one separately framed HTTP chunk. TCP/HTTP may merge
these writes; native chunk boundaries still require actual capture. The final
HTTP chunk is sent only after source verification and close. Its sendall return
proves local acceptance only. Neither a source-file EOF, an HTTP terminator nor a
TCP EOF proves native EOS. The adapters leave `native_eos=null` and never infer
commit, Finish/Free, inspection or remote delivery. Client response bytes,
including a prefix before reset/timeout, are retained verbatim.

The request and response marker fixtures straddle two physical 24-byte reads.
The 4199-byte request control places its marker at offset 4160. The currently
pinned ForwardAuth contract has `forwardBody=true,maxBodySize=4096`, so this is a
host-capacity rejection control: verify the actual status and the absence of any
authorization sample/native transaction/backend arrival. Do not assume the host
forwards an inspected 4096-byte prefix. Retain `maxResponseBodySize=32768` as the
separate authorization-response capacity setting.

For response evidence, `response_backend` accepts exactly one correlated target
request and records accept before reading the request or opening the source.
Keep the existing independent healthy-neighbor backend/router. Never use a TCP
readiness probe against this one-target backend; its listening receipt proves
bind/listen only, and real host readiness must use the separate neighbor route.

## Integration handoff

No host run is included. The JSON plan contains the four exact original IDs,
capture variants, source controls and required remaining evidence. Use fresh
sealed admissions based on the already reviewed native/auth infrastructure;
include every adapter/fixture/manifest hash in its immutable ledgers. Copy the
Python files together so the staged `run.py` can import its adjacent modules.
Create separate fresh reader-owned mode 0700 source and evidence directories.

The controller invokes the following argument contracts, with literal paths,
ports and transaction keys admitted before execution:

```text
run.py stage --manifest MANIFEST --fixture-root FIXTURES --private-root PRIVATE --evidence-root EVIDENCE
run.py client --manifest MANIFEST --fixture request-marker.txt --private-root PRIVATE --evidence-root EVIDENCE --port HOST_PORT --key EXACT_KEY --uri /no-crs/request-body
run.py backend --manifest MANIFEST --fixture response-marker.txt --private-root PRIVATE --evidence-root EVIDENCE --port BACKEND_PORT --key EXACT_KEY
```

Pass `--transaction-id EXACT_NATIVE_ID` when `X-Request-Id` differs from the file
key. `X-I12-Acceptance-Key` always carries the file target key; the backend checks
both exact headers before opening a file. Process identity, source receipts,
raw HTTP and entity hashes remain separate; the parent retains actual wait
status. Complete HTTP framing is decoded independently of TCP EOF and native EOS.

Invoke these via the controller's reviewed Python/RTK boundary. Stage once,
then run the actual reader in a separate waited client/backend process. A request
file uses the existing independent target backend; a response file uses the
existing benign target client with `/no-crs/allow`. Extend only the exact
transaction allowlist in the disposable capture staging. Preserve the central
`traefik-native` and `traefik-forwardauth` variants, authorization relay,
native/observer events, client raw bytes, UDS evidence and cleanup receipts.

Missing/symlink/nonregular/mutation/short-read negatives are tested locally.
For host negatives, arrange the admitted failure in a fresh source root, retain
the error receipt and process wait status, and verify actual engine abort,
once-only Finish/Free, healthy neighbors and cleanup. A failed source omits the
HTTP terminator; it must never promote a success. Full native EOS, commit order,
first native cause, inspection, backend inclusion/exclusion and observer
correlation remain separate host evidence obligations.

## SDK boundary and validation

`sdk_capability.c` strictly compiles/links the request-file and both byte append
functions without invoking them. `sdk_capability.py` binds the exact header and
shared library hashes and inventories C declarations/exports. The installed
SDK 3.0.14 has `msc_request_body_from_file` and no response-file C declaration or
export. This capability receipt proves neither productive route calls nor
execution of the request-file API. Do not replace byte append with a test-only
file API hook or invent a response-file API.

Focused on-demand command with the explicit environment above:

```text
ON_DEMAND_TESTS=1 rtk proxy "$FRAMEWORK_PYTHON" -P -B -m unittest -v modsecurity_connector_tests.test_traefik_i12_file_source
```

The tests cover real child file-reader processes, physical negatives, per-read
hash mapping, complete versus incomplete HTTP framing via socketpairs, bounded
manifests, descriptor close errors, accept persistence and client-prefix retention.
These establish the producer layer only. No original oracle, runtime ID, central
matrix, shared generator, Framework/MRTS or productive source is changed.

The missing-file child negative uses the immediate `ENOENT` path with
`O_NOFOLLOW|O_NONBLOCK`, followed by root-descriptor close. A previous simultaneous
four-suite run exceeded the unchanged 10-second process budget; focused reruns
passed. No source-path blocking operation or timeout relaxation was introduced.
