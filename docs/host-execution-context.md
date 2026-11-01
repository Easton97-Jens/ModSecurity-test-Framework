# Host execution context

**Language:** English | [Deutsch](host-execution-context.de.md)

Real connector tests need the execution context declared by the selected profile. UID 0 alone does not establish host-root authority: UID/GID mappings, effective capabilities, supplementary groups, path traversal and socket access also matter. Run a fresh preflight in every new session and before the selected harness; an earlier PASS cannot authorize or prove a later runtime run.

## Contexts and authority

The observed Codex sandbox maps only identity 0, has zero effective capabilities and `NoNewPrivs=1`. The separately approved host command context has full identity mappings, effective capabilities and `NoNewPrivs=0`. These are observations of different process contexts, not permanent host configuration guarantees. The preflight records the current UID/GID maps, user namespace, selected capability/security fields and bounded container markers again.

`require_escalated` requests explicit approval for an individual command through the execution tool. It is not an option of this Framework CLI. Neither the helper nor the harness automatically bypasses sandbox restrictions, changes Codex policy, installs packages, or modifies permanent host service configuration. If the required context is unavailable, retain `BLOCKED` and use an approved host command, a separately prepared runner, or a genuinely different profile whose contract fits the available context. Do not silently relabel the root-master profile as rootless.

Protected exact-head broker profiles have separate namespace identities and trust requirements. Their launcher, broker identity, provenance and exact-head controls remain authoritative; this generic preflight neither changes nor replaces them. Do not inject the ordinary NGINX worker identity into a protected broker profile.

## Explicit profile requirements

| Requirement | CLI contract |
| --- | --- |
| Profile label | Always pass `--profile`; the label does not automatically select or infer requirements. |
| Ordinary NGINX native root master | Declare `--require-root-master --require-chown` and the profile's explicit `--worker-user` and `--worker-group`. Only profiles needing a distinct worker should request one. |
| Worker files and directories | Repeat `--worker-read`, `--worker-write` and `--worker-deny` for the prepared profile paths. Operations run in a bounded child after the requested UID/GID/supplementary-group transition is verified. |
| Envoy observer UDS | Declare `--uds-path` for a fresh name inside a private directory owned by the socket identity, below the approved runtime root, or an independently verified private `--uds-root` when a shorter external socket path is needed. The probe binds, connects and exchanges one byte. |
| Other profiles | Declare only their actual requirements; do not impose NGINX root, chown or worker transitions universally. |

Read probes open a file or list a directory; write probes create and remove a unique temporary file. A deny probe verifies file-read denial or directory-search denial: preventing directory listing alone is insufficient, and a missing path or symlink does not prove isolation. Paths must be absolute and reject symlink components. The UDS path must fit the Linux socket limit; an existing socket is preserved and blocks the probe. Probe-created files and sockets are cleaned up, and the bounded child is reaped.

## Native invocation and evidence

Use the Framework-owned interpreter and source import roots. From the Framework checkout, this context-only example tests the current identity without requiring a connector binary:

```sh
rtk bypass env PYTHONDONTWRITEBYTECODE=1 PYTHONSAFEPATH=1 \
  PYTHONPATH="$PWD:$PWD/connector_suite" "$PYTHON" -P \
  -m modsecurity_connector_ci.runtime.common.hostruntime_preflight \
  --execution-context-only --profile current-identity \
  --runtime-root /var/tmp/codex/ModSecurity-conector/host-context \
  --output-dir /var/tmp/codex/ModSecurity-conector/host-context/preflight
```

Set `PYTHON` to the approved Framework interpreter before invoking the example. Use a fresh task-owned root and an output child, outside source checkouts, `/tmp` and home storage. For this Parent-coordinated task, the approved external root is `/var/tmp/codex/ModSecurity-conector`. Prepare fixture ownership and permissions through the authorized profile before passing worker path flags. A minimal current-identity PASS does not satisfy the more demanding NGINX profile.

The CLI emits `status.json` and `summary.md`. Its existing schema remains `schema_version=1`, `evidence_kind=preflight`, `runtime_status=NOT_RUN`, including when `status=PASS`. The execution-context metadata and per-check reason codes describe prerequisites only. The context-only mode skips binary/version/dependency checks; run the selected harness and its normal binary/configuration checks separately for runtime evidence. Current entry points integrate the context check into NGINX smoke/lifecycle and Envoy start/runtime paths.

| Result | Meaning and next action |
| --- | --- |
| Exit 0 / `PASS` | Declared probes passed in this process context; proceed to the selected runtime validation. |
| Exit 77 / `BLOCKED` | Environment or declared prerequisite blocker; inspect the failed check and rerun in a suitable approved context. |
| Unmapped worker / missing transition capabilities | Root label is insufficient; worker UID and every required group must be mapped, with transition capabilities available. |
| Chown, worker access or UDS blocker | Correct the authorized runtime preparation or select a compatible context; preserve private-directory and deny-path requirements. |
| Runtime failure after preflight | Investigate host/configuration/connector evidence separately; a preflight PASS is not a runtime PASS. |

No connector promotion or cached runtime claim follows from these probes. Documentation checks and unit tests establish their own layers only; fresh connector runtime results must identify their actual profile, process context and external evidence directory.
