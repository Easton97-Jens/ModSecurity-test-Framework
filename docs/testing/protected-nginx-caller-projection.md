# Protected NGINX caller projection

**Language:** English | [Deutsch](protected-nginx-caller-projection.de.md)

The immutable protected broker accepts a five-job inline Parent caller with
deny-default top-level permissions, exact master/non-fork dispatch gates and the
fixed concurrency contract. A one-job wrapper delegating the caller to Framework
does not satisfy that parser. This is separate from ordinary hosted NGINX smoke.

Framework owns the canonical caller and execution/test logic in
`.github/workflows/connector-protected-nginx-root-broker-caller.yml`. The generated
Parent `.github/workflows/run-protected-nginx-root-broker.yml` projects those exact
bytes, replacing only `workflow_call` with `workflow_dispatch` and adding source
revision/hash comments. It retains both protected broker calls at
`8ae707d72f1a8acb25d239e55e28a73cbc7522b1` with protected Framework
`99a7985c1be92a2297b1b59208f64df6768f2cbf`. These protected identities are distinct
from the current Framework source revision generating the caller.

From the Framework checkout, with the approved Framework interpreter, actual
Parent path and exact Framework source revision:

```sh
rtk bypass "$PYTHON" ci/tools/generate-protected-nginx-caller.py --check \
  --parent-root "$CONNECTOR_ROOT" --framework-revision "$FRAMEWORK_SHA"
```

Use `--sync` in place of `--check` only for an authorized projection update.
The generator reads the fixed regular blob from that exact Git object, never a
mutable source copy. Unknown source bytes, symbolic revisions or symlink targets
are rejected. The reviewed source SHA-256 is
`11ee98f070a5a4c088e0c10466c0e867869f1769e5832bacf6bf2c5986a2cb3c`.
Source-body changes require semantic review and ordinary source/generator
contract maintenance; changing a checksum alone is insufficient.

Parent's component synchronizer has a distinct `framework-inline-caller` target.
It reads the fixed candidate workflow as bounded regular Git data, requires the
reviewed source hash, reconstructs the previous projection and writes the new
projection in the existing transaction. It does not import candidate Python,
invent reusable references, or rewrite protected broker identities. The default
object repository is Parent's Framework submodule; isolated preparations can
select an existing read-only object repository with `--framework-object-root`.
Only the exact former delegated caller at its captured baseline is admitted for
one-time migration; altered/mixed callers fail. The frozen historical rejection
fixture remains a negative regression after the current caller is repaired.

Focused on-demand checks require `CONNECTOR_ROOT` to identify the actual Parent
checkout containing the immutable broker Git object:

```sh
rtk bypass "$PYTHON" -m unittest -v tests.ci_security.test_protected_nginx_caller_projection
```

These tests load only the exact immutable broker source after verifying its
SHA-256 `4c85bf823f7c9109706394b422b46a77e24e80808571cb13c7bf1a0a47abf2eb`.
They prove the generated caller is accepted and weakened gates, writable
permissions and changed/mutable protected pins are rejected. They also compare
Framework generation with Parent's typed projection and exercise exact Git reads.
No privileged broker action, publisher or administrative operation is invoked.

Parser compatibility establishes caller readiness only. Final delivery must
regenerate using the delivered Framework source revision, preserve the actual
Parent/Framework pair, run hosted workflow/security gates and obtain separately
authorized protected-master runtime evidence. No new immutable broker publication
is required solely for this caller-shape correction; no runtime PASS follows.
