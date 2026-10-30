"""Batch component checks use harmless processes/sockets; never HAProxy hosts."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from unittest import mock

import pytest

SOURCE = connector_root() / "connectors/haproxy/harness/i12_batch.py"
batch = load_source(SOURCE)


@pytest.fixture(autouse=True)
def local_storage_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(batch, "STORAGE", tmp_path)


def blank_state():
    return {"processes": {}, "sockets": {}, "descriptors": {}}


def source_fixture(root):
    root.mkdir()
    files = {"launch.py": b"ROOT='/task'; fixture='/mnt/fixtures/client.py'; port=18490; backend=18491\n",
             "client.py": b"ROOT='/task'; port=18490\n",
             "backend.py": b"ROOT='/task'; port=18491\n",
             "case-contract.json": b'{"original_id":"I12::haproxy-native-htx::allow","original_oracle":{"visible_status":200}}',
             "body.bin": b"/task /mnt/fixtures 18490 18540\x00"}
    for name, value in files.items():
        (root / name).write_bytes(value)
        (root / name).chmod(0o444)
    return {"route": "native", "source": str(root), "original_id": "I12::haproxy-native-htx::allow",
            "files": {name: batch.digest(value) for name, value in files.items()}}


def prepare_queue(tmp_path):
    source = source_fixture(tmp_path / "source")
    output = tmp_path / "out"
    output.mkdir()
    receipt = batch.prepare({"cases": [source]}, output)
    return source, output, receipt


def test_immutable_payload_oracle_and_complete_runtime_relocation(tmp_path):
    source, output, receipt = prepare_queue(tmp_path)
    assert (output / "c00/body.bin").read_bytes() == (Path(source["source"]) / "body.bin").read_bytes()
    assert (output / "c00/case-contract.json").read_bytes() == (Path(source["source"]) / "case-contract.json").read_bytes()
    launch = (output / "c00/launch.py").read_text()
    assert "'/task/c00'" in launch
    assert "'/mnt/fixtures/c00/client.py'" in launch
    assert "port=21000" in launch
    assert "backend=21001" in launch
    assert "port=21000" in (output / "c00/client.py").read_text()
    assert "port=21001" in (output / "c00/backend.py").read_text()
    assert receipt["prepared_unsealed_no_execution"] is True
    batch.seal(output, receipt["ledger_sha256"])
    queue = batch.load_queue(output / "queue.json", receipt["queue_sha256"])
    assert queue["full_lifecycle_pass"] is None
    assert queue["cases"][0]["argv"][-1] == "/mnt/fixtures/c00/launch.py"


def test_spop_all_five_ports_consistently_relocated():
    data = b"a=18540; b=18541; c=18542; d=18543; e=18544; again='18540'; rule=1185401\n"
    actual, substitutions = batch.relocate(data, "spop", "c01")
    assert actual == b"a=22010; b=22011; c=22012; d=22013; e=22014; again='22010'; rule=1185401\n"
    assert substitutions["18540"]["count"] == 2
    with pytest.raises(ValueError, match="explicit root"):
        batch.relocate(data, "companion", "c00")


def test_queue_tampering_rejected_even_before_driver_launch(tmp_path):
    _, output, receipt = prepare_queue(tmp_path)
    batch.seal(output, receipt["ledger_sha256"])
    with pytest.raises(ValueError, match="identity"):
        batch.load_queue(output / "queue.json", "0" * 64)
    target = output / "c00/body.bin"
    target.chmod(0o644)
    target.write_bytes(b"modified")
    with pytest.raises(ValueError, match="inventory"):
        batch.load_queue(output / "queue.json", receipt["queue_sha256"])


def test_seal_rejects_changed_candidate(tmp_path):
    _, output, receipt = prepare_queue(tmp_path)
    extra = output / "unreviewed.py"
    extra.write_text("raise SystemExit(0)")
    with pytest.raises(ValueError, match="candidate changed"):
        batch.seal(output, receipt["ledger_sha256"])


def test_traversal_and_symlink_sources_rejected(tmp_path):
    with pytest.raises(ValueError, match="physical"):
        batch.physical(tmp_path / ".." / "escape")
    actual = tmp_path / "actual"
    actual.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(actual)
    with pytest.raises(ValueError, match="symlink"):
        batch.physical(link)


def test_actual_live_process_and_listener_stop_next_member(tmp_path):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    listener = socket.socket()
    try:
        before = batch.sockets()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        actual = batch.process_record(child.pid)
        after = blank_state()
        key = str(child.pid) + ":" + actual["starttime"]
        after["processes"][key] = actual
        after["sockets"] = {key: value for key, value in batch.sockets().items() if key not in before}
        errors = batch.cleanup_difference(blank_state(), after)
        assert {row["kind"] for row in errors} == {"processes_leak", "sockets_leak"}
        queue = {"cases": [entry("c00", "pass"), entry("c01", "pass")]}
        with mock.patch.object(batch, "state", side_effect=[blank_state(), after]), \
                mock.patch.object(batch, "cleanup_receipt", return_value={"clean": True}):
            assert batch.execute_queue(queue, "actual-resource-negative-control", tmp_path) == 77
        assert not (tmp_path / "c01").exists()
        assert child.poll() is None
    finally:
        listener.close()
        child.terminate()
        child.wait(timeout=5)


def test_actual_descriptor_change_is_reported(tmp_path):
    before = blank_state()
    before["descriptors"] = batch.descriptors()
    with (tmp_path / "actual-open-file").open("w"):
        after = blank_state()
        after["descriptors"] = batch.descriptors()
        errors = batch.cleanup_difference(before, after)
        assert any(row["kind"] == "coordinator_descriptor_change" for row in errors)


def entry(member, code):
    return {"member": member, "original_id": "I12::haproxy-native-htx::" + member,
            "route": "native", "data_root": "/unused-by-component-test",
            "argv": [sys.executable, "-c", code], "timeout_seconds": 5}


def test_real_nonzero_clean_child_continues_to_next_member(tmp_path):
    queue = {"cases": [entry("c00", "raise SystemExit(4)"), entry("c01", "raise SystemExit(0)")]}
    with mock.patch.object(batch, "state", side_effect=blank_state), \
            mock.patch.object(batch, "cleanup_receipt", return_value={"clean": True}):
        assert batch.execute_queue(queue, "component-only", tmp_path) == 0
    result = json.loads((tmp_path / "batch-result.json").read_text())
    assert [row["waited_exit"] for row in result["members"]] == [4, 0]
    assert result["full_lifecycle_pass"] is None
    assert result["controller_zero_is_not_case_PASS"] is True
    for row in result["members"]:
        with pytest.raises(ChildProcessError):
            os.waitpid(row["launched_process"]["pid"], os.WNOHANG)


def test_cleanup_failure_stops_before_second_member(tmp_path):
    queue = {"cases": [entry("c00", "pass"), entry("c01", "pass")]}
    with mock.patch.object(batch, "state", side_effect=blank_state), \
            mock.patch.object(batch, "cleanup_receipt", return_value={"clean": False}):
        assert batch.execute_queue(queue, "component-only", tmp_path) == 77
    assert not (tmp_path / "c01").exists()
    result = json.loads((tmp_path / "batch-result.json").read_text())
    assert result["cases_not_started"] == 1


def test_timeout_stops_batch_and_waits_child(tmp_path):
    first = entry("c00", "import time; time.sleep(30)")
    first["timeout_seconds"] = .05
    with mock.patch.object(batch, "state", side_effect=blank_state), \
            mock.patch.object(batch, "cleanup_receipt", return_value={"clean": True}):
        assert batch.execute_queue({"cases": [first, entry("c01", "pass")]}, "component-only", tmp_path) == 77
    result = json.loads((tmp_path / "batch-result.json").read_text())
    assert result["members"][0]["timeout"] is True
    assert not (tmp_path / "c01").exists()


def test_cli_refuses_execution_without_controller_identity(tmp_path):
    with mock.patch.object(batch, "load_queue", return_value={"cases": []}):
        with pytest.raises(ValueError, match="admitted nonroot"):
            batch.run_batch(tmp_path / "queue.json", "component-only")


def test_real_output_budget_violation_stops_next_member(tmp_path):
    first = entry("c00", "from pathlib import Path; Path('bounded-test-output').write_bytes(b'x'*4096)")
    queue = {"cases": [first, entry("c01", "pass")], "limits": {"output_bytes": 1024}}
    with mock.patch.object(batch, "state", side_effect=blank_state), \
            mock.patch.object(batch, "cleanup_receipt", return_value={"clean": True}):
        assert batch.execute_queue(queue, "component-only", tmp_path) == 77
    result = json.loads((tmp_path / "batch-result.json").read_text())
    assert any(row["kind"] == "batch_output_limit" for row in result["members"][0]["errors"])
    assert not (tmp_path / "c01").exists()


def original_admission_inputs():
    outside = {key: key + ":[outside]" for key in batch.NAMESPACE_KEYS}
    current = {key: key + ":[private]" for key in batch.NAMESPACE_KEYS}
    # Exact existing immutable configuration schema; uid/namespaces belong
    # to the original candidate receipt, not to this controller configuration.
    config = {"mode": "nonroot", "readonly": ["/mnt/fixtures", "/mnt/artifacts"],
              "outside_namespaces": outside, "nginx_worker_alias": False}
    admission = {"mode": "nonroot", "uid": 65534, "gid": 65534, "namespaces": current}
    status = {key: "0000000000000000" for key in batch.CAPABILITY_FIELDS}
    status["NoNewPrivs"] = "1"
    identity = {"uid": 65534, "gid": 65534, "groups": []}
    return admission, config, status, current, identity


def test_actual_configuration_schema_and_original_receipt_are_both_accepted():
    inputs = original_admission_inputs()
    assert "uid" not in inputs[1]
    assert "namespaces" not in inputs[1]
    batch.check_admission(*inputs)


@pytest.mark.parametrize("unexpected", ["../status", "/proc/self/status", "unknown"])
def test_unknown_namespace_key_is_rejected_before_any_proc_read(unexpected):
    _, config, _, _, _ = original_admission_inputs()
    config["outside_namespaces"][unexpected] = "untrusted"
    with mock.patch.object(batch.os, "readlink") as readlink:
        with pytest.raises(ValueError, match="complete actual namespace set"):
            batch.private_namespaces(config)
    readlink.assert_not_called()


@pytest.mark.parametrize("missing", sorted(batch.NAMESPACE_KEYS))
def test_missing_namespace_key_is_rejected_before_any_proc_read(missing):
    _, config, _, _, _ = original_admission_inputs()
    del config["outside_namespaces"][missing]
    with mock.patch.object(batch.os, "readlink") as readlink:
        with pytest.raises(ValueError, match="complete actual namespace set"):
            batch.private_namespaces(config)
    readlink.assert_not_called()


def test_exact_namespace_keys_use_only_fixed_paths_in_deterministic_order():
    admission, config, status, current, identity = original_admission_inputs()
    with mock.patch.object(batch.os, "readlink", side_effect=lambda path: current[Path(path).name]) as readlink:
        actual = batch.private_namespaces(config)
    assert actual == current
    assert readlink.call_args_list == [mock.call("/proc/self/ns/" + key) for key in sorted(batch.NAMESPACE_KEYS)]
    batch.check_admission(admission, config, status, actual, identity)


@pytest.mark.parametrize("defect", ["outside-shared", "receipt-different", "capability", "privileges", "uid", "groups"])
def test_actual_admission_rejects_shared_namespace_or_wrong_identity(defect):
    admission, config, status, current, identity = original_admission_inputs()
    if defect == "outside-shared":
        config["outside_namespaces"]["net"] = current["net"]
    elif defect == "receipt-different":
        admission["namespaces"] = dict(current, pid="pid:[different]")
    elif defect == "capability":
        status["CapEff"] = "0000000000000001"
    elif defect == "privileges":
        status["NoNewPrivs"] = "0"
    elif defect == "uid":
        identity["uid"] = 0
    else:
        identity["groups"] = [65534]
    with pytest.raises(ValueError):
        batch.check_admission(admission, config, status, current, identity)


def test_proc_identity_race_still_waits_real_child(tmp_path):
    member = entry("c00", "raise SystemExit(3)")
    workspace = tmp_path / "c00"
    workspace.mkdir()
    with mock.patch.object(batch, "state", side_effect=blank_state), \
            mock.patch.object(batch, "cleanup_receipt", return_value={"clean": True}), \
            mock.patch.object(batch, "process_record", side_effect=FileNotFoundError("controlled proc race")):
        actual = batch.run_member(member, workspace)
    assert actual["waited_exit"] == 3
    assert actual["launched_process"]["starttime"] is None
    assert {row["kind"] for row in actual["errors"]} == {"driver_process_identity_unknown"}
    with pytest.raises(ChildProcessError):
        os.waitpid(actual["launched_process"]["pid"], os.WNOHANG)


def test_home_is_inherited_without_reassignment(tmp_path):
    member = entry("c00", "pass")
    workspace = tmp_path / "c00"
    workspace.mkdir()
    original_popen = subprocess.Popen
    inherited_home = os.environ.get("HOME")
    with mock.patch.object(batch, "state", side_effect=blank_state), \
            mock.patch.object(batch, "cleanup_receipt", return_value={"clean": True}), \
            mock.patch.object(batch.subprocess, "Popen", wraps=original_popen) as launched:
        assert batch.run_member(member, workspace)["waited_exit"] == 0
    actual_home = launched.call_args.kwargs["env"].get("HOME")
    assert actual_home == inherited_home
    assert not (workspace / "home").exists()


def test_actual_time_wait_rows_are_retained_separately():
    listener = socket.socket()
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        peer_port = listener.getsockname()[1]
        client = socket.create_connection(listener.getsockname())
        accepted, _ = listener.accept()
        local_port = client.getsockname()[1]
        client.close()
        assert accepted.recv(1) == b""
        accepted.close()
    finally:
        listener.close()
    captured = batch.socket_tables()
    markers = (f"0100007F:{local_port:04X}", f"0100007F:{peer_port:04X}")
    actual = [row for row in captured["tcp_time_wait"].values()
              if all(marker in row["raw"] for marker in markers)]
    assert actual
    assert all(row["raw"].split()[3] == "06" for row in actual)
    assert not any(all(marker in row["raw"] for marker in markers)
                   for row in captured["live"].values())

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
