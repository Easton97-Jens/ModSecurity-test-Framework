"""Pure verification of the bounded Go external-link FIPS transition."""

import hashlib
from pathlib import Path
import struct


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fips_section(before):
    table = struct.unpack_from("<Q", before, 40)[0]
    entry_size, count, names_index = struct.unpack_from("<HHH", before, 58)
    if entry_size != 64 or not 0 < count <= 65535 or names_index >= count or table + count * 64 > len(before):
        raise ValueError("Go link transition has an invalid ELF section table")
    rows = [struct.unpack_from("<IIQQQQIIQQ", before, table + index * 64) for index in range(count)]
    names = rows[names_index]
    if names[4] + names[5] > len(before):
        raise ValueError("Go link transition has an invalid ELF string table")
    strings = before[names[4]:names[4] + names[5]]
    matches = []
    for row in rows:
        if row[0] >= len(strings) or b"\0" not in strings[row[0]:]:
            raise ValueError("Go link transition has an invalid section name")
        name = strings[row[0]:strings.index(b"\0", row[0])]
        if name == b".go.fipsinfo":
            matches.append(row)
    if len(matches) != 1:
        raise ValueError("Go link transition requires exactly one FIPS metadata section")
    return matches[0]


def verify_fips_transition(raw, finalized):
    """Permit only Go's documented 32-byte FIPS checksum slot to change.

    This validates byte boundaries only; the actual approved Go linker computes
    the checksum. No FIPS field is masked, rewritten or independently computed.
    """
    before = Path(raw).read_bytes()
    after = Path(finalized).read_bytes()
    if len(before) != len(after) or before[:6] != b"\x7fELF\x02\x01" or len(before) < 64:
        raise ValueError("Go link transition requires equal-size little-endian ELF64")
    row = fips_section(before)
    start = row[4] + 16
    end = start + 32
    if row[5] != 120 or end > len(before) or before[row[4]:start] != b"\xff Go fipsinfo \xff\0":
        raise ValueError("Go FIPS metadata layout differs from the approved toolchain")
    if before[:start] != after[:start] or before[end:] != after[end:]:
        raise ValueError("unexpected bytes changed outside Go FIPS checksum slot")
    if before[start:end] != bytes(32) or after[start:end] == bytes(32):
        raise ValueError("Go FIPS finalization did not replace the initial empty checksum")
    return {"offset": start, "length": 32, "raw_sha256": digest(raw), "finalized_sha256": digest(finalized)}


def verify_go_producer(chain, checkout, records):
    version = "go" + (checkout / ".go-version").read_text().strip()
    goroot = Path(chain["goroot"])
    go = Path(chain["go_executable"])
    if chain["go_version"] != version or go != goroot / "bin/go" or digest(go) != chain["go_sha256"]:
        raise ValueError("Go producer chain toolchain differs from approved Parent identity")
    required_sources = {str(goroot / name) for name in (
        "src/cmd/link/internal/ld/fips140.go", "src/cmd/go/internal/work/buildid.go",
        "src/cmd/buildid/buildid.go", "src/cmd/internal/buildid/rewrite.go")}
    if set(chain["go_sources"]) != required_sources:
        raise ValueError("Go producer chain lacks its exact postlink source identities")
    for name, expected in chain["go_sources"].items():
        if digest(name) != expected:
            raise ValueError("Go producer implementation changed")
    link = chain["go_link"]
    tool = Path(link["arguments"][0])
    if (link not in records or link["kind"] != "go-tool-link" or tool.name != "link"
            or not tool.is_relative_to(goroot / "pkg/tool") or digest(tool) != link["tool_sha256"]
            or digest(link["retained_output"]) != link["output_sha256"]):
        raise ValueError("Go producer chain lacks its actual unmodified linker execution")
    return go, link


def verify_buildid_replay(chain, artifact, go):
    replay = Path(chain["buildid_replay"])
    if chain["buildid_replay_arguments"] != [str(go), "tool", "buildid", "-w", str(replay)]:
        raise ValueError("Go producer chain does not use the official buildid replay")
    if (chain["published_artifact"] != str(artifact) or digest(artifact) != chain["published_sha256"]
            or digest(replay) != chain["buildid_replay_sha256"]
            or chain["buildid_replay_sha256"] != chain["published_sha256"]):
        raise ValueError("Go producer replay differs from the final published artifact")


def verify_object_aliases(chain, checkout, records, raw):
    for name, alias in chain["object_aliases"].items():
        matches = [record for record in records if record["kind"] == "compile"
                   and record["output"] == alias["producer"] and record["output_sha256"] == alias["sha256"]]
        if (len(matches) != 1 or raw["inputs"].get(name) != alias["sha256"]
                or alias["producer"] == name or alias["producer"] in chain["object_aliases"]
                or digest(name) != alias["sha256"] or digest(alias["producer"]) != alias["sha256"]
                or not all(Path(source).is_relative_to(checkout) for source in matches[0]["sources"])):
            raise ValueError("Go object alias is not the identical actual Parent compiler output")


def verify_external_go_inputs(chain, checkout, raw):
    work = Path(chain["go_work_root"])
    if not work.is_absolute() or not work.is_dir() or work.is_relative_to(checkout):
        raise ValueError("Go producer work context must remain external and durable")
    for name, expected in chain["external_go_inputs"].items():
        if (not Path(name).is_relative_to(work) or raw["inputs"].get(name) != expected
                or digest(name) != expected):
            raise ValueError("unadmitted Go-generated native object")


def verify_chain(chain, checkout, artifact, records):
    """Validate actual captured producer identities and the replayed final bytes."""
    go, link = verify_go_producer(chain, checkout, records)
    raw_records = [record for record in records if record["kind"] == "link"
                   and record["output"] == chain["raw_link_output"]
                   and record["output_sha256"] == chain["raw_link_sha256"]]
    if len(raw_records) != 1 or link["output"] != chain["raw_link_output"]:
        raise ValueError("Go producer chain lacks its real native link")
    raw = raw_records[0]
    if (raw["retained_files"].get(raw["output"]) != chain["retained_raw_link"]
            or digest(chain["retained_raw_link"]) != chain["raw_link_sha256"]):
        raise ValueError("Go producer chain raw native output changed")
    transition = verify_fips_transition(chain["retained_raw_link"], link["retained_output"])
    if transition != chain["fips_transition"]:
        raise ValueError("Go producer chain FIPS transition receipt changed")
    verify_buildid_replay(chain, artifact, go)
    verify_external_go_inputs(chain, checkout, raw)
    verify_object_aliases(chain, checkout, records, raw)
    for record in chain["external_context_compilations"]:
        if (record not in records or record["kind"] != "compile"
                or any(Path(source).is_relative_to(checkout) for source in record["sources"])
                or record["output_sha256"] not in chain["external_go_inputs"].values()):
            raise ValueError("Parent source cannot be hidden in Go-generated context")
    return raw
