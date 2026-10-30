"""Read evidence only inside roots selected by the invoking application.

Evidence content cannot extend this immutable allowlist. Every path component is
opened without following links; the final descriptor must be a regular file.
"""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Iterator, Any, Callable


class EvidenceInputs:
    def __init__(self, roots: Iterable[Path | str], *, files: Iterable[Path | str] = ()) -> None:
        self.roots = tuple(self._absolute(value) for value in roots)
        self.files = tuple(self._absolute(value) for value in files)
        if any(root == Path(root.anchor) for root in self.roots):
            raise ValueError("an evidence root must not authorize the entire filesystem")

    @staticmethod
    def _absolute(value: Path | str) -> Path:
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts or "\0" in str(path):
            raise ValueError("evidence paths must be absolute and contain no parent traversal")
        return path

    def path(self, value: Path | str) -> Path:
        path = self._absolute(value)
        if path not in self.files and not any(path.is_relative_to(root) for root in self.roots):
            raise ValueError("evidence path is outside the configured input roots")
        return path

    @contextmanager
    def _descriptor(self, value: Path | str, *, directory_target: bool = False) -> Iterator[int]:
        path = self.path(value)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            raise ValueError("safe evidence reads require O_NOFOLLOW and O_DIRECTORY")
        flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
        parent = os.open(path.anchor, flags | directory)
        descriptor = -1
        try:
            for component in path.parts[1:-1]:
                child = os.open(component, flags | directory, dir_fd=parent)
                os.close(parent)
                parent = child
            descriptor = os.open(path.name, flags | (directory if directory_target else 0)
                                 | getattr(os, "O_NONBLOCK", 0), dir_fd=parent)
            mode = os.fstat(descriptor).st_mode
            if not (stat.S_ISDIR(mode) if directory_target else stat.S_ISREG(mode)):
                raise ValueError("evidence must be a regular file or selected directory")
            yield descriptor
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent)

    def read_bytes(self, value: Path | str) -> bytes:
        with self._descriptor(value) as descriptor:
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 1024 * 1024):
                chunks.append(chunk)
            return b"".join(chunks)

    def read_text(self, value: Path | str, *, errors: str = "replace") -> str:
        return self.read_bytes(value).decode("utf-8", errors=errors)

    def stat(self, value: Path | str) -> os.stat_result:
        with self._descriptor(value) as descriptor:
            return os.fstat(descriptor)

    def is_file(self, value: Path | str) -> bool:
        try:
            self.stat(value)
        except (OSError, ValueError):
            return False
        return True

    def is_dir(self, value: Path | str) -> bool:
        try:
            with self._descriptor(value, directory_target=True):
                return True
        except (OSError, ValueError):
            return False

    def file_proof(self, value: Path | str) -> tuple[str, int]:
        with self._descriptor(value) as descriptor:
            digest = hashlib.sha256()
            size = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
            return digest.hexdigest(), size

    def _input_record(self, path: Path, connector_root: Path) -> tuple[dict[str, Any], bytes]:
        shown = str(path.relative_to(connector_root)) if path.is_relative_to(connector_root) else str(path)
        try:
            content = self.read_bytes(path)
        except FileNotFoundError:
            return {"path": shown, "status": "missing", "notes": "input file missing"}, b""
        except (OSError, ValueError):
            return {"path": shown, "status": "blocked", "notes": "input path rejected by configured evidence boundary"}, b""
        digest = hashlib.sha256(content).hexdigest()
        return {"path": shown, "status": "present" if content else "empty",
                "sha256": digest, "source_hash": digest,
                "notes": "input file available" if content else "input file exists but is empty"}, content

    @staticmethod
    def _json_receipt(content: bytes) -> tuple[dict[str, Any], str]:
        try:
            data = json.loads(content)
        except ValueError:
            return {}, ""
        if not isinstance(data, dict):
            return {}, ""
        candidate = data.get("metadata")
        metadata = candidate if isinstance(candidate, dict) else {}
        return metadata, str(data.get("status") or metadata.get("run_status") or "")

    @staticmethod
    def _markdown_receipt(content: bytes) -> dict[str, Any]:
        labels = (("Verified run id:", "verified_run_id"), ("Connector SHA:", "connector_sha"),
                  ("Framework SHA:", "framework_sha"), ("Framework gitlink SHA:", "framework_gitlink_sha"),
                  ("Framework checkout:", "framework_checkout_status"), ("Framework gitlink status:", "framework_gitlink_status"))
        metadata: dict[str, Any] = {}
        for line in content.decode("utf-8", errors="replace").splitlines()[:30]:
            for label, field in labels:
                if label in line.strip():
                    metadata[field] = line.strip().split(label, 1)[1].strip().strip("` ")
                    break
        return metadata

    @staticmethod
    def _apply_source_receipt(record: dict[str, Any], path: Path, content: bytes,
                              metadata: dict[str, Any], connector_root: Path,
                              framework_root: Path, policy: Any) -> None:
        source_metadata: dict[str, Any] = {}
        source_status = ""
        if path.suffix == ".json":
            source_metadata, source_status = EvidenceInputs._json_receipt(content)
        elif path.suffix == ".md":
            source_metadata = EvidenceInputs._markdown_receipt(content)
        provenance = policy._report_provenance(source_metadata)
        record.update(provenance)
        reasons = policy._report_staleness_reasons(
            provenance, str(metadata.get("verified_run_id") or ""), connector_root, framework_root)
        if reasons:
            record.update(status="stale", notes="generated report input is stale: " + "; ".join(reasons))
        elif not provenance.get("verified_run_id"):
            record.update(status="stale", notes="generated report input has no verified_run_id")
        elif source_status and policy._unusable_source_status(source_status):
            record.update(status="blocked" if source_status.startswith("blocked") else source_status,
                          notes=f"generated report input is not usable: status={source_status}")

    def build_metadata(self, builder: Callable[..., dict[str, Any]], *,
                       inputs: Iterable[Path | str], **arguments: Any) -> dict[str, Any]:
        """Build normal provenance from confined bytes without reopening inputs.

        The existing metadata policy still decides generated-report staleness.
        Only input acquisition changes: hashes and embedded provenance use the
        same bytes obtained through the no-follow descriptor boundary.
        """
        import modsecurity_connector_ci.lib.generated_report_utils as policy

        metadata = builder(inputs=(), **arguments)
        connector_root = Path(arguments["connector_root"])
        framework_root = arguments.get("framework_root") or connector_root / "modules/ModSecurity-test-Framework"
        records = []
        for raw in inputs:
            path = Path(raw)
            record, content = self._input_record(path, connector_root)
            if content and path.name in policy.FILENAME_TO_KEY:
                self._apply_source_receipt(record, path, content, metadata,
                                           connector_root, framework_root, policy)
            records.append(record)
        metadata["inputs"] = records
        metadata["input_status"] = policy.input_status_summary(records)
        for status in ("missing", "empty", "unknown"):
            metadata[f"{status}_inputs"] = [record["path"] for record in records if record["status"] == status]
        return metadata

    def json(self, value: Path | str) -> dict[str, Any]:
        try:
            result = json.loads(self.read_text(value))
        except (OSError, ValueError):
            return {}
        return result if isinstance(result, dict) else {}

    def jsonl(self, value: Path | str) -> list[dict[str, Any]]:
        try:
            text = self.read_text(value)
        except (OSError, ValueError):
            return []
        rows = []
        for line in text.splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                rows.append(value)
        return rows
