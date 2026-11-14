"""Framework offline contracts; never imported by the protected Parent publisher."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re

REPOSITORY = "Easton97-Jens/ModSecurity-test-Framework"
ACTION_PATH = ".github/actions/sonar-private"
COMMIT = "9ae8ecc4f686e9cc70413e5494bc098a24eb18d7"
REFERENCE = f"{REPOSITORY}/{ACTION_PATH}@{COMMIT}"
METADATA_SHA256 = "2f8f446c1ec1fe765060fdadb54c854f29f474f4eb0091e2001e43d6e6474229"
MAIN_SHA256 = "3865be06f1ccfaf2c2757b0fc29bfd0ae0c0a0374aec9f09342292402d592a1b"
UPSTREAM = "SonarSource/sonarqube-scan-action@e805d875275f728fac1885b413934be6d7c63f65"
SCANNER_VERSION = "8.2.0.6438"
REVISION = "${{ github.event.pull_request.head.sha || github.sha }}"
NATIVE_INCLUDES = "${{ steps.native-context.outputs.includes }},/usr/include,/usr/include/apache2,/usr/include/apr-1.0"


def canonical_role(values: dict[str, str]) -> str:
    expected = {"REPOSITORY": REPOSITORY, "ACTION_PATH": ACTION_PATH, "COMMIT": COMMIT}
    if any(values.get("CI_SONAR_DIAGNOSTIC_" + key) != value for key, value in expected.items()):
        raise ValueError("private Sonar role differs from the reviewed immutable source")
    return REFERENCE


def scanner_step(owner: str, upstream: str = UPSTREAM, *, wrapped: bool = True) -> dict:
    """Return complete approved mappings, without permissive overlays."""
    if re.fullmatch(r"SonarSource/sonarqube-scan-action@[a-f0-9]{40}", upstream) is None:
        raise ValueError("private Sonar upstream must be an exact official action")
    if owner == "framework":
        result = {"name": "Analyze maintained languages and wait for the Quality Gate",
                  "env": {"SONAR_TOKEN": "${{ secrets.SONAR_TOKEN }}",
                          "SONAR_USER_HOME": "${{ runner.temp }}/framework-sonar-cache"}}
        args = (f"-Dsonar.scm.revision={REVISION} "
                "-Dsonar.working.directory=${{ runner.temp }}/framework-sonar-work "
                "-Dsonar.cfamily.compile-commands=${{ runner.temp }}/framework-sonar-native/compile_commands.json")
        mode = "framework"
    elif owner == "parent":
        result = {"name": "Analyze exact revision and await Quality Gate", "id": "scan",
                  "env": {"SONAR_TOKEN": "${{ secrets.SONAR_TOKEN }}"}}
        args = ("-Dsonar.projectKey=${{ matrix.project }} "
                "-Dsonar.cfamily.reportingCppStandardOverride=c++${{ matrix.cpp }} "
                f"-Dsonar.scm.revision={REVISION} "
                "-Dsonar.working.directory=${{ runner.temp }}/sonar-work "
                f"-Dsonar.cfamily.customCIncludes={NATIVE_INCLUDES} "
                f"-Dsonar.cfamily.customCppIncludes={NATIVE_INCLUDES} "
                "-Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=600")
        mode = "parent-cpp${{ matrix.cpp }}"
    else:
        raise ValueError("unknown private Sonar owner")
    result["uses"] = REFERENCE if wrapped else upstream
    result["with"] = {"scannerVersion": SCANNER_VERSION, "args": args}
    if wrapped:
        result["with"].update({"owner-mode": mode, "upstream-action": upstream})
    return result


def scanner_allowed(step: dict, owner: str, upstream: str = UPSTREAM) -> bool:
    return any(step == scanner_step(owner, upstream, wrapped=wrapped) for wrapped in (False, True))


def validate_frozen_metadata(root: Path, relative: str, read_source) -> None:
    if relative != ACTION_PATH + "/action.yml":
        raise ValueError("unknown private Sonar metadata path")
    text = read_source(root, relative)
    from .workflow_sources import _read
    main = _read(root, ACTION_PATH + "/main.cjs")
    if (sha256(text.encode()).hexdigest() != METADATA_SHA256
            or sha256(main.encode()).hexdigest() != MAIN_SHA256):
        raise ValueError("private Sonar metadata or implementation differs from frozen review")
