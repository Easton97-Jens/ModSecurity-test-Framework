#!/usr/bin/env python3
"""Allocate disjoint loopback port ranges for full-matrix runtime jobs.

The connector smoke harnesses select a free listener from a bounded range.
Their secondary listeners are offset from the primary one, so the matrix
runner must reserve the *whole possible range* before it executes jobs in
parallel.  This module is deliberately dependency-free so the shell runner
can validate the plan before starting any build or runtime command.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import sys
from typing import Iterable


# 1024 is the first unprivileged TCP port.  The full twelve-job matrix needs
# the complete unprivileged range once every two-stage listener search window
# is reserved; the planner fails closed if the requested tuple set cannot fit.
MIN_PORT = 1024
MAX_PORT = 65000
CONNECTORS = frozenset(("apache", "nginx", "haproxy"))


class PortPlanError(ValueError):
    """A requested matrix cannot receive safe, disjoint listener ranges."""


@dataclass(frozen=True)
class MatrixJob:
    variant: str
    connector: str
    case_count: int

    @property
    def identifier(self) -> str:
        return f"{self.variant}:{self.connector}"


@dataclass(frozen=True)
class PortInterval:
    start: int
    end: int
    job: str
    listener: str

    def overlaps(self, other: "PortInterval") -> bool:
        return self.start <= other.end and other.start <= self.end


def positive_decimal(value: str, *, label: str) -> int:
    if not value.isdecimal() or int(value) <= 0:
        raise PortPlanError(f"{label} must be a positive decimal integer: {value!r}")
    return int(value)


def nonnegative_decimal(value: str, *, label: str) -> int:
    if not value.isdecimal():
        raise PortPlanError(f"{label} must be a non-negative decimal integer: {value!r}")
    return int(value)


def parse_case_count(value: str) -> tuple[str, int]:
    try:
        connector, count = value.split("=", 1)
    except ValueError as exc:
        raise PortPlanError(f"invalid --case-count value: {value!r}") from exc
    if connector not in CONNECTORS:
        raise PortPlanError(f"unsupported connector in --case-count: {connector!r}")
    return connector, positive_decimal(count, label=f"case count for {connector}")


def parse_job(value: str, case_counts: dict[str, int]) -> MatrixJob:
    try:
        variant, connector = value.rsplit(":", 1)
    except ValueError as exc:
        raise PortPlanError(f"invalid --job value: {value!r}") from exc
    if not variant or "/" not in variant:
        raise PortPlanError(f"invalid matrix variant in --job: {value!r}")
    if connector not in CONNECTORS:
        raise PortPlanError(f"unsupported connector in --job: {connector!r}")
    try:
        return MatrixJob(variant=variant, connector=connector, case_count=case_counts[connector])
    except KeyError as exc:
        raise PortPlanError(f"missing --case-count for connector: {connector}") from exc


def listener_offsets(
    job: MatrixJob,
    *,
    haproxy_spoa_offset: int,
    haproxy_backend_offset: int,
) -> tuple[tuple[str, int], ...]:
    offsets: list[tuple[str, int]] = [("frontend", 0)]
    if job.connector in {"apache", "nginx"}:
        offsets.append(("response-header-backend", 1000))
    else:
        offsets.extend(
            (
                ("spoa", haproxy_spoa_offset),
                ("backend", haproxy_backend_offset),
            )
        )
    return tuple(offsets)


def validate_same_case_offsets(offsets: Iterable[tuple[str, int]], span: int, *, job: MatrixJob) -> None:
    ordered = sorted(offsets, key=lambda item: item[1])
    for (left_name, left_offset), (right_name, right_offset) in zip(ordered, ordered[1:]):
        if left_offset + span > right_offset:
            raise PortPlanError(
                f"{job.connector} listener offsets overlap for a single case: "
                f"{left_name}={left_offset}, {right_name}={right_offset}, span={span}"
            )


def intervals_for(
    job: MatrixJob,
    base_port: int,
    *,
    span: int,
    haproxy_spoa_offset: int,
    haproxy_backend_offset: int,
) -> tuple[PortInterval, ...]:
    # Every case advances the primary base by its zero-based case index.  A
    # secondary listener starts from the selected primary listener and can
    # then probe another full span, so reserve both selector windows across
    # the selected case sequence.  This intentionally over-reserves the
    # primary-only interval as well, keeping the cross-job proof simple.
    width = job.case_count + (2 * span) - 2
    offsets = listener_offsets(
        job,
        haproxy_spoa_offset=haproxy_spoa_offset,
        haproxy_backend_offset=haproxy_backend_offset,
    )
    validate_same_case_offsets(offsets, span, job=job)
    return tuple(
        PortInterval(
            start=base_port + offset,
            end=base_port + offset + width - 1,
            job=job.identifier,
            listener=listener,
        )
        for listener, offset in offsets
    )


def ensure_unique_jobs(jobs: Iterable[MatrixJob]) -> None:
    seen: set[str] = set()
    for job in jobs:
        if job.identifier in seen:
            raise PortPlanError(f"duplicate matrix job: {job.identifier}")
        seen.add(job.identifier)


def ordered_jobs(
    jobs: Iterable[MatrixJob],
    *,
    haproxy_spoa_offset: int,
    haproxy_backend_offset: int,
) -> list[MatrixJob]:
    # Place the least flexible jobs first. HAProxy has three listener banks,
    # whereas Apache and NGINX have two.
    return sorted(
        jobs,
        key=lambda job: (
            -len(
                listener_offsets(
                    job,
                    haproxy_spoa_offset=haproxy_spoa_offset,
                    haproxy_backend_offset=haproxy_backend_offset,
                )
            ),
            job.identifier,
        ),
    )


def allocate_job_port(
    job: MatrixJob,
    allocated: list[PortInterval],
    *,
    span: int,
    haproxy_spoa_offset: int,
    haproxy_backend_offset: int,
) -> int:
    for base_port in range(MIN_PORT, MAX_PORT + 1):
        intervals = intervals_for(
            job,
            base_port,
            span=span,
            haproxy_spoa_offset=haproxy_spoa_offset,
            haproxy_backend_offset=haproxy_backend_offset,
        )
        if any(interval.start < MIN_PORT or interval.end > MAX_PORT for interval in intervals):
            # Offsets are non-negative, so later candidates cannot fit.
            break
        if any(candidate.overlaps(existing) for candidate in intervals for existing in allocated):
            continue
        allocated.extend(intervals)
        return base_port
    raise PortPlanError(f"no safe port range is available for {job.identifier}")


def plan_ports(
    jobs: tuple[MatrixJob, ...],
    *,
    span: int,
    haproxy_spoa_offset: int,
    haproxy_backend_offset: int,
) -> dict[str, int]:
    ensure_unique_jobs(jobs)
    ordered = ordered_jobs(
        jobs,
        haproxy_spoa_offset=haproxy_spoa_offset,
        haproxy_backend_offset=haproxy_backend_offset,
    )
    allocated: list[PortInterval] = []
    result: dict[str, int] = {}
    for job in ordered:
        result[job.identifier] = allocate_job_port(
            job,
            allocated,
            span=span,
            haproxy_spoa_offset=haproxy_spoa_offset,
            haproxy_backend_offset=haproxy_backend_offset,
        )
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--port-span", required=True)
    result.add_argument("--haproxy-spoa-offset", required=True)
    result.add_argument("--haproxy-backend-offset", required=True)
    result.add_argument("--case-count", action="append", default=[])
    result.add_argument("--job", action="append", default=[])
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        span = positive_decimal(args.port_span, label="port span")
        haproxy_spoa_offset = nonnegative_decimal(
            args.haproxy_spoa_offset,
            label="HAProxy SPOA offset",
        )
        haproxy_backend_offset = nonnegative_decimal(
            args.haproxy_backend_offset,
            label="HAProxy backend offset",
        )
        case_counts = dict(parse_case_count(value) for value in args.case_count)
        jobs = tuple(parse_job(value, case_counts) for value in args.job)
        if not jobs:
            raise PortPlanError("at least one --job is required")
        planned = plan_ports(
            jobs,
            span=span,
            haproxy_spoa_offset=haproxy_spoa_offset,
            haproxy_backend_offset=haproxy_backend_offset,
        )
    except PortPlanError as exc:
        print(f"ERROR: full-matrix port plan: {exc}", file=sys.stderr)
        return 2

    for job in jobs:
        print(f"{job.variant}\t{job.connector}\t{planned[job.identifier]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
