#!/usr/bin/env python3
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

SCENARIOS = [
    ("postgres-multi-replica", "postgres_multi_replica", 480, 20_000),
    ("postgres-tenant-canaries", "postgres_quota_process", 480, 15_000),
    ("postgres-callback-recovery", "postgres_push_process", 600, 20_000),
    ("postgres-artifact-recovery", "postgres_artifact_process", 600, 90_000),
    ("postgres-observability-recovery", "postgres_observability_process", 480, 20_000),
]


def atomic_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run_scenario(identifier, target, watchdog_seconds, rto_target_millis):
    command = [
        "cargo", "test", "--locked", "--test", target, "--", "--test-threads=1"
    ]
    started = time.monotonic()
    process = subprocess.Popen(command, start_new_session=True)
    status = "pass"
    try:
        return_code = process.wait(timeout=watchdog_seconds)
        if return_code != 0:
            status = "fail"
    except subprocess.TimeoutExpired:
        status = "timeout"
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=15)
    elapsed_millis = int((time.monotonic() - started) * 1000)
    return {
        "id": identifier,
        "status": status,
        "elapsedMillis": elapsed_millis,
        "commandWatchdogMillis": watchdog_seconds * 1000,
        "rtoTargetMillis": rto_target_millis,
    }


def scalar_query(sql):
    url = os.environ["SMESH_TEST_POSTGRES_SUPERUSER_URL"]
    result = subprocess.run(
        ["psql", url, "-At", "-v", "ON_ERROR_STOP=1", "-c", sql],
        check=True,
        text=True,
        capture_output=True,
        timeout=30,
    )
    return int(result.stdout.strip())


def main():
    output = Path("target/hostile-load/postgres-process.json")
    report = {
        "schemaVersion": "smesh.chaos-matrix-result/1",
        "backend": "postgres",
        "profile": "scheduled",
        "scenarios": [],
        "cleanup": {"schemas": -1, "sessions": -1},
        "verdict": "fail",
        "limitations": [
            "RTO targets are enforced by each scenario's internal deterministic watchdogs"
        ],
    }
    atomic_write(output, report)
    failed = False
    for scenario in SCENARIOS:
        result = run_scenario(*scenario)
        report["scenarios"].append(result)
        failed = failed or result["status"] != "pass"
        atomic_write(output, report)
        if failed:
            break

    try:
        report["cleanup"] = {
            "schemas": scalar_query(
                "SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'smesh_%'"
            ),
            "sessions": scalar_query(
                "SELECT count(*) FROM pg_stat_activity WHERE usename IN ('smesh_migrator','smesh_test_runtime') AND pid <> pg_backend_pid()"
            ),
        }
    except (KeyError, ValueError, subprocess.SubprocessError):
        failed = True
    failed = failed or report["cleanup"] != {"schemas": 0, "sessions": 0}
    failed = failed or len(report["scenarios"]) != len(SCENARIOS)
    report["verdict"] = "fail" if failed else "pass"
    atomic_write(output, report)
    print(f"PostgreSQL chaos matrix: {report['verdict']} ({len(report['scenarios'])}/{len(SCENARIOS)})")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
