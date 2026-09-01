#!/usr/bin/env python3
import json
import sys
from pathlib import Path

EXPECTED_IDS = [
    "postgres-multi-replica",
    "postgres-tenant-canaries",
    "postgres-callback-recovery",
    "postgres-artifact-recovery",
    "postgres-observability-recovery",
]
ROOT_KEYS = {"schemaVersion", "backend", "profile", "scenarios", "cleanup", "verdict", "limitations"}
SCENARIO_KEYS = {"id", "status", "elapsedMillis", "commandWatchdogMillis", "rtoTargetMillis"}


def validate(report):
    if not isinstance(report, dict) or set(report) != ROOT_KEYS:
        raise ValueError("invalid root fields")
    if report["schemaVersion"] != "smesh.chaos-matrix-result/1":
        raise ValueError("unsupported schemaVersion")
    if report["backend"] != "postgres" or report["profile"] != "scheduled":
        raise ValueError("invalid report scope")
    if report["verdict"] != "pass":
        raise ValueError("matrix verdict is not pass")
    scenarios = report["scenarios"]
    if not isinstance(scenarios, list) or [item.get("id") for item in scenarios] != EXPECTED_IDS:
        raise ValueError("scenario set or order differs")
    for scenario in scenarios:
        if set(scenario) != SCENARIO_KEYS or scenario["status"] != "pass":
            raise ValueError("scenario did not pass")
        for key in ("elapsedMillis", "commandWatchdogMillis", "rtoTargetMillis"):
            value = scenario[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"invalid scenario metric {key}")
        if scenario["elapsedMillis"] > scenario["commandWatchdogMillis"]:
            raise ValueError("scenario exceeded command watchdog")
        if not 0 < scenario["rtoTargetMillis"] <= 90_000:
            raise ValueError("invalid RTO target")
    if report["cleanup"] != {"schemas": 0, "sessions": 0}:
        raise ValueError("PostgreSQL cleanup failed")
    if not isinstance(report["limitations"], list) or not report["limitations"]:
        raise ValueError("limitations are required")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_postgres_chaos_evidence.py REPORT.json")
    path = Path(sys.argv[1])
    report = json.loads(path.read_text(encoding="utf-8"))
    validate(report)
    print(f"validated {path}: {report['verdict']}")


if __name__ == "__main__":
    main()
