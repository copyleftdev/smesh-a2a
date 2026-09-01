#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT_KEYS = {
    "schemaVersion", "backend", "profile", "workload", "epochs", "latencyMillis", "rssBytes",
    "fileDescriptors", "databaseBytes", "network", "recovery", "cleanup", "verdict", "limitations",
}


def exact_keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} keys differ: {sorted(value) if isinstance(value, dict) else type(value)}")


def nonnegative(value, label):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")


def validate(report):
    exact_keys(report, ROOT_KEYS, "root")
    if report["schemaVersion"] != "smesh.hostile-load-evidence/1":
        raise ValueError("unsupported schemaVersion")
    if report["backend"] not in {"sqlite", "postgres"}:
        raise ValueError("invalid backend")
    if report["profile"] not in {"stable", "sustained"}:
        raise ValueError("invalid profile")
    if report["verdict"] != "pass":
        raise ValueError("evidence verdict is not pass")

    groups = {
        "workload": {"offenders", "canaries", "slowConsumers"},
        "latencyMillis": {"p95", "max"},
        "rssBytes": {"baseline", "peak", "final"},
        "fileDescriptors": {"baseline", "peak", "final"},
        "databaseBytes": {"baseline", "final"},
    }
    for name, keys in groups.items():
        exact_keys(report[name], keys, name)
        for key, value in report[name].items():
            nonnegative(value, f"{name}.{key}")

    latency = report["latencyMillis"]
    if latency["p95"] > 500 or latency["max"] > 1_000 or latency["p95"] > latency["max"]:
        raise ValueError("latency threshold failed")
    rss = report["rssBytes"]
    if rss["peak"] > 256 * 1024 * 1024 or rss["peak"] > rss["baseline"] + 64 * 1024 * 1024:
        raise ValueError("RSS threshold failed")
    if rss["final"] > rss["baseline"] + 64 * 1024 * 1024:
        raise ValueError("final RSS threshold failed")
    fds = report["fileDescriptors"]
    workload = report["workload"]
    synchronized_bound = workload["offenders"] // 3 + workload["canaries"] // 3 + workload["slowConsumers"] + 16
    if fds["peak"] > fds["baseline"] + synchronized_bound or fds["final"] > fds["baseline"] + 8:
        raise ValueError("file descriptor threshold failed")
    database = report["databaseBytes"]
    if database["final"] > database["baseline"] + 2 * 1024 * 1024:
        raise ValueError("database growth threshold failed")
    epochs = report["epochs"]
    if not isinstance(epochs, list) or len(epochs) != 3:
        raise ValueError("exactly three measured epochs are required")
    for index, epoch in enumerate(epochs):
        exact_keys(epoch, {"index", "rssPeak", "rssGrowthFromPrevious", "fdPeak", "canaryP95Millis", "canaryMaxMillis"}, f"epoch[{index}]")
        if epoch["index"] != index:
            raise ValueError("epoch index mismatch")
        for key, value in epoch.items():
            nonnegative(value, f"epoch[{index}].{key}")
        if epoch["rssPeak"] > 256 * 1024 * 1024 or epoch["canaryP95Millis"] > 500 or epoch["canaryMaxMillis"] > 1_000:
            raise ValueError("epoch threshold failed")
        expected_growth = 0 if index == 0 else max(0, epoch["rssPeak"] - epochs[index - 1]["rssPeak"])
        if epoch["rssGrowthFromPrevious"] != expected_growth:
            raise ValueError("epoch RSS growth derivation mismatch")
    if epochs[2]["rssPeak"] > epochs[1]["rssPeak"] + 16 * 1024 * 1024:
        raise ValueError("late epoch RSS plateau failed")

    exact_keys(report["network"], {"blackholeObserved", "healthyDuringFault", "recovered"}, "network")
    if set(report["network"].values()) != {True}:
        raise ValueError("network qualification is incomplete")
    exact_keys(
        report["recovery"],
        {"signal", "acknowledged", "recovered", "rpoLost", "readinessMillis", "firstCanaryMillis"},
        "recovery",
    )
    recovery = report["recovery"]
    if recovery["signal"] != "SIGKILL" or recovery["rpoLost"] != 0:
        raise ValueError("recovery RPO qualification is incomplete")
    for key in ("acknowledged", "recovered", "rpoLost", "readinessMillis", "firstCanaryMillis"):
        nonnegative(recovery[key], f"recovery.{key}")
    if recovery["acknowledged"] != recovery["recovered"]:
        raise ValueError("acknowledged recovery count mismatch")
    if recovery["acknowledged"] < 1 or recovery["readinessMillis"] > 5_000 or recovery["firstCanaryMillis"] > 2_000:
        raise ValueError("recovery threshold failed")
    exact_keys(report["cleanup"], {"processes", "boundPorts", "temporaryArtifacts", "sqliteQuickCheck"}, "cleanup")
    if report["cleanup"] != {"processes": 0, "boundPorts": 0, "temporaryArtifacts": 0, "sqliteQuickCheck": "ok"}:
        raise ValueError("cleanup qualification is incomplete")
    if not isinstance(report["limitations"], list) or not report["limitations"]:
        raise ValueError("limitations must be a non-empty list")
    if not all(isinstance(item, str) and 0 < len(item) <= 512 for item in report["limitations"]):
        raise ValueError("invalid limitation")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_hostile_load_evidence.py REPORT.json")
    path = Path(sys.argv[1])
    report = json.loads(path.read_text(encoding="utf-8"))
    validate(report)
    print(f"validated {path}: {report['verdict']}")


if __name__ == "__main__":
    main()
