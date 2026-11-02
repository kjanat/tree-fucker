"""Aggregate Linux resource samples for a benchmark and its subprocesses.

Usage: python3 benchmarks/coordination_resources.py OUTPUT.json BINARY [ARGS...]
"""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from resources import redacted


def read_at(descriptor: int, name: str) -> str:
    with os.fdopen(os.open(name, os.O_RDONLY, dir_fd=descriptor)) as file:
        return file.read()


def process_tree(root: int) -> list[int]:
    pending = [root]
    seen: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        try:
            children = redacted(Path(f"/proc/{pid}/task/{pid}/children").read_text())
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        pending.extend(int(child) for child in children.split())
    return sorted(seen)


def sample(root: int) -> dict[str, int]:
    raw = []
    for pid in process_tree(root):
        try:
            # A pinned proc directory cannot turn into a reused PID between reads.
            descriptor = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        try:
            raw.append({
                "smaps": read_at(descriptor, "smaps_rollup"),
                "maps": read_at(descriptor, "maps"),
                "fds": os.listdir(f"/proc/self/fd/{descriptor}/fd"),
            })
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        finally:
            os.close(descriptor)
    # Redact the complete inspection before parsing or selecting measurements.
    inspected = json.loads(redacted(json.dumps(raw)))
    totals = {
        "processes": len(inspected),
        "private_kib": 0,
        "rss_kib": 0,
        "mapped_bytes": 0,
        "descriptors": 0,
    }
    for process in inspected:
        for line in process["smaps"].splitlines():
            if line.startswith((
                "Private_Clean:",
                "Private_Dirty:",
                "Private_Hugetlb:",
            )):
                totals["private_kib"] += int(line.split()[1])
            elif line.startswith("Rss:"):
                totals["rss_kib"] += int(line.split()[1])
        for line in process["maps"].splitlines():
            start, end = line.split()[0].split("-")
            totals["mapped_bytes"] += int(end, 16) - int(start, 16)
        totals["descriptors"] += len(process["fds"])
    return totals


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    output = Path(sys.argv[1])
    command = sys.argv[2:]
    output.parent.mkdir(parents=True, exist_ok=True)
    redacted("")
    peaks = {
        "processes": 0,
        "private_kib": 0,
        "rss_kib": 0,
        "mapped_bytes": 0,
        "descriptors": 0,
    }
    samples = 0
    interval = 0.005
    started = time.monotonic()
    with output.with_suffix(".stdout").open("w") as stdout:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        sanitizer = None
        try:
            sanitizer = subprocess.Popen(
                ["envctl", "redact"], stdin=process.stdout, stdout=stdout
            )
            assert process.stdout is not None
            process.stdout.close()
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    usage_values = json.loads(redacted(json.dumps(list(usage))))
                    break
                values = sample(process.pid)
                if values["processes"]:
                    samples += 1
                    peaks = {
                        key: max(value, values[key]) for key, value in peaks.items()
                    }
                time.sleep(interval)
        finally:
            if process.returncode is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            if sanitizer is not None:
                sanitizer_code = sanitizer.wait()
    if process.returncode or sanitizer_code:
        raise SystemExit(
            f"benchmark exit {process.returncode}, redactor exit {sanitizer_code}; see {output.with_suffix('.stdout')}"
        )
    if not samples:
        raise SystemExit("no resource sample completed; increase workload duration")
    report = {
        "command": command,
        "wall_seconds": time.monotonic() - started,
        "user_cpu_seconds": usage_values[0],
        "system_cpu_seconds": usage_values[1],
        "voluntary_context_switches": usage_values[14],
        "involuntary_context_switches": usage_values[15],
        "sampled_peak_aggregate": peaks,
        "samples": samples,
        "sample_sleep_seconds": interval,
        "scope": "benchmark controller and descendants; startup, verification, workload, and teardown",
        "sampling": "aggregate peaks across live processes; interval includes proc inspection and redaction",
    }
    output.write_text(redacted(json.dumps(report, indent=2)) + "\n")
    print(output)


if __name__ == "__main__":
    main()
