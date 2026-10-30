"""Linux process-level resource probe; timings belong to the normal Rust harness.

Usage: python3 benchmarks/resources.py BINARY ROOT MODE RUNS OUTPUT.json
Requires envctl. Process inspection is redacted before parsing or persistence.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path


def redacted(value: str) -> str:
    return subprocess.run(
        ["envctl", "redact"], input=value, text=True, capture_output=True, check=True
    ).stdout


def main() -> None:
    binary, root, mode, runs, output = sys.argv[1:]
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = [str(Path(binary).resolve()), str(Path(root).resolve()), mode, runs, "0"]
    # Validate the redactor before starting the workload.
    redacted("")
    with (
        destination.with_suffix(".stdout").open("w") as stdout,
        destination.with_suffix(".stderr").open("w") as stderr,
    ):
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        samples = 0
        peak_private_kib = 0
        peak_descriptors = 0
        try:
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                try:
                    smaps = redacted(
                        Path(f"/proc/{process.pid}/smaps_rollup").read_text()
                    )
                    private = sum(
                        int(line.split()[1])
                        for line in smaps.splitlines()
                        if line.startswith((
                            "Private_Clean:",
                            "Private_Dirty:",
                            "Private_Hugetlb:",
                        ))
                    )
                    descriptors = redacted(
                        "\n".join(os.listdir(f"/proc/{process.pid}/fd"))
                    ).splitlines()
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    # A child can exit between wait4 and either /proc read;
                    # Linux may deny access to the resulting zombie's fd dir.
                    # Persistent denial produces zero samples and fails below.
                    continue
                samples += 1
                peak_private_kib = max(peak_private_kib, private)
                peak_descriptors = max(peak_descriptors, len(descriptors))
                time.sleep(0.005)
        finally:
            if process.returncode is None:
                process.terminate()
                process.wait()
    if process.returncode:
        raise SystemExit(
            f"benchmark exited {process.returncode}; see {destination.with_suffix('.stderr')}"
        )
    if not samples:
        raise SystemExit("workload ended before any sample; increase RUNS")
    destination.write_text(
        redacted(
            json.dumps(
                {
                    "command": command,
                    "user_cpu_seconds": usage.ru_utime,
                    "system_cpu_seconds": usage.ru_stime,
                    "max_rss_kib": usage.ru_maxrss,
                    "sampled_peak_private_kib": peak_private_kib,
                    "sampled_peak_descriptors": peak_descriptors,
                    "samples": samples,
                    "scope": "whole process: startup, oracle walks, verification, measured traversals, teardown",
                    "sampling": "5ms sleep plus inspection/redaction overhead; sampled peaks are lower bounds",
                },
                indent=2,
            )
        )
        + "\n"
    )
    print(destination)


if __name__ == "__main__":
    main()
