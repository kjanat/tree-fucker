"""Validate the complete resource matrix and render a CI summary."""

import json
import sys
from pathlib import Path


def main() -> None:
    root = Path(sys.argv[1])
    rows = []
    for scenario in ["tiny", "disjoint", "contention", "churn", "slow", "idle"]:
        for mode in ["local", "shared"]:
            report = json.loads(
                (root / f"resources-{scenario}-{mode}.json").read_text()
            )
            command = report["command"]
            assert command[command.index("--scenario") + 1] == scenario
            assert command[command.index("--mode") + 1] == mode
            minimum = 2 if scenario == "tiny" else 5
            assert report["minimum_processes"] == minimum
            assert report["samples"], "No samples"
            for sample in report["samples"]:
                assert sample["processes"] >= minimum
                assert all(
                    type(value) is int and value >= 0 for value in sample.values()
                )
            peak = report["peak_aggregate"]
            assert peak == {
                key: max(sample[key] for sample in report["samples"])
                for key in report["samples"][0]
            }, "Peak report differs from retained samples"
            rows.append((scenario, mode, len(report["samples"]), peak))
    print("## Aggregate coordination resources\n")
    print("Sampled peaks for the benchmark controller and its live descendants.\n")
    print(
        "| Workload | Mode | Samples | Private KiB | RSS KiB | Virtual MiB | Handles / FDs |"
    )
    print("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for scenario, mode, samples, peak in rows:
        print(
            f"| {scenario} | {mode} | {samples} | {peak['private_bytes'] / 1024:.1f} "
            f"| {peak['rss_bytes'] / 1024:.1f} | {peak['virtual_bytes'] / 1048576:.1f} "
            f"| {peak['handles']} |"
        )


if __name__ == "__main__":
    main()
