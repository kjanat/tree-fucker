# Native coordination CI

The [acceptance workflow](../.github/workflows/coordination-acceptance.yml) runs on pull requests and pushes to master. It complements the full integration suites in [CI](../.github/workflows/ci.yml).

| Job                 | Execution and evidence                                                                                                                                                                                                                                                                                                              |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Solaris             | Boots Solaris 11.4, installs the native Rust distribution, and runs Clippy, tests, socket-lifetime candidates, and rustdoc. Shared-backend integration awaits the Solaris implementation.                                                                                                                                           |
| Windows reboot      | Builds a static-CRT fixture on Windows, installs Windows Server 2022 Evaluation in a disposable KVM guest, and reboots with authorized ownership and a persisted journal. The second phase requires a changed boot epoch, unchanged generation/accounting, recovered ownership, and a shared clock mapping after all handles close. |
| Aggregate resources | Runs all six workloads in local/shared modes on Linux, Windows x64/ARM64, and macOS Intel/ARM64. Reports complete live-cohort samples and aggregate peaks for USS, RSS, virtual address space, and handles/descriptors.                                                                                                             |
| Syscalls            | Uses Linux strace, macOS DTrace, and realtime Windows ETW in separate runs. Windows records syscall addresses and counts, requires zero lost events, and captures the workload's process descendants without saving a machine-wide ETL.                                                                                             |
| macOS sleep/wake    | Runs on a sleep-capable runner selected by COORDINATION_SLEEP_RUNNER or the sleep_runner dispatch input. Requires new kernel sleep/wake timestamps while ownership stays live.                                                                                                                                                      |

The Windows controller continues running on Linux while the guest kernel restarts. The guest sends the second-phase result to the controller over Docker's bridge and saves it on its retained NTFS disk. If delivery fails, the guest shuts down and the controller reads that result using guestfish in read-only mode. The job uploads logs and the result rather than the disk image. Headless execution keeps the virtual VGA device needed by Windows setup.

The hosted Mac runners were tested in [run 40774525521](https://github.com/kjanat/tree-fucker/actions/runs/40774525521): ARM returned `Unable to sleep system: error 0xe00002e2`; Intel returned from the sleep request without new kernel sleep/wake timestamps. With no sleep-capable runner configured, CI records the missing gate in its summary. That gate remains open in the PR checklist.

Resource and syscall jobs cancel superseded PR runs independently. Solaris and Windows reboot jobs finish their evidence collection when another revision is pushed. No job depends on formatting or another platform's success. The reboot job depends only on its Windows fixture build.

## Reproduce resource collection

Build the optimized benchmark and obtain its executable from Cargo's artifact output:

```sh
mkdir -p target/benchmarks
cargo bench --bench coordination_processes --no-run --message-format=json > target/benchmarks/resource-build.jsonl
binary=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "coordination_processes") | .executable // empty' target/benchmarks/resource-build.jsonl)
uv run benchmarks/native_resources.py --minimum-processes 5 \
  target/benchmarks/resources-contention-shared.json "$binary" \
  --scenario contention --mode shared --workers 4 --iterations 2000 \
  --ready-hold-ms 500 --runs 1 --warmups 0 2>&1 | envctl redact
```

Use a shell with pipefail enabled. The collector requires envctl and obtains psutil through uv's script dependencies. On macOS, task-memory inspection requires running the collector with sudo; the workflow preserves only PATH and supplies a separate uv cache. Shared macOS runs also require the tmpfs rendezvous used by the native tests.

The sampling hold keeps the entire ready cohort alive before dispatch. It defaults to zero in normal benchmarks and is outside the cohort timer. Sampled peaks include startup, ready state, work, and teardown; they are lower bounds. The collector rejects an unsuccessful workload, redaction failure, or absence of a complete cohort. Windows virtual bytes include committed and reserved address ranges from VirtualQueryEx; Windows pagefile usage is not substituted for virtual address space. RSS counts shared pages in each process; USS counts unique resident memory. Windows handles and Unix descriptors retain their native meanings in the report.

## Reproduce syscall collection

```sh
bash benchmarks/trace_coordination.sh "$binary" shared target/benchmarks/syscalls-shared.log
```

The Unix script checks both trace counts and the benchmark's verified result row. Windows builds the repository-owned ETW collector with .NET 10, then runs it as shown in the workflow. Trace sessions stop on completion or failure. Traced and sampled runs do not supply ordinary latency measurements.
