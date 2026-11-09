# Native coordination CI

The [acceptance workflow](../.github/workflows/coordination-acceptance.yml) runs on pull requests and pushes to master. It complements the full integration suites in [CI](../.github/workflows/ci.yml).

| Job                 | Execution and evidence                                                                                                                                                                                                                                                                                                              |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Solaris             | Boots Solaris 11.4, installs the native Rust distribution, and runs Clippy, tests, socket-lifetime candidates, and rustdoc. Shared-backend integration awaits the Solaris implementation.                                                                                                                                           |
| Windows reboot      | Builds a static-CRT fixture on Windows, installs Windows Server 2022 Evaluation in a disposable KVM guest, and reboots with authorized ownership and a persisted journal. The second phase requires a changed boot epoch, unchanged generation/accounting, recovered ownership, and a shared clock mapping after all handles close. |
| Aggregate resources | Runs all six workloads in local/shared modes on Linux, Windows x64/ARM64, and macOS Intel/ARM64. Reports complete live-cohort samples and aggregate peaks for USS, RSS, virtual address space, and handles/descriptors.                                                                                                             |
| Syscalls            | Uses Linux strace, macOS DTrace, and realtime Windows ETW in separate runs. Windows records syscall addresses and counts, requires zero lost events, and captures the workload's process descendants without saving a machine-wide ETL.                                                                                             |
| macOS sleep/wake    | Runs only on default-branch pushes or manual dispatches, using COORDINATION_SLEEP_RUNNER or the sleep_runner input. Requires new kernel sleep/wake timestamps while ownership stays live.                                                                                                                                           |

The Windows controller continues running on Linux while the guest kernel restarts. The guest sends the second-phase result to the controller over Docker's bridge and saves it on its retained NTFS disk. The `--no-map-gw` flag stops passt from translating that destination to the container's loopback interface, where the controller does not listen. If delivery fails, the guest shuts down. The controller then reads the result with guestfish in read-only mode and keeps the redacted payload before it parses the result. The job uploads the logs and the result and omits the disk image. Headless execution keeps the virtual VGA device that Windows setup needs.

After reboot, the same guest runs `windows_sessions::interactive_session_fixture` in real RDP sessions. The controller uses FreeRDP under Xvfb with at most four connections and a loopback-only RDP port. The controller creates disposable credentials in a private OEM input and sends them to FreeRDP over stdin. Artifacts exclude the credentials and the OEM directory. The guest creates a standard user and a separate administrator, installs the Session Host role for ordinary concurrent desktops, and enables UAC before the existing reboot. The session controller uses `WTSQueryUserToken` and `CreateProcessAsUserW`, and it records the actual session, authentication identity, elevation and authority generation from each fixture process.

The histories require two concurrent standard-user sessions to share discovery and a physical ceiling, logoff to retire only the departed owner with one surcharge, and a new logon to retain generation and debt. Both UAC creation orders must share an authority and ceiling. Another principal must fail to open private storage. A real AppContainer must return the documented pre-join fallback/error before joining. FAT32, a read-only NTFS virtual disk and a mapped loopback SMB share must also report pre-join unavailability. These setup changes and virtual disks exist only inside the disposable guest. The controller reports success only when both reboot and session acceptance pass. A newly added fixture counts as evidence only after its native run passes.

The sleep runner executes privileged commands, so configure it only for trusted code. The job accepts default-branch pushes and default-branch manual dispatches, and it rejects pull requests and other refs even when a runner label is configured. Use [runner-group workflow restrictions](https://docs.github.com/en/enterprise-cloud@latest/actions/how-tos/manage-runners/self-hosted-runners/manage-access) to restrict access to `kjanat/tree-fucker/.github/workflows/coordination-acceptance.yml@refs/heads/master` where available. A workflow condition alone cannot constrain a pull request that rewrites the workflow itself. Keep the physical sleep acceptance item open until a trusted run supplies evidence.

[Run 40774525521](https://github.com/kjanat/tree-fucker/actions/runs/40774525521) tested the hosted Mac runners. ARM returned `Unable to sleep system: error 0xe00002e2`. Intel returned from the sleep request without new kernel sleep/wake timestamps. With no sleep-capable runner configured, CI records the missing gate in its summary. That gate remains open in the PR checklist.

Resource and syscall jobs cancel superseded PR runs independently. Solaris and Windows reboot jobs finish their evidence collection when another revision is pushed. No job depends on formatting or another platform's success. The reboot job depends only on its Windows fixture build.

## Reproduce resource collection

Build the optimized benchmark and obtain its executable from Cargo's artifact output:

```sh
mkdir -p target/benchmarks
cargo bench --bench coordination_processes --no-run --message-format=json >target/benchmarks/resource-build.jsonl
binary=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "coordination_processes") | .executable // empty' target/benchmarks/resource-build.jsonl)
uv run benchmarks/native_resources.py --synchronize-cohort --minimum-processes 5 \
  target/benchmarks/resources-contention-shared.json "$binary" \
  --scenario contention --mode shared --workers 4 --iterations 2000 \
  --runs 1 --warmups 0 2>&1 | envctl redact
```

Use a shell with pipefail enabled. The collector requires envctl and obtains psutil through uv's script dependencies. On macOS, task-memory inspection requires running the collector with sudo. The workflow preserves only PATH and supplies a separate uv cache. Shared macOS runs also require the tmpfs rendezvous that the native tests use.

The synchronized collector passes a private `--sample-barrier` directory to the benchmark. Each cohort announces readiness after all workers initialize, then waits up to sixty seconds for a complete sample to acknowledge that cohort number. The collector checks readiness before inspection and acknowledges only complete, successful samples. Each churn wave uses a new number, so an old acknowledgement cannot release it. The handshake ends before the cohort timer starts. Ordinary timing runs use neither the handshake nor a startup hold. Sampled peaks include startup, ready state, work, and teardown, and they are lower bounds. The collector rejects an unsuccessful workload, a redaction failure, or the absence of a complete cohort. When a macOS USS region enumeration fails, the collector discards the entire sample only after a bounded check confirms that the original process identity exited. A failure in a live process remains an error. The resource jobs run `benchmarks/test_native_resources.py` before measurement to verify exit handling and rejection of partial samples. Windows virtual bytes include committed and reserved address ranges from VirtualQueryEx, and the collector does not substitute Windows pagefile usage for virtual address space. RSS counts shared pages in each process, and USS counts unique resident memory. The report keeps the native meanings of Windows handles and Unix descriptors.

## Reproduce syscall collection

```sh
bash benchmarks/trace_coordination.sh "$binary" shared target/benchmarks/syscalls-shared.log
```

The Unix script checks both trace counts and the benchmark's verified result row. Windows builds the repository-owned ETW collector with .NET 10, then runs it as shown in the workflow. Trace sessions stop on completion or failure. Latency measurements come from untraced, unsampled runs.
