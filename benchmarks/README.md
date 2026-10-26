# Layer benchmarks and profiles

Run from the repository root. These are Cargo `[[bench]]` targets with `harness = false`, using the optimized bench profile and a custom in-process measurement harness. They complement the CLI and Criterion benchmarks. Each repository builds against its own dependency graph: fsql measures its pinned tree-fucker revision; tree-fucker measures its local library. No sibling checkout or temporary source package is required.

```sh
cargo bench:layers --test
cargo bench:alloc --test
cargo bench:layers --fixture 20000 all 15 2
cargo bench:alloc --fixture 20000 all 3 1
cargo bench:layers /absolute/path/to/input scan-count 25 2
```

The aliases invoke `cargo bench --bench layers --` and `cargo bench --bench layers_alloc --`. The entry points and shared harness live under `benches/`. Cargo's injected `--bench` flag is accepted by the custom argument parser.

The arguments are `ROOT MODE [RUNS=15] [WARMUPS=2]`, or `--fixture FILES MODE [RUNS] [WARMUPS]`. `MODE=all` runs the repository's complete layer suite sequentially. `--help` lists modes. Zero warmups are allowed; measured runs and fixture files must be positive. Input trees must remain unchanged throughout measurement.

Generated fixtures live under **target/benchmarks**, and are removed when the probe exits. They contain ten directories of sparse files, a hidden directory, Unicode/quoted names and, on Unix, a directory symlink and dangling symlink. Symlinks are not followed. One in seven regular files exceeds 1,000,000 bytes. For comparisons between repositories, pass the same existing input tree to both probes. Generated fixtures are not the same shape as the Python CLI benchmark fixture.

| Mode               | Work measured                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------- |
| std-count          | std::fs traversal and counting without collecting paths                                           |
| fsql-walk-baseline | Original Linux fsql walker at `d5ac9c80a2c5d8322d9ae096d6b0d860d73a4d4f`, with a minimal row shim |
| scan-count         | Default complete-listing Scan without absolute path materialization                               |
| scan-bounded       | Scan with a two-worker ListingExecutor, including pool startup                                    |
| scan-streaming     | Scan with incremental listing chunks                                                              |
| scan-anchors       | Scan with an optional anchor budget of 1024                                                       |
| scan-paths         | Scan plus absolute path materialization                                                           |
| scan-stats         | Scan plus diagnostic statistics; not for timing comparisons                                       |
| tree-initial       | Persistent Tree initialization, initial snapshot, and shutdown, including runtime startup         |

The governor is installed once with foreground and background duty 1.0. Scan follows filesystem domains, uses an unlimited time ceiling and fails on errors, unlisted directories or unexpected boundaries. Anchors retain their safety semantics; this is a bounded-budget comparison, not a proposal to remove them.

`first_result_ms` reports the median time from scan opening to the first non-root entry, including bootstrap, pool setup where applicable, and the first complete listing or streamed chunk. For `tree-initial`, it reports when the initial snapshot is available; this control deliberately waits for the full initial scan rather than consuming the update stream. It is `-` for `std-count` or an empty input. `scan-bounded` creates a pool per traversal to include startup costs; applications can reuse a cloned executor across scans. Use normal timings to compare throughput and latency, and the allocation executable separately to compare allocation cost. Allocation counts include worker-thread allocations, so unrelated concurrent allocator activity can affect them.

Before each mode, an independent std::fs walk supplies the expected **complete path multiset**, which is compared with the probe's results. Verification materializes paths outside measured iterations. Each iteration checks its row count; the oracle is repeated afterward to detect changed membership. This does not detect every possible concurrent metadata change. Root entries are excluded. Verification checks query paths, not round-tripping the serialized output. The existing CLI benchmark remains responsible for external tool/output equivalence.

TSV results go to stdout; root, run settings and ScanStats go to stderr. Save reports outside the input tree, for example:

```sh
mkdir -p target/benchmarks
cargo bench:layers /absolute/path/to/input all 25 2 > target/benchmarks/layers.tsv
cargo bench:alloc /absolute/path/to/input all 3 1 > target/benchmarks/allocations.tsv
```

Timing uses the normal system allocator. **The allocation executable is separate** and uses stats_alloc only as a development dependency; no unsafe code is added to either library. Its timing columns include instrumentation overhead and must not be compared with the timing executable. Allocation columns are per measured iteration (integer averages), separating allocations and reallocations. `bytes_allocated` follows stats_alloc's definition, including positive reallocation growth; it is not RSS, peak memory, or the sum of full requested realloc sizes. Normal timing runs have zero allocation counters because their allocator is not instrumented. Preparation and teardown inside the measured operation are included; fixture creation, oracle verification and governor installation are excluded.

Modes run sequentially with warm caches. Compare their complete measured runtimes. CI runs both executables with `--test` as correctness smoke checks.

## Profiling

Build first, then invoke the executable directly to avoid profiling Cargo. Benchmark executable paths depend on Cargo’s toolchain and build layout; obtain the exact path from its JSON artifact output instead of guessing a filename or globbing stale builds. For symbolized profiles, set `CARGO_PROFILE_BENCH_DEBUG=1` on the build command below. Use `--bench layers_alloc` to build the separate allocation executable.

```sh
set -o pipefail
layers_bin=$(cargo bench --bench layers --no-run --locked --message-format=json |
  python3 -c 'import json, sys; artifacts = [json.loads(line) for line in sys.stdin]; paths = [a["executable"] for a in artifacts if a.get("reason") == "compiler-artifact" and a.get("target", {}).get("name") == "layers" and a.get("executable")]; assert len(paths) == 1, paths; print(paths[0])')
mkdir -p target/benchmarks
perf record -o target/benchmarks/layers.perf -- "$layers_bin" /absolute/path/to/input scan-count 100 2 2>&1 | envctl redact
perf report --stdio -i target/benchmarks/layers.perf 2>&1 | envctl redact
strace -c "$layers_bin" /absolute/path/to/input scan-count 1 0 2>&1 | envctl redact
```

Profiles and syscall totals include startup, the pre/post oracle walks, one verification traversal, warmups and measured traversals. Use enough measured iterations for CPU profiles to be dominated by the workload; **do not divide total syscall counts by RUNS and call that a single traversal**. Allocation regions exclude verification and warmups. Keep traced/instrumented results separate from normal timing. `perf`, `strace` and `envctl` are optional profiling tools, not prerequisites for the benchmarks.

## Acceptance comparison

The historical traversal source is retained under [`benchmarks/baselines/fsql/`](baselines/fsql/README.md), with its exact upstream revision recorded in the file. Its imports use a small row shim that preserves owned paths, directory descriptors and lazy `statx`, but omits SQL-only caches. An optional delay is inserted before directory opens. This compares traversal implementations; it does not claim to reproduce the old executable's SQL planning, row layout, or output costs. The Linux-only control is omitted on other targets. `tree-initial` uses a real Tokio runtime with bounded blocking workers; its runtime startup and shutdown are included.

Fixture shape and controlled latency are selectable without editing the harness:

```sh
BENCH_FIXTURE_SHAPE=wide cargo bench:layers --fixture 20000 all 15 2
BENCH_FIXTURE_SHAPE=deep cargo bench:layers --fixture 20000 all 15 2
BENCH_LISTING_DELAY_US=1000 cargo bench:layers --fixture 20000 all 15 2
```

`balanced` is the default. `wide` puts files at the root; `deep` spreads them over a 64-level chain. The delay adds one sleep per opened directory to the historical walker, governed scans, and persistent Tree. The adapter reports that injected time to the governor. `std-count` is not delayed and is not a slow-storage comparator. This is controlled latency injection, not a measured network mount or cold-storage result. Barrier-based scan tests separately cover a call that never returns until released and prove cancellation/quarantine ownership.

On Linux, collect CPU, sampled private memory and open descriptor counts in a separate instrumented run:

```sh
python3 benchmarks/resources.py "$layers_bin" /absolute/path/to/input fsql-walk-baseline 100 target/benchmarks/fsql-baseline-resources.json
python3 benchmarks/resources.py "$layers_bin" /absolute/path/to/input scan-streaming 100 target/benchmarks/scan-resources.json
python3 benchmarks/resources.py "$layers_bin" /absolute/path/to/input tree-initial 100 target/benchmarks/tree-resources.json
```

The script requires `envctl` and redacts process inspection before parsing or saving it. CPU comes from `wait4` for the benchmark process, excluding the sampler/redactor. Private memory sums `Private_Clean`, `Private_Dirty`, and `Private_Hugetlb`; it is distinct from RSS. Descriptor and private-memory peaks are sampled lower bounds, with a 5 ms sleep plus inspection/redaction overhead. These runs include startup, verification, oracle walks and teardown and must not supply normal timing results. Use enough traversals to obtain samples. Run syscall profiling separately with `strace -f -c` and the redaction pipeline above so worker threads are included.

See [the acceptance report](scan-acceptance.md) for the measured fixture, results, and mapping to issue #2.

## Coordination admission microbenchmarks

The `coordination` Cargo benchmark measures local admission, provisional local admission, the bounded ownership protocol, shared admission accounting, recoverable snapshot transactions, and uncontended Linux coordination separately:

```sh
cargo bench --bench coordination -- --test
cargo bench --bench coordination -- 100000
```

The default is 100,000 operations per round, two warmup rounds, and seven measured rounds with alternating mode order. The output contains median, minimum, and maximum nanoseconds per operation. The smoke mode performs 16 operations per mode and checks that all physical ownership and provisional reservations have been released. Native CI runs that mode.

The local modes include grant creation, admission, physical start, and release. The prepared mode also prepares and commits local budget. Budgets are deliberately generous to measure overhead without sleeping for duty refill. The protocol mode includes preparation, authorization, running acknowledgment, and settlement in a preallocated ownership table. Participant registration is outside the timed loop.

The `shared-authority` mode includes shared budget preparation, physical authorization, elapsed accounting, and settlement. `snapshot-journal` performs those transitions as three recoverable snapshot transactions over an in-memory byte device. It includes encoding, validation, allocation, checksums, and recovery selection; it does not include native filesystem calls or interprocess locks. Comparing these modes identifies serialization cost separately from admission policy.

`linux-tmpfs` on Linux, `freebsd-tmpfs` on FreeBSD, `illumos-tmpfs` on illumos, and `macos-tmpfs` on macOS run the same prepare/start/settle lifecycle through a private tmpfs scope, real `flock` calls, namespace and file-identity validation, owner recovery checks, and journal I/O. It excludes initial discovery and joining, and verifies that no physical work or cleanup thread remains afterward. The isolated benchmark scope is removed only after its handles close.

Native correctness tests run with `cargo test --all-features --test coordination_processes`.

## Independent-process coordination benchmarks

On Linux, FreeBSD, illumos, macOS, and Windows, `coordination_processes` launches separate executables using the real Scan API. Each round compares independent process governors with governors that also join one shared authority. Both use a physical ceiling of two; the shared mode enforces that ceiling across the cohort. Duty allowances are generous so the measurements expose coordination and physical-capacity costs.

```sh
cargo bench --bench coordination_processes -- --test
cargo bench --bench coordination_processes_alloc -- --test
cargo bench --bench coordination_processes -- \
  --workers 8 --iterations 100 --files 64 --runs 5 --warmups 1
```

| Scenario     | Work performed                                                                                                    |
| ------------ | ----------------------------------------------------------------------------------------------------------------- |
| `tiny`       | One participant repeatedly reads a warm file through `Scan::read`.                                                |
| `disjoint`   | Each participant repeatedly scans its own directory, including bootstrap and listing.                             |
| `contention` | Participants concurrently read the same warm file through `Scan::read`.                                           |
| `churn`      | Each participant joins, performs one read, and exits; `--waves` cohorts reuse the same authority.                 |
| `slow`       | Each participant blocks on a kernel pipe read through `Scan::read`; the controller supplies data after `--hold-ms`. |
| `idle`       | Joined participants wait on their control pipes for `--hold-ms`; authority-access counters must remain unchanged. |

Use `--scenario NAME` and `--mode local|shared|both` to select a workload. Defaults are all scenarios, both modes, eight workers, 100 iterations, 64 files per directory, five measured rounds, one warmup, four churn waves, and 100 ms holds. The tiny case always uses one worker. Local/shared execution order alternates between rounds. Fixtures live under `target/benchmarks`; isolated Linux authority files use tmpfs and are removed after all participants exit.

Before timing, disjoint scans compare complete sorted paths with the generated fixture. Timed scans check row counts, and reads check file contents. Every child must exit successfully. Each shared round also verifies that preparations, physical ownership, and participants are fully reclaimed.

The output is TSV with one row per mode, scenario, and measured round:

- `operations` counts complete scans for `disjoint`, reads for `tiny`, `contention`, `churn`, and `slow`, and zero for `idle`. `rows` counts scan entries or verified file reads.
- `cohort_ns` measures from releasing ready children until all report completion, summed across churn waves. `wall_ns` additionally includes process creation, joining, fixture verification, and child teardown; fixture creation and final authority inspection are outside it.
- `worker_p50_ns` and `worker_p95_ns` summarize whole worker workload durations. `join_p95_ns` measures opening the scope and constructing the governor. These are worker durations, not individual-operation percentiles.
- `lock_attempts`, `lock_acquired`, and `lock_busy` sum connection access counters during the workload, including deferred settlement. Busy results include either the connection mutex or the interprocess lock.
- `user_cpu_ns` and `system_cpu_ns` sum each worker's CPU deltas across the workload and settlement, using `getrusage(RUSAGE_SELF)` on Unix and [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes) on Windows. They include all worker threads and use the native kernel's accounting resolution. The two resource snapshots are outside the wall-clock interval; joining and initial verification precede both snapshots.

The separate `coordination_processes_alloc` executable installs the counting allocator. Its allocation fields cover worker workload execution and waiting for pending settlement, excluding setup, joining, and the before/after counter snapshots. Run it with the same options as the timing executable. The ordinary executable uses the system allocator and reports zero in allocation columns.

Native Windows x64/ARM64 and macOS ARM64/Intel CI run both smoke targets, then measure all six scenarios with four workers, 100 iterations, 64 files, one warmup, and three measured rounds. Each job uploads `native-coordination-timing.tsv` and `native-coordination-allocations.tsv` in its `coordination-<runner>` artifact. These reports retain latency, worker CPU, lock attempts, and allocations for every round. Aggregate handles, mappings, and sampled memory remain separate resource-acceptance work.

### Linux CPU, memory, descriptors, and syscalls

Build the executable and obtain its actual path from Cargo, then run resource collection separately:

```sh
mkdir -p target/benchmarks
cargo bench --bench coordination_processes --no-run --message-format=json \
  > target/benchmarks/coordination-build.jsonl
COORDINATION_BENCH=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "coordination_processes") | .executable // empty' \
  target/benchmarks/coordination-build.jsonl)
python3 benchmarks/coordination_resources.py target/benchmarks/coordination-resources.json \
  "$COORDINATION_BENCH" --scenario contention --mode shared \
  --workers 8 --iterations 1000 --runs 3 --warmups 0
```

The profiler requires `envctl`. It redacts process inspection before parsing or saving it and writes benchmark output alongside the JSON report. CPU and context-switch totals include the controller and its waited descendants. Memory, mapped virtual bytes, and open descriptors are sampled and summed across the live process tree; each reported peak is the largest observed aggregate for that metric. RSS includes shared pages in each process that maps them; private memory is reported separately. A sample includes inspection/redaction time followed by a 5 ms sleep. The report covers startup, verification, work, and teardown. Use the ordinary benchmark executable for workload timing.

```sh
set -o pipefail
strace -f -c -e trace=flock,openat,newfstatat,statx,read,write,lseek,close \
  "$COORDINATION_BENCH" --scenario contention --mode shared \
  --workers 8 --iterations 100 --runs 1 --warmups 0 \
  2>&1 | envctl redact > target/benchmarks/coordination-syscalls.txt
```

`flock` counts native authority and owner-lifetime locking. The other syscall totals include fixture I/O and process control. Repeat with `--mode local` for the corresponding process-only workload. Both Cargo executables have smoke runs in Linux, FreeBSD, OmniOS, macOS, and Windows CI. Implementation coverage is tracked in [the acceptance ledger](../rfc/coordination-acceptance.md).

## Local FreeBSD acceptance VM

`freebsd_vm.py` prepares a checksum-verified FreeBSD 15.0 cloud image and a writable overlay. QEMU with KVM, `qemu-img`, `genisoimage`, and OpenSSH are required on the Linux host. Generated disks, the VM-specific SSH key, and transferred build inputs stay under ignored `target/native/freebsd/`.

```sh
python3 benchmarks/freebsd_vm.py prepare
python3 benchmarks/freebsd_vm.py run
```

The foreground VM performs first-boot updates and may reboot before SSH is ready. From another terminal, provision its toolchain and retained tmpfs, then copy the repository build inputs:

```sh
python3 benchmarks/freebsd_vm.py provision
python3 benchmarks/freebsd_vm.py sync
python3 benchmarks/freebsd_vm.py exec \
  '. /root/.cargo/env; cd /root/tree-fucker && cargo test --all-features --no-fail-fast'
python3 benchmarks/freebsd_vm.py exec \
  '. /root/.cargo/env; cd /root/tree-fucker && cargo test --test coordination_freebsd privileged_ -- --ignored'
python3 benchmarks/freebsd_vm.py exec \
  '. /root/.cargo/env; cd /root/tree-fucker && cargo bench --bench coordination_processes -- --test'
python3 benchmarks/freebsd_vm.py exec 'shutdown -p now'
```

SSH listens on host loopback port 40222; pass `--port PORT` before the subcommand to select another port. Run `provision` after each VM boot to mount `/var/run/tree-fucker` as tmpfs. `sync` refreshes source inputs while keeping the guest's Cargo cache and build artifacts. The jail and effective-user acceptance tests run explicitly because they require root; capability-mode tests launch dedicated subprocesses during the ordinary suite.

## Local OmniOS acceptance VM

`omnios_vm.py` prepares the checksum-verified OmniOS r151058 cloud image, a writable disk overlay, and NoCloud SSH configuration under ignored `target/native/omnios/`. It uses QEMU/KVM, `qemu-img`, `genisoimage`, OpenSSH, and EDK II UEFI firmware. The default firmware directory is `/usr/share/edk2/x64`; pass `--firmware-dir DIR` before `run` to select another directory containing `OVMF_CODE.4m.fd` and `OVMF_VARS.4m.fd`.

```sh
python3 benchmarks/omnios_vm.py prepare
python3 benchmarks/omnios_vm.py run
```

After first-boot configuration completes, use another terminal:

```sh
python3 benchmarks/omnios_vm.py provision
python3 benchmarks/omnios_vm.py sync
python3 benchmarks/omnios_vm.py exec \
  '. /root/.cargo/env; cd /root/tree-fucker && cargo test --all-features --no-fail-fast'
python3 benchmarks/omnios_vm.py exec \
  '. /root/.cargo/env; cd /root/tree-fucker && cargo bench --bench coordination_processes -- --test'
python3 benchmarks/omnios_vm.py exec 'poweroff'
```

SSH listens only on host loopback port 40223, configurable with `--port PORT`. Provisioning creates the rendezvous inside OmniOS's tmpfs-backed `/var/run`; repeat provisioning after reboot. The shared transfer helper writes USTAR archives accepted by both native base-system `tar` commands. UEFI avoids the Arch SeaBIOS build's early illumos `startup_modules` panic; firmware variables belong to this VM, and the host firmware files are read-only. QEMU exits on a guest reboot so a boot failure cannot become an unattended restart loop.

The zone transition fixture uses a dedicated network-isolated linked-package zone. `provision-zone` runs the same `omnios_zone.sh` setup as CI and waits for the zone's `/var/run` tmpfs before creating its rendezvous. Create the zone once in this VM, then run the privileged tests explicitly:

```sh
python3 benchmarks/omnios_vm.py provision-zone
python3 benchmarks/omnios_vm.py exec \
  '. /root/.cargo/env; cd /root/tree-fucker && cargo test --test coordination_illumos privileged_ -- --ignored --nocapture'
```

The fixture mounts its temporary authority into the zone, enters that zone with a live governor, checks that the old governor is fenced, and performs separately governed zone-local work. The fixture unmounts its shared directory when it exits; the dedicated zone remains available for repeated runs.

## macOS coordination acceptance

Provision retained tmpfs once per boot before running the shared tests or benchmarks:

```sh
sudo mkdir -p /var/run/tree-fucker
sudo /sbin/mount_tmpfs -e -s 128m /var/run/tree-fucker
sudo chmod 1777 /var/run/tree-fucker
cargo test --all-features
cargo bench --bench coordination -- --test
cargo bench --bench coordination_processes -- --test
cargo bench --bench coordination_processes_alloc -- --test
```

The native suite includes a subprocess that applies sandbox restrictions after joining. The workflow also executes the privileged root-transition fixture using the already-built test executable. The mount remains available after the tests; unmounting it ends the authority lifetime and must only happen after participating applications close their handles. Native evidence is tracked in [the acceptance ledger](../rfc/coordination-acceptance.md#macos-port-and-native-acceptance-wiring).

## Windows coordination development checks

On native Windows, run `cargo test --test coordination_windows`. This suite also runs in the existing Windows CI job. For local Linux development, the repository helper builds the same tests for Windows and executes them under Wine:

```sh
rustup target add x86_64-pc-windows-gnu
python3 benchmarks/windows_wine.py prepare
python3 benchmarks/windows_wine.py run
```

The helper requires Wine, Zig, and `llvm-dlltool`. `prepare` uses Arch/Manjaro's configured package repository to download the MinGW runtime, verifies its signature with `pacman-key`, and extracts its libraries with `bsdtar` into `target/native/windows`. It does not install system packages. On other distributions, supply an installed MinGW sysroot through `WINDOWS_SYSROOT` and omit `prepare`.

Build records and the isolated Wine prefix stay under `target/native/windows`. The helper shuts down only its own Wine prefix after execution. The fixtures cover owner-handle lifetime, nonblocking bookkeeping, replacement rejection, and interrupted journal publication. Wine 11.20 does not preserve protected file ACLs, so the complete file-based suite rejects its storage. Descriptor-policy and caller-context checks can run separately while native Windows validates the storage path:

```sh
python3 benchmarks/windows_wine.py run --filter private_descriptors
python3 benchmarks/windows_wine.py run --filter impersonation
python3 benchmarks/windows_wine.py run --filter native_discovery_
python3 benchmarks/windows_wine.py run --filter relative_
python3 benchmarks/windows_wine.py run --filter storage_
```
