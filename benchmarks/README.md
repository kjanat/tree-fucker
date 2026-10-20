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

Modes run sequentially with warm caches; there is no randomization, cold-cache guarantee or performance threshold. Do not subtract independently measured medians as an exact attribution of cost. CI runs both executables with `--test` as correctness smoke checks, not performance gates.

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

See [the acceptance report](scan-acceptance.md) for the measured fixture, limitations, and mapping to issue #2.
