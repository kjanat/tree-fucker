# Governed one-shot scan acceptance

This records the implementation and local validation for [issue #2](https://github.com/kjanat/tree-fucker/issues/2), on 2026-10-20. The synchronous default stays available. Consumers opt into the stronger anchor, streaming, and blocked-listing contracts separately.

## Acceptance mapping

| Requirement            | Implemented contract and evidence                                                                                                                                                                                                                                                                                                        |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Newly blocked listings | `ListingExecutor` bounds reusable workers. A barrier-held listing quarantines its own domain; healthy siblings progress while worker and governor capacity remain. Detached calls retain physical ownership until completion.                                                                                                            |
| Cancellation histories | Tests cover admission waiting, physical-slot waiting, active listings, pool exhaustion, between chunks, and worker panic. Logical cancellation never releases a running physical slot or detached buffer.                                                                                                                                |
| Required anchors       | `AnchorPolicy::Required` reports `ResourceLimit::Anchors` for exhaustion or missing adapter support. Non-root observations cannot silently fall back to absolute paths. Tests retain observations across a directory rename and across multiple chunks that share one anchor.                                                            |
| Bounded buffering      | `streaming` drains admitted chunks without waiting for the whole directory. Session and policy opt in explicitly. Total entry limits span chunks; retained memory along a deep active path is capped, and earlier observations survive a later limit. Complete-listing mode remains available for policies that need the entire listing. |
| Lazy consumer reads    | `Scan::read` admits one adapter-specific callback under the scan's governor/domain/cancellation/command ceiling. A query-shaped test reads only selected metadata through the original directory descriptor after rename. Callback unwinding preserves physical cost and releases the grant.                                             |
| Performance controls   | Cargo benchmarks include the historical fsql traversal, governed complete/streamed/bounded scans, and persistent Tree initial scanning. Balanced/wide/deep fixtures, controlled listing delay, resource sampling, and syscall reports are reproducible from the benchmark guide.                                                         |

`Scan::read` is the consumer-read boundary, and direct syscalls outside it are ungoverned. Call it before the scan is exhausted, because reads after exhaustion return `Shutdown`. It prefetches no SQL columns, manages no consumer caches, and keeps consumer schemas out of the traversal API. The bootstrap root is not a child of a listing, so it has no parent-listing anchor. `StdFileSystem` supports identity-preserving anchors on Unix, and other platforms fail required-anchor requests explicitly.

Bounded execution applies to listing leases. Bootstrap, domain resolution, session construction, enrichment, and admitted lazy callbacks run inline. Bounded execution makes no progress guarantee past arbitrary blocked kernel calls. A fully occupied worker pool cannot create replacement capacity. RFC §9.3 documents these boundaries, and the cancellation and ownership tests exercise them.

## Validation

- `cargo test --all-features --locked --quiet` reported 404 passed tests.
- `cargo clippy --all-targets --all-features --locked -- -D warnings` passed.
- `cargo doc --no-deps --all-features --locked` passed.
- `cargo fmt --check` and the documented Markdown and RFC formatting checks passed.
- Both `[[bench]]` targets passed correctness smoke checks. Every comparison mode verifies full path multisets before timing and checks counts during timing.
- From an fsql checkout beside the tree-fucker checkout, `cargo test -p fsql walk::tests --locked --config 'paths=["../tree-fucker"]'` reported 10 passed tests against the local tree-fucker library. The pinned dependency and lockfile are unchanged. This run validates compatibility. Adopting the new opt-in policies in fsql is a separate change in fsql.
- Review regressions cover duplicate command charges, separate resolution admission, atomic return of worker buffers, and panic failure surcharges.

## Measurement method

The measurements below come from the implementation committed as `4712e4b`. Later correctness fixes, including cursor-lifetime anchor reservations, are not in these timings.

The machine is an AMD Ryzen 9 3900X running Linux 7.1.10-1-MANJARO x86_64 with Rust 1.101.0-nightly (`5d8fec066`, 2026-10-16). Cargo's JSON artifact output supplied the path of the normal optimized `layers` executable. Timings are warm-cache medians of 15 measured traversals after two warmups, including setup and teardown. Modes run sequentially. The fixtures are synthetic and differ from the user's dprint checkout.

Each shape contains 20,000 sparse files plus directories and fixture symlinks: balanced has 20,013 rows, wide has 20,003, and deep has 20,066. The controlled-delay run uses the balanced shape and injects 1 ms per directory opening. It tests latency sensitivity and governor accounting. It does not test a real network mount, a cold disk, or an uninterruptible kernel fault. Separate barrier tests establish stuck-call and cancellation histories with no live remote filesystem.

The `fsql-walk-baseline` comparison source lives under [`benchmarks/baselines/fsql/`](baselines/fsql/README.md), and its README documents provenance and adaptations. It comes from fsql `d5ac9c80a2c5d8322d9ae096d6b0d860d73a4d4f`, with a minimal row adapter. It still creates owned paths and retains directory descriptors. The count-only scan modes omit absolute path materialization, and `scan-paths` adds that work for comparison. The baseline excludes SQL evaluation, output, and historical SQL-only row caches. The result says nothing about the complete historical fsql executable, and no production code calls the reference code.

`first_result_ms` excludes the root. `tree-initial` waits for the complete initial snapshot and includes runtime startup and shutdown. Incremental Tree update-stream latency is a separate measurement.

## Normal timing results

The first table shows median total traversal time in milliseconds. The delayed column uses the balanced fixture with 1 ms injected per directory opening. `std-count` receives no delay. `scan-stats` is diagnostic and omitted from timing comparisons.

| Mode                 | Balanced |    Wide |     Deep | Delayed |
| -------------------- | -------: | ------: | -------: | ------: |
| `std-count`          |    5.024 |   4.981 |    5.347 |   4.892 |
| `fsql-walk-baseline` |    7.492 |   7.112 |    9.886 |  20.412 |
| `scan-count`         |    8.010 |   7.382 |   10.165 |  20.631 |
| `scan-streaming`     |    7.818 |   7.578 |   10.836 |  21.464 |
| `scan-bounded`       |    8.868 |   9.606 |   12.748 |  21.849 |
| `scan-anchors`       |    8.010 |   7.786 |   10.857 |  21.445 |
| `scan-paths`         |   11.404 |   9.392 |   17.448 |  24.813 |
| `tree-initial`       |  102.975 | 103.412 | 2334.934 | 113.825 |

The second table shows median first non-root result latency in milliseconds. For `tree-initial`, this is initial snapshot readiness; total traversal also includes shutdown.

| Mode                 | Balanced |   Wide |     Deep | Delayed |
| -------------------- | -------: | -----: | -------: | ------: |
| `fsql-walk-baseline` |    0.042 |  0.050 |    0.051 |   2.161 |
| `scan-count`         |    0.045 |  5.549 |    0.149 |   1.103 |
| `scan-streaming`     |    0.031 |  1.416 |    0.163 |   1.110 |
| `scan-bounded`       |    0.131 |  7.680 |    0.274 |   1.190 |
| `scan-anchors`       |    0.033 |  5.788 |    0.167 |   1.108 |
| `scan-paths`         |    0.046 |  5.851 |    0.166 |   1.108 |
| `tree-initial`       |   94.175 | 95.811 | 2295.518 | 105.504 |

On the wide fixture, streaming cuts first-child latency from 5.549 ms to 1.416 ms while total time changes from 7.382 ms to 7.578 ms. On the balanced fixture, the bounded executor costs about 11% over inline complete listings, including a new pool per traversal. The frozen walker's owned-path traversal takes 7.492 ms versus 11.404 ms for `scan-paths`, which also performs governance. These controls do not isolate governance as the sole cause of that difference.

The persistent Tree control takes 102.975 ms on the balanced fixture and 2334.934 ms on the deep fixture, against 8.010 ms and 10.165 ms for `scan-count`. Waiting for its complete initial snapshot is slower than every scan mode on this transient workload. These measurements do not identify which internal Tree costs dominate.

## Separate resource probes

The fixed input was `target/benchmarks/acceptance-profile-input`, relative to the tree-fucker repository root, containing the balanced 20,000-file shape (20,013 rows). Each process ran 30 measured traversals, zero warmups, one verification traversal, two oracle walks, startup, and teardown. CPU totals come from `wait4` for that entire process and exclude the sampler and redactor. Private-memory and descriptor peaks are sampled lower bounds. Inspection and redaction add overhead to the 5 ms sampling sleep. The normal timings above come from separate runs.

| Mode                 | User CPU (s) | System CPU (s) | Sampled private peak (KiB) | Sampled FD peak | Samples |
| -------------------- | -----------: | -------------: | -------------------------: | --------------: | ------: |
| `fsql-walk-baseline` |        0.113 |          0.163 |                     11,828 |               7 |      38 |
| `scan-count`         |        0.141 |          0.155 |                     12,640 |               4 |      40 |
| `scan-streaming`     |        0.146 |          0.147 |                     12,568 |               4 |      40 |
| `tree-initial`       |        3.026 |          0.249 |                     58,144 |               4 |     397 |

Private memory sums `Private_Clean`, `Private_Dirty`, and `Private_Hugetlb` from the Linux process mapping report. The harness retains an oracle path vector during timing, so process peaks include that vector and do not isolate library memory. FD counts also include the process standard streams and runtime descriptors. Focused ownership tests establish the required-anchor and deep-buffer limits.

## Separate syscall probes

Each `strace -f -c` process used the same fixed input, one measured traversal, zero warmups, one verification traversal, and two independent oracle walks. Counts include startup, teardown and all worker threads, so they differ from the counts for one traversal. The timing tables exclude traced durations. The table lists selected filesystem calls:

| Mode                 | getdents64 | open | openat | close | statx | fstat | newfstatat |
| -------------------- | ---------: | ---: | -----: | ----: | ----: | ----: | ---------: |
| `fsql-walk-baseline` |        256 |    0 |     90 |    90 |     1 |    28 |          3 |
| `scan-count`         |        256 |   24 |     28 |    52 |    75 |    28 |          3 |
| `scan-streaming`     |        256 |   24 |     28 |    52 |    75 |    28 |          3 |
| `tree-initial`       |        256 |   24 |     29 |    53 |    73 |    28 |          3 |

## Reproduction artifacts

The committed [benchmark guide](README.md) provides the Cargo commands, fixture-shape and delay controls, resource sampler, and separate syscall-profiling commands. The [fsql baseline notes](baselines/fsql/README.md) identify the frozen source and adaptations. All generated fixtures and raw reports are in the ignored `target/benchmarks/` directory. The implementation and this report are versioned.

The run used the optimized `layers` benchmark executable that Cargo identified. The generated `target/benchmarks/acceptance-artifacts.jsonl` records its exact local path. Rebuild and extract the path as described in the guide, because Cargo artifact locations depend on the checkout and build configuration.

Raw timing reports are `acceptance-{balanced,wide,deep,delayed}.tsv`, with matching `.log` files. Resource reports are `acceptance-{MODE}-resources.json` (plus `.stdout` and `.stderr`), and syscall summaries are `acceptance-{MODE}-syscalls.txt`, all relative to `target/benchmarks/`. The mode names in these final reports match the documented benchmark interface.
