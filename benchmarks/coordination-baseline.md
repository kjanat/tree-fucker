# Shared coordination baseline

Measured on Linux x86-64 with an AMD Ryzen 9 3900X, Rust `1.101.0-nightly (5d8fec066 2026-10-16)`, and Cargo's optimized bench profile. This baseline measures the full-snapshot Linux authority with 64 participant slots, 128 operation slots, 128 domain slots, and a shared physical ceiling of two. The initial results below precede the duplicate-ledger allocation fix described in the final section.

The timing executable is `target/release/build/tree-fucker/01444fa73ab74f54/out/coordination_processes-01444fa73ab74f54`; the counting-allocator executable is `target/release/build/tree-fucker/030b3cda7bf652bf/out/coordination_processes_alloc-030b3cda7bf652bf`. Obtain rebuilt executable paths from Cargo's JSON output as shown in [the benchmark instructions](README.md#cpu-memory-descriptors-and-syscalls).

Fixtures contain generated 21-byte files under `target/benchmarks/coordination-workload-*`. Each directory contains 64 files. Scans return the root and all files, and reads verify the bytes. The shared authority lives in an isolated tmpfs scope.

## Workload timing

Both modes ran with four workers, 20 iterations per worker, one warmup and three measured rounds. The tiny case uses one worker. Churn uses four successive waves, each with four workers performing one read. Slow and idle holds are 100 ms. Modes alternate order between rounds.

```sh
cargo bench --bench coordination_processes -- \
  --workers 4 --iterations 20 --files 64 --runs 3 --warmups 1 \
  --waves 4 --hold-ms 100
```

| Scenario   | Work per round        | Local cohort median | Shared cohort median |
| ---------- | --------------------- | ------------------: | -------------------: |
| Tiny       | 20 reads              |            0.149 ms |             5.352 ms |
| Disjoint   | 80 scans, 5,200 rows  |            1.745 ms |           125.784 ms |
| Contention | 80 reads              |            1.176 ms |            49.730 ms |
| Churn      | 16 one-read processes |            3.113 ms |            80.160 ms |
| Slow       | 4 held FIFO reads     |          100.445 ms |           104.216 ms |
| Idle       | 4 joined processes    |          100.536 ms |           100.776 ms |

The cohort interval starts when ready workers are released and ends when all report completion. Churn sums those intervals across waves. Joining and process startup are recorded separately in the TSV; their median total wall interval for churn was 21.167 ms local and 141.320 ms shared. Raw rounds are in `target/benchmarks/coordination-timing.tsv`.

## Allocations and lock access

The counting-allocator executable ran separately with identical options. These are medians of aggregate allocation counts and bytes during worker execution, including pending settlement:

| Scenario   | Local allocations | Shared allocations | Local bytes | Shared bytes |
| ---------- | ----------------: | -----------------: | ----------: | -----------: |
| Tiny       |                68 |              1,507 |       6,480 |   12,870,608 |
| Disjoint   |            13,370 |             36,848 |   2,131,616 |  206,455,001 |
| Contention |               273 |              6,066 |      26,176 |   51,541,006 |
| Churn      |               118 |              1,583 |      11,680 |   13,509,541 |
| Slow       |                32 |                668 |       4,496 |    5,116,171 |
| Idle       |                 0 |                  0 |           0 |            0 |

The timing run's tiny case acquired the authority 61 times for 20 reads. The disjoint case acquired it 960 times for 80 full scans returning 5,200 rows. Idle workers made zero authority accesses. Raw allocation rounds are in `target/benchmarks/coordination-allocations.tsv`.

## Aggregate resources

The process-tree profiler ran separately with four workers and 2,000 reads each, one round, and no warmup. CPU includes startup, joining, verification, work, and teardown for the controller and all waited children. Memory and descriptor values are sampled aggregate peaks.

| Metric                       |       Local |      Shared |
| ---------------------------- | ----------: | ----------: |
| User CPU                     |    0.0181 s |    0.4775 s |
| System CPU                   |    0.0595 s |    1.7337 s |
| Private memory               |   1,020 KiB |   2,044 KiB |
| RSS                          |  16,324 KiB |  18,276 KiB |
| Mapped virtual bytes         | 300,269,568 | 577,576,960 |
| Open descriptors             |          25 |          44 |
| Voluntary context switches   |          33 |       1,941 |
| Involuntary context switches |          60 |         968 |

Both samples observed all five processes. Separate two-second idle runs also observed five processes, with zero worker authority accesses. Idle aggregate descriptor peaks were 23 local and 43 shared; private-memory peaks were 1,020 KiB and 1,288 KiB. Reports are `target/benchmarks/coordination-contention-{local,shared}.json` and `target/benchmarks/coordination-idle-{local,shared}.json`.

## Syscalls and optimization targets

Separate `strace -f -c` runs used four workers and 20 reads each, one round, and no warmup. Counts include startup, generated-fixture I/O, joining, work, and teardown:

| Syscall  | Local | Shared |
| -------- | ----: | -----: |
| `flock`  |     0 |    785 |
| `statx`  |    94 |  5,962 |
| `openat` |   359 |  1,091 |
| `read`   |   201 |  1,387 |
| `write`  |   270 |  1,422 |
| `lseek`  |    10 |  2,345 |
| `close`  |   375 |  1,107 |

Reports are `target/benchmarks/coordination-syscalls-{local,shared}.txt`. The shared trace recorded 195 unsuccessful `flock` calls, including busy lifetime probes and bookkeeping contention.

The initial active-work results identified two concrete costs to reduce. Each successful journal transaction read, validated, and decoded both snapshots, allocated bounded authority tables, and published another complete snapshot. Composed admission also used a fixed 10 ms retry delay after shared denial. The changes below retain corruption detection, ambiguous-dispatch ownership, replacement fencing, and accounting across participant exit, checked by the same benchmarks and interruption tests.

## First allocation fix

`Authority::decode` previously decoded the ownership ledger, constructed an authority with a second empty ledger, and immediately discarded that empty ledger. It now constructs the authority around the decoded ledger. Configuration, record, checksum, and accounting validation remain in place.

Both Cargo executables were rebuilt and rerun with the same options. Median allocation totals for shared work changed as follows:

| Scenario   | Allocations before | Allocations after | Bytes before | Bytes after |
| ---------- | -----------------: | ----------------: | -----------: | ----------: |
| Tiny       |              1,507 |             1,264 |   12,870,608 |  10,934,480 |
| Disjoint   |             36,848 |            32,988 |  206,455,001 | 175,286,323 |
| Contention |              6,066 |             5,109 |   51,541,006 |  43,800,334 |
| Idle       |                  0 |                 0 |            0 |           0 |

The tiny case allocates 15% fewer bytes while retaining 61 successful authority accesses for 20 reads. The after-change reports are `target/benchmarks/coordination-allocations-after.tsv` and `target/benchmarks/coordination-timing-after.tsv`. Codec corruption tests, journal byte-interruption tests, deterministic ownership/accounting tests, and all native subprocess acceptance tests pass after the change.

## Reusing snapshot validation

The journal now retains the last structurally validated payload. Each access still reads both slots and checks their framing, sequence, checksums, and configuration agreement. A payload with the same sequence and identical bytes can reuse that validation. The selected state is decoded into an independent authority before use; neither a mutable authority nor its accounting is cached. The retained payload is bounded by the journal's configured slot capacity.

The allocation executable ran before and after this change with one worker, 100 verified reads per round, one warmup, and three measured rounds:

```sh
cargo bench --bench coordination_processes_alloc -- \
  --scenario tiny --mode shared --workers 1 --iterations 100 --runs 3 --warmups 1
```

| Metric, median per round |     Before |      After |
| ------------------------ | ---------: | ---------: |
| Allocations              |      6,255 |      3,941 |
| Allocated bytes          | 53,970,136 | 27,492,000 |
| Authority acquisitions   |        301 |        301 |

Allocated bytes fell 49.1% and allocation count fell 37.0%. Reports are `target/benchmarks/coordination-journal-cache-{before,after}.tsv`, produced by the counting-allocator executable identified above. The existing byte-interruption and native writer-kill tests pass with this change. New cache tests modify both older and newest cached payloads while repairing their checksums, verify rejection, and check that another writer's committed accounting replaces the previously loaded state.

## Contention retry intervals

With snapshot validation reuse already enabled, the timing executable compared the fixed 10 ms retry with a 3 ms initial delay for lock and physical-capacity conflicts, doubling repeated denials up to 10 ms. Successful preparation or authorization resets the delay. Budget, bootstrap, and quarantined-domain denials retain 10 ms.

```sh
cargo bench --bench coordination_processes -- \
  --workers 4 --iterations 20 --files 64 --runs 5 --warmups 1 \
  --waves 4 --hold-ms 100
```

| Shared scenario | Fixed-delay median | Backoff median |
| --------------- | -----------------: | -------------: |
| Tiny            |           4.235 ms |       4.555 ms |
| Disjoint        |          87.832 ms |      79.661 ms |
| Contention      |          34.278 ms |      23.814 ms |
| Churn           |         123.267 ms |      79.256 ms |
| Slow            |         112.138 ms |     110.843 ms |
| Idle            |         100.438 ms |     100.271 ms |

Reports are `target/benchmarks/coordination-retry-{before,after}.tsv`. Both runs use the normal timing executable identified above. Local/shared order alternates by round. Idle workers make zero authority accesses in both runs. Disjoint median busy-lock attempts increased from 25 to 45; contention increased from 6 to 11. Trials starting at 100 microseconds or 1 ms caused more collisions and slower disjoint scans; their raw reports are `coordination-retry-100us.tsv` and `coordination-retry-1ms.tsv` in the same directory.

Separate resource samples used four workers with 2,000 contended reads each, one measured round, and no warmup. Aggregate user plus system CPU increased from 1.761 s to 1.928 s (9.5%), while total wall time decreased from 2.181 s to 2.103 s. Both samples observed five processes and a peak of 44 descriptors. Reports are `target/benchmarks/coordination-retry-resources-{before,after}.json`. Further contention work should reduce repeated authority access while retaining the shorter completion latency.
