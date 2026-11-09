# Shared coordination resource bounds

This audit covers the shared authority, its per-connection state, its recovery work, and the native resource evidence for PR #9. It sets no memory ceiling on caller-owned filesystem trees or on the number of independently opened connections.

## Retained authority

Let `P`, `O`, and `D` be the configured participant, operation, and domain capacities. `protocol::Limits` requires positive capacities, at most 4,096 participants and 65,536 operations, and a physical ceiling no larger than the operation capacity. `authority::Config` allows at most 4,096 domains.

| Resource                                       | Bound                                | Exhaustion behavior                                                              |
| ---------------------------------------------- | ------------------------------------ | -------------------------------------------------------------------------------- |
| Participant records and owner-slot names       | `P`                                  | Explicit participant-capacity error after a complete bounded recovery rotation   |
| Prepared and physically owned records together | `O`                                  | Explicit operation-capacity error                                                |
| Retained domain accounts                       | `D`                                  | Explicit domain-capacity error; accounts are not evicted to forgive debt         |
| Encoded snapshot capacity                      | `C = 1024 + 64P + 256O + 384D` bytes | Configuration and encoded-size checks reject overflow                            |
| Journal file                                   | `128 + 2C` bytes                     | Both slots and framing have a fixed length; reopening rejects a different length |

At the largest legal configuration, `C` is 18,613,248 bytes and the journal is 37,226,624 bytes. The reader caps an encoded snapshot at 32 MiB, so even a journal header built outside the library cannot request more than 67,108,992 bytes of framed journal storage. Decoding also checks the configured record limits and the structural consistency of the snapshot.

The journal keeps two reusable payload buffers and a cache of validated payloads. Decoded authority records and serialization buffers add transient storage proportional to `P + O + D + C`. This is a structural bound and makes no promise about exact Rust heap size or RSS, because the collection representation, the allocator capacity, and the number of simultaneous connections all change those measurements. A retained buffer can keep its high-water allocation after records retire.

The model tests reject capacity exhaustion without mutation. The authority tests `bounded_domain_accounts_are_not_evicted_to_forgive_debt` and `sparse_snapshots_can_grow_to_domain_capacity_without_losing_live_accounting` cover retained domain growth. The journal corruption tests and byte-interruption tests check the fixed framing and the rule that each publication is a complete state.

## Connection state and recovery

The composed binding holds at most one entry for each of its live shared operations. It keys quarantine and domain-capacity retries by domain, and it keys budget retries by domain and origin, including the bootstrap account. The number of domains registered in that binding bounds these records. A successful admission clears the applicable retry records, and a lock-busy result keeps the history of unrelated domains. A failed domain registration inserts no local mapping to an unregistered shared account.

Deferred settlement counts the task in progress as well as the queued tasks. Their sum cannot exceed `O`, and an overflow fences the connection. A connection has one worker only while cleanup is pending. A busy attempt waits 2 ms before it retries. Empty cleanup starts no thread, timer, heartbeat, or shared transaction. Physical completion and cancellation keep their owner handle until settlement commits, including when the application drops its final client reference.

Each native recovery transaction examines at most eight participant slots and retires at most eight operations. A join can run up to `ceil(P / 8)` such transactions and releases bookkeeping exclusion between them. A failed join keeps the recovery progress it committed. These bounds apply to lifetime probes and retirement per acquisition. Journal loading, validation, and serialization still scale with the retained snapshot, so recovery is not constant-time.

Unix connections pin the rendezvous objects and each live owner description. Windows connections also pin each ancestor directory in the supplied path and hold exclusive recovered-owner handles through the commit. The cost of the ancestor handles grows with path depth. Duplicate or inherited owner handles extend the lifetime of the owner they duplicate, and elapsed time alone never allows reclamation.

## Native measurements

[Coordination acceptance run 41372711016](https://github.com/kjanat/tree-fucker/actions/runs/41372711016) tested commit `6b996590e37f05c472ba37db6373e298ef772e18`. Its five `aggregate-resources-*` artifacts contain all 60 combinations of six scenarios (`tiny`, `disjoint`, `contention`, `churn`, `slow`, `idle`), two modes, and five native platforms. Every report has samples that contain its required complete cohort, and every recorded peak equals the maximum of its samples. Tiny runs need two processes. The other scenarios need five.

The resource jobs in [run 41386719491](https://github.com/kjanat/tree-fucker/actions/runs/41386719491) on `024dfad8116bbfc0f4bb93231cd63ae9dfecb19a` passed on all five runners after the collector's acknowledgement replaced the fixed startup hold. All sixty downloaded reports contain complete cohorts and correctly computed peaks. Every churn report acknowledges four distinct ready cohorts, and every other report acknowledges one. The ten idle workloads again report zero operations, rows, and bookkeeping attempts, acquisitions, and contention. This run verifies the resource jobs. It says nothing about the separate Windows session guest or the physical sleep job.

The same complete resource matrix passes again in [run 41391215417](https://github.com/kjanat/tree-fucker/actions/runs/41391215417) on `69d0f009a25f8f78d09ee2453f12a6e60fcb7d9e`, with the updated dependency set. An independent check of all 60 downloaded reports confirmed complete cohorts, exact sampled peaks, and per-wave acknowledgements. All ten idle outputs again show zero operations, rows, and bookkeeping activity.

The idle measurements below are peaks for the complete five-process cohort, including its controller. Private memory is the sum of unique resident bytes (USS). Handle counts are file descriptors on Unix and kernel handles on Windows. The artifacts report virtual-address reservations separately, and those reservations are not resident memory.

| Runner           | Process-only private bytes | Shared private bytes | Process-only handles | Shared handles |
| ---------------- | -------------------------: | -------------------: | -------------------: | -------------: |
| Ubuntu 26.04 x64 |                  1,052,672 |            1,130,496 |                   23 |             43 |
| macOS 26 ARM64   |                  3,637,248 |            3,883,008 |                   23 |             43 |
| macOS 26 Intel   |                    925,696 |            1,110,016 |                   23 |             43 |
| Windows 2025 x64 |                  2,850,816 |            3,084,288 |                  316 |            444 |
| Windows 11 ARM64 |                  3,371,008 |            3,694,592 |                  324 |            428 |

Every idle timing workload reported zero operations, rows, lock attempts, acquired locks, and busy locks during its measurement interval. These jobs use `coordination_processes`, which disables its allocation counters, so its zero allocation fields are placeholders and show nothing about allocations. The separate `coordination_processes_alloc` executable takes instrumented allocation measurements. The process samples above include the startup and retained connection costs. The numbers are observed costs for this fixture and revision. They are not per-process limits, and they do not show that operating-system CPU time is exactly zero.

A separate local Linux allocation run on 2026-11-02 used `target/release/build/tree-fucker/714f7d26763a5feb/out/coordination_processes_alloc-714f7d26763a5feb`, built from the same production source. Four idle workers in each mode reported zero allocations, reallocations, allocated bytes, and authority accesses during the 200 ms measurement interval. This is instrumented Linux evidence for that interval and says nothing about allocator behavior on the other native runners. Reproduce it with:

```sh
CARGO_UNSTABLE_HINT_MSRV=false cargo bench --bench coordination_processes_alloc -- \
  --scenario idle --mode both --workers 4 --hold-ms 200 --runs 1 --warmups 0
```

The same run collected syscalls successfully on all five platforms. The [benchmark baseline](../benchmarks/coordination-baseline.md) describes the fixtures and their timing and allocation tradeoffs. Reproduce aggregate collection with `benchmarks/native_resources.py`, and validate the resulting directory with `benchmarks/summarize_resources.py`, using the commands in the `Coordination acceptance` workflow. The five-runner measurements give no native resource results for FreeBSD, illumos, or Solaris, so read the evidence for those targets separately.
