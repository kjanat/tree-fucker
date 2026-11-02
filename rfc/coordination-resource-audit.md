# Shared coordination resource bounds

This audit covers the shared authority, its per-connection state, recovery work, and the native resource evidence for PR #9. It does not impose a memory ceiling on caller-owned filesystem trees or on the number of independently opened connections.

## Retained authority

Let `P`, `O`, and `D` be the configured participant, operation, and domain capacities. `protocol::Limits` requires positive capacities, at most 4,096 participants and 65,536 operations, and a physical ceiling no larger than the operation capacity. `authority::Config` permits at most 4,096 domains.

| Resource                                       | Bound                                | Exhaustion behavior                                                              |
| ---------------------------------------------- | ------------------------------------ | -------------------------------------------------------------------------------- |
| Participant records and owner-slot names       | `P`                                  | Explicit participant-capacity error after a complete bounded recovery rotation   |
| Prepared and physically owned records together | `O`                                  | Explicit operation-capacity error                                                |
| Retained domain accounts                       | `D`                                  | Explicit domain-capacity error; accounts are not evicted to forgive debt         |
| Encoded snapshot capacity                      | `C = 1024 + 64P + 256O + 384D` bytes | Configuration and encoded-size checks reject overflow                            |
| Journal file                                   | `128 + 2C` bytes                     | Both slots and framing have a fixed length; reopening rejects a different length |

At the largest legal configuration, `C` is 18,613,248 bytes and the journal is 37,226,624 bytes. The reader separately caps an encoded snapshot at 32 MiB, so even an externally constructed journal header cannot request more than 67,108,992 bytes of framed journal storage. Decoding also checks the configured record limits and structural consistency.

The journal keeps two reusable payload buffers and a validated-payload cache. Decoded authority records and serialization buffers add transient storage proportional to `P + O + D + C`. This is a structural bound, not an exact Rust heap-size or RSS promise: collection representation, allocator capacity and the number of simultaneous connections affect those measurements. A retained buffer's high-water allocation may remain after records retire.

The model tests reject capacity exhaustion without mutation. Authority tests `bounded_domain_accounts_are_not_evicted_to_forgive_debt` and `sparse_snapshots_can_grow_to_domain_capacity_without_losing_live_accounting` cover retained domain growth. Journal corruption and byte-interruption tests check the fixed framing and complete-state publication rules.

## Connection state and recovery

The composed binding owns at most one entry for each of its live shared operations. Quarantine and domain-capacity retries are keyed by domain; budget retries are keyed by domain and origin, including the bootstrap account. These records are bounded by the domains registered in that binding. Successful admission clears the applicable retry records; a lock-busy result retains unrelated domain history. Failed domain registration does not insert a local mapping to an unregistered shared account.

Deferred settlement counts the task being attempted as well as queued tasks. Their sum cannot exceed `O`; overflow fences the connection. One worker per connection exists only while cleanup is pending. A busy attempt waits 2 ms before retrying. Empty cleanup starts no thread, timer, heartbeat or shared transaction. Physical completion and cancellation retain their owner handle until settlement commits, including when the application drops its final client reference.

Each native recovery transaction examines at most eight participant slots and retires at most eight operations. A join can perform up to `ceil(P / 8)` such transactions, releasing bookkeeping exclusion between them. A failed join keeps committed recovery progress. These are bounds on lifetime probes and retirement per acquisition; journal loading, validation and serialization still scale with the retained snapshot. They are not a constant-time claim.

Unix connections pin the rendezvous objects and each live owner description. Windows also pins each ancestor directory in the supplied path and keeps exclusive recovered-owner handles through commit. Ancestor-handle cost grows with path depth. Duplicate or inherited owner handles extend the associated lifetime; elapsed time alone never allows reclamation.

## Native measurements

[Coordination acceptance run 41372711016](https://github.com/kjanat/tree-fucker/actions/runs/41372711016) tested commit `6b996590e37f05c472ba37db6373e298ef772e18`. Its five `aggregate-resources-*` artifacts contain all 60 combinations of six scenarios (`tiny`, `disjoint`, `contention`, `churn`, `slow`, `idle`), two modes, and five native platforms. Every report has samples containing its required complete cohort, and every recorded peak equals the maximum of its samples. Tiny runs require two processes; the remaining scenarios require five.

The idle measurements below are peaks for the complete five-process cohort, including its controller. Private memory is the sum of unique resident bytes (USS). Handle counts mean file descriptors on Unix and kernel handles on Windows. Virtual-address reservations are reported separately in the artifacts and must not be interpreted as resident memory.

| Runner           | Process-only private bytes | Shared private bytes | Process-only handles | Shared handles |
| ---------------- | -------------------------: | -------------------: | -------------------: | -------------: |
| Ubuntu 26.04 x64 |                  1,052,672 |            1,130,496 |                   23 |             43 |
| macOS 26 ARM64   |                  3,637,248 |            3,883,008 |                   23 |             43 |
| macOS 26 Intel   |                    925,696 |            1,110,016 |                   23 |             43 |
| Windows 2025 x64 |                  2,850,816 |            3,084,288 |                  316 |            444 |
| Windows 11 ARM64 |                  3,371,008 |            3,694,592 |                  324 |            428 |

Every idle timing workload reported zero operations, rows, lock attempts, acquired locks and busy locks during its measurement interval. These jobs use `coordination_processes`, whose allocation counters are disabled; their zero allocation fields are placeholders, not allocation evidence. Instrumented allocation measurements use the separate `coordination_processes_alloc` executable. Startup and retained connection costs remain visible in the process samples above. These are observed costs for this fixture and revision, not per-process limits or a promise that operating-system CPU time is exactly zero.

A separate local Linux allocation run on 2026-11-02 used `target/release/build/tree-fucker/714f7d26763a5feb/out/coordination_processes_alloc-714f7d26763a5feb`, built from the same production source. Four idle workers in each mode reported zero allocations, reallocations, allocated bytes and authority accesses during the 200 ms measurement interval. This is instrumented Linux evidence for that interval; it does not establish allocator behavior on the other native runners. Reproduce it with:

```sh
CARGO_UNSTABLE_HINT_MSRV=false cargo bench --bench coordination_processes_alloc -- \
  --scenario idle --mode both --workers 4 --hold-ms 200 --runs 1 --warmups 0
```

The same run contains successful syscall collection on all five platforms. The [benchmark baseline](../benchmarks/coordination-baseline.md) describes the fixtures and their timing/allocation tradeoffs. Reproduce aggregate collection with `benchmarks/native_resources.py` and validate the resulting directory with `benchmarks/summarize_resources.py`, using the commands in the `Coordination acceptance` workflow. FreeBSD, illumos and Solaris evidence must be read separately; these five-runner measurements do not supply their native resource results.
