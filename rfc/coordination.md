# Cross-process governance protocol

Status: implementation in progress for [issue #1](https://github.com/kjanat/tree-fucker/issues/1).

This extension specifies the shared authority below the process governor. It does not change the default process-only mode or introduce shared filesystem observations. The requirements below are acceptance criteria; their presence in this document is not a backend support claim.

## Boundary and existing contracts

The scan contract in RFC §9.3 now includes governed lazy reads, bounded listing execution, streamed chunks, and completion-owned physical grants. Both that contract and persistent-tree execution must use the same shared operation boundary. Snapshots, paths, credentials, publication guards (§§10 and 13.5), application ceilings, and accounted process memory stay local.

An operation must satisfy both the process authority and the shared authority. The existing duty, foreground, bootstrap, stuck-domain, and physical-occupancy rules in §§15.1–15.4 continue to apply. Shared accounting is a second view of the same operation, not additional filesystem work. Observability (§16) distinguishes the two views.

The cooperating scope is explicitly identified by its security, namespace, clock, boot, and rendezvous lifetime. It is not automatically machine-wide. Clients that ignore this protocol remain outside the guarantee. Same-user cooperation is not a hostile-client security boundary.

## Identities and bounded state

A protocol version is independent of the crate version. A stable rendezvous must reject incompatible versions instead of creating parallel version-named budgets.

An authority has a nonzero generation. Each participant has a slot and a monotonically allocated incarnation within that generation. Each operation has a participant identity and a monotonically allocated sequence. Counters must fail on exhaustion, never wrap. Restart, slot reuse, and delayed messages cannot acquire the identity of earlier work.

Operation records are bounded independently of participant records. Completed operation records can be reclaimed because each participant retains its issued-sequence watermark. A missing, previously issued operation is terminal and cannot be created again. Slots cannot be reused while they own nonterminal operations.

Domain accounts, waiters, recovery work, diagnostics, journals, handles, and mappings need independent fixed bounds. Exhaustion returns a named capacity failure. No peer can request unbounded storage through a record length or table count. No Rust pointers or native mutex representations are part of the serialized protocol.

Domain matching requires positive namespace-qualified identity evidence. Process-local `StorageDomainId` numbers and equal paths are insufficient. Unknown identities still draw on the aggregate allowance. Traversal domains, filesystem identity spaces, and physical contention groups remain distinct.

## Operation ownership

The lifecycle is:

```text
Prepared -> StartAuthorized -> Running -> Settled
    |
    +----------------------------------> Aborted
```

`Prepared` holds provisional budget and bounded record space but no physical permit. Preparation is reversible and does not permanently charge a command for unsuccessful attempts to acquire the other authority.

`StartAuthorized` occupies physical capacity before dispatch. The owner may be interrupted immediately before or after entering the syscall; another participant must conservatively treat both histories as potentially running. `Running` is a diagnostic refinement, not the point where physical capacity is first consumed.

Cancellation can abort `Prepared`. Cancellation of either physical state only detaches the caller. Completion ownership stays with the worker. Timeouts, missed notifications, missing heartbeats, and lock-owner death do not establish physical completion.

Settlement is an idempotent transition containing cumulative work and failure accounting. Progress reports carry monotonically increasing revisions; duplicate reports cannot add another charge. The same revision with different payload is an error. Settlement cannot consume more operations than the grant permits, although elapsed occupancy may exceed the estimate and create debt.

Retired records cannot be restarted. A late settlement for a retired operation is harmless and cannot release another operation's capacity. Failed and stuck operations receive the existing failure surcharge once. The stuck-domain exception to global admission debt does not erase physical occupancy or domain debt.

## Composing the authorities

1. Prepare local budget without holding the process mutex afterward.
2. Attempt shared preparation without blocking.
3. On denial, abort provisional ownership before waiting.
4. Reconcile both reservations to the permitted operation count before physical authorization. The smaller permitted count wins.
5. Acquire physical authorization with nonblocking transitions.
6. Dispatch only after both authorities permit it.
7. Move ownership into the physical-completion guard.
8. Settle each authority once using the same cumulative operation facts.

No shared wait holds a process-governor mutex or target-filesystem worker. A bounded bookkeeping path may wait separately. Cancellation between every pair of transitions requires an executable history.

Local `try_admit` currently makes an irrevocable admission charge. Calling it repeatedly and using `release` as rollback is therefore incorrect. Provisional reservations require an explicit implementation; ordinary release retains its existing semantics.

Watch release retains its explicit duty-budget exception, but consumes shared physical capacity. Cleanup exceptions must be visible at both levels. Bootstrap, domain discovery, all listing leases, enrichment, lazy reads, persistent-tree jobs, watch registration, and watch release must all pass through this boundary.

## Crash consistency and recovery

Each storage transaction has a checked identity, revision, and commit decision. The backend must recover an interrupted update to a defined before or after state before admitting further work. A checksum detects damage; it does not establish that a debit or settlement committed.

The deterministic model injects interruption before and after each transition. The storage tests additionally interrupt each individual write and commit-marker update. The physical syscall may start only after its authorization is committed.

Operation reclamation requires completion or platform evidence that the owning execution ended. A PID alone is not such evidence. The backend must bind its lifetime evidence to the recorded incarnation, including inherited descriptors, fork, exec, and independently embedded crate copies. Owner exit cannot prove that a remote server stopped processing an already submitted request; the resource guarantee is about participating client execution and its conservative accounting.

Recovery retains all committed debt. A participant joining after the last participant exits inherits the existing buckets and outstanding liabilities. Refill follows the agreed scope clock, never a fresh process-relative `Instant`. Backward time and incompatible clock namespaces fail explicitly.

No timeout permits unlinking or replacing an authority. Replacement requires a lifetime barrier excluding all old participants, recovery of their liabilities, and a committed generation handoff. Until that protocol is implemented, automatic replacement is forbidden.

A participant suspended while holding the bookkeeping lock can delay the scope. Safety does not justify forcibly stealing its lock.

## Storage decision

Compare these candidates against the same fault histories:

| Candidate                               | Advantages                                                                                         | Obligations                                                                                                     |
| --------------------------------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Bounded local file with native locking  | Retains records after all applications exit; inspectable format; no shared native structure layout | Recover torn/interrupted updates; validate filesystem locality and object ownership; fence replacement          |
| Named shared memory with native locking | Direct access; potentially cheaper updates                                                         | Recover inconsistent state; define synchronization ABI; retain debt after final handle closes; fence recreation |

The initial Linux preference is a bounded file-backed ledger with a bounded journal/checkpoint scheme. This is provisional until actual recovery tests and coordination benchmarks establish its suitability. No database transaction or synchronization is required per directory child; a grant covers a bounded lease.

The implemented reference authority uses fixed-point refill, separate foreground and background buckets, and bounded domain accounts. Preparations hold budget without spending it. Elapsed physical occupancy, failure surcharges, and the stuck-domain debt exception are accounted on access. Domain records survive participant exit; exhausted domain capacity is an explicit error rather than eviction that resets an account. Process-local adaptive windows continue to tighten the shared physical ceiling.

The reference journal stores two bounded snapshots with explicit little-endian fields. Its stable header binds capacity and generation. A slot is marked preparing before any of its old data is overwritten; the other committed slot remains untouched. After all new data is written, a final one-byte commit decision permits publication. Recovery can adopt a complete preparing snapshot conservatively. A damaged committed snapshot fails closed instead of selecting an older budget. Checksums detect accidental damage; they do not authenticate peers.

The journal requires exclusive native bookkeeping synchronization and unbuffered host-local writes that survive process exit. It does not claim power-loss durability. Its tests inject interruption after every written byte of authorization and settlement, including snapshot-slot reuse. Native tests kill an actual tmpfs writer at ten publication boundaries for preparation, abort, authorization, progress, settlement, and owner-exit recovery. They reopen through `Scope`, compare complete before/after states, and replay each transition twice. The writer and operation owner are distinct, so bookkeeping-owner death cannot release a live owner's physical permit. The recovery case first launches a separate owner that completes filesystem work through `Prepared::try_run` and exits before publishing settlement, then kills the recovery writer. Initialization and inherited-lock histories are also tested in `tests/coordination_processes.rs`.

The snapshot implementation is a correctness baseline. The benchmark separates authority decision cost from full snapshot transaction cost; native workload measurements must determine whether incremental journaling or a validated cached representation is needed before rollout. Observation reuse does not excuse bypassing the authority.

`XDG_RUNTIME_DIR` is a candidate for private local rendezvous. Its lifetime ends at full logout. A runtime-directory backend must expose that scope and retain accounting across application exits within it. A claim across logout instead requires a separately established local retention and fencing contract. Neither a network home directory nor the filesystem being scanned is an acceptable implicit substitute.

Linux must validate type, ownership, mode, locality, size, header, clock scope, and generation. Open/create races and path substitution must be tested. Nonblocking native locks keep admission from indefinitely blocking an async executor. Lock ownership is not operation ownership.

The [native platform contracts](coordination-platforms.md) specify rendezvous, lifetime, synchronization, recovery, and activation gates for Windows, macOS, FreeBSD, illumos, and Solaris. Unavailable platforms return the configured explicit pre-join fallback or error; no dummy shared implementation is permitted.

## Linux implementation

`coordination::linux::Scope` opens an opt-in authority. `discover` uses a private directory on `/dev/shm`, qualified by effective user ID and the user, IPC, and time namespace identities. `open` accepts an explicit absolute tmpfs scope for application isolation and tests. `HostGovernor::with_coordination` joins that scope and composes its authority with local policy. The resulting governor can be supplied to Scan and Tree through their explicit-governor constructors.

Admission holds local and shared reservations provisionally. Start reserves local physical capacity, attempts shared authorization without holding the local mutex, and commits the local charge only after authorization succeeds. A denied start returns the provisional local physical slot. Queued cancellation aborts both budget holds. The final optional-operation count and local reservation cost are reduced to the shared allowance before the caller constructs a lease.

Linux domains established with `STATX_MNT_ID_UNIQUE` use a shared key qualified by the user namespace and authority generation. Declared, weak, and unknown identities use participant-private domain accounts within the same aggregate envelope. Process-local interned numbers are never interpreted as cross-process identity.

The lifetime is the retained tmpfs mount and compatible namespaces, rather than a login session. There is no implicit home-directory fallback. Reboot, unmount, namespace destruction, or deliberate deletion of both the rendezvous and state are outside this retained lifetime. The implementation does not defend against a cooperating user deliberately forging records or removing the entire authority. It never removes authority files itself.

The scope directory must be owned by the effective user with mode 0700. Regular state, anchor, and owner files require mode 0600, matching ownership, and a single link. Files are opened relative to pinned directory descriptors with no-follow and close-on-exec flags. A stable sibling anchor binds the scope directory and journal identities; replacing just the state directory cannot create another allowance. An initialized anchor with missing or replaced state fails closed. Anchor names contain no protocol or crate version.

Each access checks process identity before touching a mutex, rejects inherited API use after fork, checks namespace compatibility, and validates the pinned file identities. Admission acquires both the connection mutex and the interprocess anchor lock nonblockingly. A busy result permits retry outside the filesystem worker. The kernel monotonic clock supplies journal time in the agreed time namespace.

The composed governor retries lock and physical-capacity conflicts after 3 ms, doubling successive denied attempts up to 10 ms. Successful preparation or authorization resets that backoff. Budget, bootstrap, and quarantined-domain denials use 10 ms. Reading an upcoming retry deadline does not postpone it; expired hints retain their delay to avoid a tight loop when local constraints prevent another shared attempt. Waiting never holds a local governor mutex or a filesystem worker. Idle Trees arm no coordination timer unless work is waiting.

A participant holds an exclusive lifetime lock on its persistent slot file. The ledger records that file's device and inode with the participant incarnation. Recovery checks at most eight participant slots and retires at most eight operations per access, rotating through the table. It only reclaims a participant after acquiring the same lifetime lock while holding the authority lock. A removed or replaced owner file is an error, not evidence of death. Reclamation retains the incarnation until all of its outstanding records have settled.

Lifetime descriptors are closed, never explicitly unlocked. Consequently, a forked process retaining a duplicate can conservatively keep ownership alive after the original process dies. Suspended processes retain permits. Close-on-exec prevents an unrelated executed program from retaining those descriptors. Killing a bookkeeping lock holder does not by itself establish operation completion.

`Client::prepare` returns reversible ownership. `Prepared::try_run` commits start permission before invoking the physical callback and retains ownership until the callback returns or unwinds. Failed start attempts retain the preparation for retry. Successful completion reports cumulative counts; malformed completion reports and uncertain journal failures fence the connection. A busy settlement transfers ownership to a bounded queue and one short-lived bookkeeping thread per connection. That thread runs only while there is pending cleanup and never executes target-filesystem work.

Initialization has its own preparing/ready decision. Only an anchor that never published ready permits reinitializing an interrupted initial journal on the same inode. Once ready, corruption cannot trigger a reset. Journal generations, protocol versions, exact configuration, and scope identities must agree on every new connection.

Native initialization tests kill writers during partial anchor headers, the ready decision, initial journal headers, file extension, slot headers, payload publication, and the first commit decision. Recovery retains the generation and state inode pinned by a complete anchor. A partial anchor header is rejected unchanged. Recovered authorities admit real filesystem work and preserve its accounting across final-handle closure.

`Scope::view` exposes shared participants, physical occupancy, preparations, and accounting separately from local totals. `Scope::diagnostics` exposes effective scope, namespace identities, generation, configuration, failure state, pending bookkeeping, and connection access counters without acquiring the interprocess lock. The counters distinguish attempts, successful acquisitions, and busy connection/interprocess locks. No permanent maintenance thread or idle timer is created.

The native acceptance tests launch twenty independent processes. Their callbacks block in filesystem FIFO reads while a separate fixture counts actual entry and completion. The maximum observed concurrent dispatch must be two, including after the stuck threshold. The Scan cohort runs real bootstrap and lazy-read APIs. A mixed Scan/Tree cohort holds bootstrap, lazy-read, and shutdown watch-release callbacks concurrently. Other tests cover killed and stopped owners, inherited descriptors, final-handle debt retention, malformed initialization, replacement, panic settlement, and nonblocking cleanup.

## Failure modes and API policy

`ProcessOnly` is the default. Opt-in `Auto` can fall back before joining when policy permits, with an observable reason. `Required` starts no target-filesystem work without shared protection.

`coordination::Mode` selects `ProcessOnly`, `Auto(Options)`, or `Required(Options)`. Shared options specify discovery or an explicit directory and the authoritative limits. `HostGovernor::configured` constructs an explicit governor; `install_with_coordination` installs it before the first process-wide use. An already installed governor rejects another installation before opening its requested scope.

Auto fallback is restricted to an unsupported native platform or an unavailable pre-join rendezvous. Invalid configuration, unsafe storage, contention, capacity exhaustion, incompatibility, and damaged state return errors. A failure during or after joining never becomes a fallback. `coordination_status` retains the requested mode, effective state, shared participant/generation, namespace identity, limits, pending settlements, and failure reason. Process-only construction performs no native discovery.

Tree result classification precedes shared settlement, including validation failures, worker loss, and partial enrichment failures. A queued cancellation aborts both preparations without an admission charge or failure surcharge. A running cancellation retains the physical grant through its completion message. A confirming metadata read after `NotDirectory` receives its own bounded lease and start permission.

After joining, coordinator failure stops new shared work. It does not discard liabilities or quietly enable independent admission. A full, malformed, or incompatible ledger does not authorize a replacement. Recovery state, effective scope, limits, participants, physical occupancy, debt, and wait causes are observable (§16).

## Acceptance histories

Acceptance requires these histories:

- Every cancellation and interruption boundary, including ambiguous dispatch, duplicate reports, and completion before publication.
- Twenty independent participants under a physical ceiling of two, checking actual dispatch of bootstrap, lazy reads, and watch cleanup.
- Paused live participants, owner death, PID/incarnation reuse, creation races, restart storms, and final-participant exit.
- Healthy work alongside stuck domains without forgotten occupancy.
- Capacity exhaustion, malformed state, mixed versions, notification loss, incompatible namespaces, and generation replacement attempts.
- Identical work histories under one and many participants.

Repository-owned Cargo benchmarks compare process-only and shared governance on tiny warm work, disjoint directories, contention, churn, slow work, and idle scopes. Measure aggregate CPU, latency, allocations, coordination syscalls, contention, wakeups, handles, and mapped bytes. Observation reuse is a separate proposal and benchmark dimension.

Issue #1 stays open until the agreed native support matrix, integration, recovery histories, diagnostics, and measured overhead are verified. Intermediate protocol milestones do not close the whole issue.
