# Cross-process governance protocol

Status: implementation in progress for [issue #1](https://github.com/kjanat/tree-fucker/issues/1).

This extension specifies the shared authority below the process governor. It leaves the default process-only mode unchanged and adds no shared filesystem observations. The requirements below are acceptance criteria. Their presence in this document makes no claim that a backend supports them.

## Boundary and existing contracts

The scan contract in RFC §9.3 includes governed lazy reads, bounded listing execution, streamed chunks, and completion-owned physical grants. That contract and persistent-tree execution must use the same shared operation boundary. Snapshots, paths, credentials, publication guards (§§10 and 13.5), application ceilings, and accounted process memory stay local.

An operation must satisfy both the process authority and the shared authority. The duty, foreground, bootstrap, stuck-domain, and physical-occupancy rules in §§15.1–15.4 continue to apply. Shared accounting is a second view of the same operation and adds no filesystem work. Observability (§16) reports the two views separately.

The cooperating scope is explicitly identified by its security, namespace, clock, boot, and rendezvous lifetime. A scope spans the whole machine only when every participant on the machine shares that identity. Clients that ignore this protocol are outside the guarantee. Same-user cooperation provides no security boundary against a hostile client.

## Identities and bounded state

A protocol version is independent of the crate version. A stable rendezvous must reject incompatible versions and must never create parallel version-named budgets.

### Release compatibility

The `0.1.x` crate series uses rendezvous protocol version 1 and journal format 1. It reads and writes authority snapshot format 2 without a clock binding and format 3 with a clock binding. Unix authorities use format 2. Windows authorities use format 3 to bind retained accounting to their clock history. Native anchor formats and namespace identities must also match. The Unix anchor format is 1.

A participant may join and recover an authority only when its protocol, storage formats, exact configuration, generation, and native identity checks succeed. An unknown version returns an incompatibility error before admission. Malformed or replaced storage fails closed. The caller must report the error and use a compatible implementation or an explicit administrative migration. Deleting the authority to get a fresh budget is not a recovery path. A Cargo upgrade creates no version-named rendezvous and clears no retained liabilities. `Auto` does not fall back for incompatible versions, and no mode falls back after joining.

An authority has a nonzero generation. Each participant has a slot and a monotonically allocated incarnation within that generation. Each operation has a participant identity and a monotonically allocated sequence. Counters must fail on exhaustion and must never wrap. Restart, slot reuse, and delayed messages cannot acquire the identity of earlier work.

Operation records are bounded independently of participant records. Each participant retains its issued-sequence watermark, so the authority can reclaim completed operation records. A missing operation with a previously issued sequence is terminal and cannot be created again. A slot cannot be reused while it owns nonterminal operations.

Domain accounts, waiters, recovery work, diagnostics, journals, handles, and mappings each need an independent fixed bound. Exhaustion returns a named capacity failure. A record length or table count in a peer's data cannot make the authority allocate unbounded storage. The serialized protocol contains no Rust pointers and no native mutex representations.

Domain matching requires positive namespace-qualified identity evidence. Process-local `StorageDomainId` numbers and equal paths are insufficient. Unknown identities still draw on the aggregate allowance. Traversal domains, filesystem identity spaces, and physical contention groups remain distinct.

## Operation ownership

The lifecycle is:

```text
Prepared -> StartAuthorized -> Running -> Settled
    |
    +----------------------------------> Aborted
```

`Prepared` holds provisional budget and bounded record space but no physical permit. Preparation is reversible. A command pays no permanent charge for unsuccessful attempts to acquire the other authority.

`StartAuthorized` occupies physical capacity before dispatch. The owner may be interrupted immediately before or after entering the syscall, so another participant must treat both histories as potentially running. `Running` is a diagnostic refinement. The operation first consumes physical capacity at `StartAuthorized`.

Cancellation can abort `Prepared`. Cancellation of either physical state only detaches the caller, and the worker keeps completion ownership. Timeouts, missed notifications, missing heartbeats, and lock-owner death do not establish physical completion.

Settlement is an idempotent transition that carries cumulative work and failure accounting. Progress reports carry monotonically increasing revisions, and a duplicate report adds no further charge. The same revision with a different payload is an error. Settlement cannot consume more operations than the grant permits. Elapsed occupancy may exceed the estimate and create debt.

A retired record cannot be restarted. A late settlement for a retired operation has no effect and cannot release another operation's capacity. Failed and stuck operations receive the existing failure surcharge once. The stuck-domain exception to global admission debt leaves physical occupancy and domain debt in place.

## Composing the authorities

1. Prepare local budget, then release the process mutex.
2. Attempt shared preparation without blocking.
3. On denial, abort provisional ownership before waiting.
4. Reconcile both reservations to the permitted operation count before physical authorization. The smaller permitted count wins.
5. Acquire physical authorization with nonblocking transitions.
6. Dispatch only after both authorities permit it.
7. Move ownership into the physical-completion guard.
8. Settle each authority once using the same cumulative operation facts.

No shared wait holds a process-governor mutex or a target-filesystem worker. A bounded bookkeeping path may wait separately. Cancellation between every pair of transitions requires an executable history.

Local `try_admit` makes an irrevocable admission charge. Calling it repeatedly and using `release` as rollback is therefore incorrect. Provisional reservations need an explicit implementation, and ordinary release keeps its existing semantics.

Watch release keeps its explicit duty-budget exception and consumes shared physical capacity. Cleanup exceptions must be visible at both levels. Bootstrap, domain discovery, all listing leases, enrichment, lazy reads, persistent-tree jobs, watch registration, and watch release must all pass through this boundary.

## Crash consistency and recovery

Each storage transaction has a checked identity, revision, and commit decision. The backend must recover an interrupted update to a defined before or after state before it admits further work. A checksum detects damage. It cannot show that a debit or settlement committed.

The deterministic model injects interruption before and after each transition. The storage tests also interrupt each individual write and commit-marker update. The physical syscall may start only after its authorization commits.

Operation reclamation requires completion or platform evidence that the owning execution ended. A PID alone is not such evidence. The backend must bind its lifetime evidence to the recorded incarnation, including inherited descriptors, fork, exec, and independently embedded crate copies. Owner exit cannot prove that a remote server stopped processing an already submitted request. The resource guarantee covers participating client execution and its conservative accounting.

Recovery retains all committed debt. A participant that joins after the last participant exits inherits the existing buckets and outstanding liabilities. Refill follows the agreed scope clock and never a fresh process-relative `Instant`. Backward time and incompatible clock namespaces fail with an explicit error.

No timeout permits unlinking or replacing an authority. Replacement requires a lifetime barrier that excludes all old participants, recovery of their liabilities, and a committed generation handoff. Automatic replacement is forbidden until that protocol exists.

A participant suspended while it holds the bookkeeping lock can delay the scope. Forcibly stealing the lock is forbidden.

## Storage decision

Compare these candidates against the same fault histories:

| Candidate                               | Advantages                                                                                         | Obligations                                                                                                     |
| --------------------------------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Bounded local file with native locking  | Retains records after all applications exit; inspectable format; no shared native structure layout | Recover torn/interrupted updates; validate filesystem locality and object ownership; fence replacement          |
| Named shared memory with native locking | Direct access; potentially cheaper updates                                                         | Recover inconsistent state; define synchronization ABI; retain debt after final handle closes; fence recreation |

The initial Linux preference is a bounded file-backed ledger with a bounded journal/checkpoint scheme. This choice is provisional until recovery tests and coordination benchmarks confirm it. A directory child needs no database transaction or synchronization, because a grant covers a bounded lease.

The reference authority uses fixed-point refill, separate foreground and background buckets, and bounded domain accounts. Preparations hold budget without spending it. The authority accounts elapsed physical occupancy, failure surcharges, and the stuck-domain debt exception on access. Domain records survive participant exit. Exhausted domain capacity returns an explicit error, and the authority never evicts or resets a domain account. Process-local adaptive windows continue to tighten the shared physical ceiling. When an operation becomes stuck, all globally charged occupancy beyond its reservation moves to withheld debt, including overshoot accrued before detection. Domain debt and physical occupancy remain charged. Settlement or proven owner exit restores the withheld global debt exactly once.

The reference journal stores two bounded snapshots with explicit little-endian fields. Its stable header binds capacity and generation. The journal marks a slot as preparing before it overwrites any old data in that slot, and the other committed slot stays untouched. After all new data is written, a final one-byte commit decision permits publication. Recovery can adopt a complete preparing snapshot conservatively. A damaged committed snapshot fails closed and recovery never selects an older budget. Checksums detect accidental damage and do not authenticate peers.

The journal requires exclusive native bookkeeping synchronization and unbuffered host-local writes that survive process exit. It makes no power-loss durability claim. Its tests inject interruption after every written byte of authorization and settlement, including snapshot-slot reuse. Native tests kill a tmpfs writer at ten publication boundaries for preparation, abort, authorization, progress, settlement, and owner-exit recovery. They reopen through `Scope`, compare the complete states before and after each transition, and replay each transition twice. The writer and the operation owner are distinct processes, so the death of the bookkeeping owner cannot release a live owner's physical permit. The recovery case first launches a separate owner that completes filesystem work through `Prepared::try_run` and exits before publishing settlement, then kills the recovery writer. `tests/coordination_processes.rs` also tests initialization and inherited-lock histories.

The snapshot implementation is a correctness baseline. The benchmark separates authority decision cost from full snapshot transaction cost. Native workload measurements must determine whether incremental journaling or a validated cached representation is needed before rollout. Observation reuse never permits bypassing the authority.

`XDG_RUNTIME_DIR` is a candidate for private local rendezvous. Its lifetime ends at full logout. A runtime-directory backend must expose that scope and retain accounting across application exits within it. A claim that spans logout needs a separately established local retention and fencing contract. A network home directory and the filesystem being scanned are both unacceptable implicit substitutes.

Linux must validate type, ownership, mode, locality, size, header, clock scope, and generation. Tests must cover open/create races and path substitution. Nonblocking native locks keep admission from blocking an async executor indefinitely. Lock ownership is distinct from operation ownership.

The [native platform contracts](coordination-platforms.md) specify rendezvous, lifetime, synchronization, recovery, and activation gates for Windows, macOS, FreeBSD, illumos, and Solaris. An unavailable platform returns the configured explicit pre-join fallback or error. A dummy shared implementation is forbidden.

## Linux implementation

`coordination::linux::Scope` opens an opt-in authority. `discover` uses a private directory on `/dev/shm` and qualifies it by the effective user ID and the user, IPC, and time namespace identities. `open` accepts an explicit absolute tmpfs scope for application isolation and tests. `HostGovernor::with_coordination` joins that scope and composes its authority with local policy. Callers can pass the resulting governor to Scan and Tree through their explicit-governor constructors.

Admission holds local and shared reservations provisionally. Start reserves local physical capacity, attempts shared authorization without holding the local mutex, and commits the local charge only after authorization succeeds. A denied start returns the provisional local physical slot. Queued cancellation aborts both budget holds. Before the caller constructs a lease, the governor reduces the final optional-operation count and local reservation cost to the shared allowance.

Linux domains established with `STATX_MNT_ID_UNIQUE` use a shared key qualified by the user namespace and authority generation. Declared, weak, and unknown identities use participant-private domain accounts within the same aggregate envelope. The implementation never interprets a process-local interned number as a cross-process identity.

The lifetime is the retained tmpfs mount and compatible namespaces. A login session does not bound it. There is no implicit home-directory fallback. Any of reboot, unmount, namespace destruction, or deliberate deletion of both the rendezvous and the state ends the retained lifetime. The implementation gives no defense against a cooperating user who forges records or removes the entire authority. It never removes authority files itself.

The scope directory must be owned by the effective user with mode 0700. Regular state, anchor, and owner files require mode 0600, matching ownership, and a single link. The implementation opens files relative to pinned directory descriptors with no-follow and close-on-exec flags. A stable sibling anchor binds the scope directory and journal identities, so replacing only the state directory cannot create another allowance. An initialized anchor with missing or replaced state fails closed. Anchor names contain no protocol or crate version.

Each access checks process identity before it touches a mutex, rejects inherited API use after fork, checks namespace compatibility, and validates the pinned file identities. Admission acquires both the connection mutex and the interprocess anchor lock without blocking. A busy result permits a retry outside the filesystem worker. The kernel monotonic clock supplies journal time in the agreed time namespace.

The composed governor retries lock and aggregate physical-capacity conflicts after 3 ms and doubles the delay on successive denied attempts up to 10 ms. These conflicts block every account. Per-domain physical-capacity denials use the same bounded backoff for that domain only. Budget and bootstrap denials use 10 ms per domain and work origin, so another domain or origin can still attempt admission. Watch-release cleanup bypasses budget backoff and still obeys physical capacity and quarantine. Cleanup and unrelated admissions leave another account's budget retry in place.

The governor keeps quarantine backoff per domain. A domain's quarantine denials start at 10 ms, and each consecutive quarantine denial of that domain doubles the delay up to 1 s. While a backoff is pending, the composed governor refuses affected preparations and starts before any shared attempt. A successful preparation or authorization resets the global lock backoff and the applicable domain and origin records. Any other shared answer for a domain clears its quarantine backoff. A Busy answer sets the global lock retry and preserves domain records. Reading an upcoming retry deadline does not postpone it. A queued preparation subject to a scoped backoff uses that deadline and ignores an earlier generic retry. Expired global hints keep their delay to avoid a tight loop when local constraints prevent another shared attempt.

Waiting holds neither a local governor mutex nor a filesystem worker. An idle Tree arms no coordination timer unless work is waiting. A governor change wakes a Tree. A peer's stuck operation settles without sending this participant any input. Tree reads cancelled under a peer's quarantine wait on the quarantine retry.

A participant holds an exclusive lifetime lock on its persistent slot file. The ledger records that file's device and inode with the participant incarnation. Recovery checks at most eight participant slots and retires at most eight operations per authority-lock acquisition, and it rotates through the table. Joining inspects a complete table rotation before it reports participant exhaustion. Each bounded batch commits, and the join releases the authority lock between batches. A failed join retains the operations it reclaimed, so fresh connections keep making progress when an abandoned participant needs several batches. Recovery reclaims a participant only after it acquires the same lifetime lock while it holds the authority lock. A removed or replaced owner file is an error and gives no evidence of death. Reclamation retains the incarnation until all of its outstanding records have settled.

Lifetime descriptors are closed and never explicitly unlocked. A forked process that holds a duplicate can therefore keep ownership alive after the original process dies. Suspended processes retain permits. Close-on-exec keeps an unrelated executed program from retaining those descriptors. Killing a bookkeeping lock holder does not by itself establish operation completion.

`HostGovernor::try_prepare` retains the caller's ceiling separately from its local cost hold. Commit can tighten local repricing to the held amount without passing that amount to the shared authority as a caller limit. Each authority prices the same operation against the original caller allowance.

`Client::prepare` returns reversible ownership. `Prepared::try_run` commits start permission before it invokes the physical callback and retains ownership until the callback returns or unwinds. Failed start attempts retain the preparation for retry. Successful completion reports cumulative counts. A malformed completion report or an uncertain journal failure fences the connection. A busy settlement transfers ownership to a bounded queue and one short-lived bookkeeping thread per connection. That thread runs only while cleanup is pending and never executes target-filesystem work.

Initialization has its own preparing/ready decision. Only an anchor that never published ready permits reinitializing an interrupted initial journal on the same inode. After the anchor publishes ready, corruption cannot trigger a reset. Journal generations, protocol versions, exact configuration, and scope identities must agree on every new connection.

Native initialization tests kill writers during partial anchor headers, the ready decision, initial journal headers, file extension, slot headers, payload publication, and the first commit decision. Recovery retains the generation and state inode pinned by a complete anchor. Recovery rejects a partial anchor header and leaves it unchanged. Recovered authorities admit real filesystem work and preserve its accounting across final-handle closure.

`Scope::view` exposes shared participants, physical occupancy, preparations, and accounting separately from local totals. `Scope::diagnostics` exposes effective scope, namespace identities, generation, configuration, failure state, pending bookkeeping, and connection access counters without acquiring the interprocess lock. The counters distinguish attempts, successful acquisitions, and busy connection and interprocess locks. The implementation creates no permanent maintenance thread and no idle timer.

The native acceptance tests launch twenty independent processes. Their callbacks block in filesystem FIFO reads while a separate fixture counts actual entry and completion. The maximum observed concurrent dispatch must be two, including after the stuck threshold. The Scan cohort runs real bootstrap and lazy-read APIs. A mixed Scan/Tree cohort holds bootstrap, lazy-read, and shutdown watch-release callbacks concurrently. Other tests cover killed and stopped owners, inherited descriptors, final-handle debt retention, malformed initialization, replacement, panic settlement, and nonblocking cleanup.

## Failure modes and API policy

`ProcessOnly` is the default. Opt-in `Auto` can fall back before joining when policy permits, with an observable reason. `Required` starts no target-filesystem work without shared protection.

`coordination::Mode` selects `ProcessOnly`, `Auto(Options)`, or `Required(Options)`. Shared options specify discovery or an explicit directory and the authoritative limits. `HostGovernor::configured` constructs an explicit governor, and `install_with_coordination` installs it before the first process-wide use. An already installed governor rejects another installation before it opens the requested scope.

Auto fallback applies only to an unsupported native platform or an unavailable pre-join rendezvous. Invalid configuration, unsafe storage, contention, capacity exhaustion, incompatibility, and damaged state return errors. A failure during or after joining never becomes a fallback. `coordination_status` retains the requested mode, effective state, shared participant and generation, namespace identity, limits, pending settlements, and failure reason. Process-only construction performs no native discovery.

Tree result classification precedes shared settlement, including validation failures, worker loss, and partial enrichment failures. A queued cancellation aborts both preparations with no admission charge and no failure surcharge. A running cancellation retains the physical grant through its completion message. A confirming metadata read after `NotDirectory` receives its own bounded lease and start permission.

When the governor prices other work, command ceilings count queued preparations as reversible holds. A hold alone cannot exhaust a command. Cancelling an unstarted shared lease refunds that lease's command hold and preserves charges and overshoot from earlier physical leases, including when a suspended session had acquired its next preparation.

After joining, a coordinator failure stops new shared work. It discards no liabilities and enables no independent admission. A full, malformed, or incompatible ledger does not authorize a replacement. Recovery state, effective scope, limits, participants, physical occupancy, debt, and wait causes are observable (§16).

## Acceptance histories

Acceptance requires these histories:

- Every cancellation and interruption boundary, including ambiguous dispatch, duplicate reports, and completion before publication.
- Twenty independent participants under a physical ceiling of two, checking actual dispatch of bootstrap, lazy reads, and watch cleanup.
- Paused live participants, owner death, PID/incarnation reuse, creation races, restart storms, and final-participant exit.
- Healthy work alongside stuck domains with no forgotten occupancy.
- Capacity exhaustion, malformed state, mixed versions, notification loss, incompatible namespaces, and generation replacement attempts.
- Identical work histories under one and many participants.

Repository-owned Cargo benchmarks compare process-only and shared governance on tiny warm work, disjoint directories, contention, churn, slow work, and idle scopes. They measure aggregate CPU, latency, allocations, coordination syscalls, contention, wakeups, handles, and mapped bytes. Observation reuse is a separate proposal and benchmark dimension.

Issue #1 stays open until the agreed native support matrix, integration, recovery histories, diagnostics, and measured overhead are verified. Intermediate protocol milestones do not close the issue.
