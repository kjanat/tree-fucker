# tree-fucker

[![Crates.io](https://img.shields.io/crates/v/tree-fucker?logo=rust&labelColor=B7410E&color=black)][crates]

`tree-fucker` is a Rust library for maintaining an immutable, versioned, diffable view of a filesystem tree without trusting filesystem watchers for correctness.

It combines direct directory reconciliation, optional watcher hints, explicit storage-domain semantics, and a process-wide resource governor behind one interface. The library keeps converging on the real filesystem and limits the RAM and I/O it spends on slow, remote, very large, or broken filesystems.

> The crate is at version 0.1. The RFC is normative, and the test suite covers it natively on Linux, macOS, Windows, FreeBSD and illumos.

## What it does

A `Tree` represents a filesystem subtree as immutable `Snapshot`s. The tree publishes changes through an `UpdateStream`. A `TreeHandle` answers queries for the current snapshot, health state, and operational statistics.

Watcher events are only hints. Reconciliation eventually lists each loaded directory directly from the filesystem, so a missed, coalesced, overflowing, or unavailable watcher does not become the source of truth.

`tree-fucker` counts resource usage as part of correctness. A shared host governor admits filesystem work and bounds worker occupancy, background duty, burst capacity, listing size, represented entries, memory, and per-domain behaviour. The governor can quarantine a stuck SMB mount while healthy domains keep making progress.

## Design properties

- **Immutable snapshots.** Snapshots have stable versions and explicit diffs.
- **Watcher-independent correctness.** Watchers reduce latency, and reconciliation determines the represented state.
- **Bounded filesystem work.** The governor accounts for listings, metadata reads, domain probes, and watch registrations before they run.
- **Per-storage-domain isolation.** Local disks, remote mounts, userspace filesystems, and other domains can have independent capabilities, budgets, latency behaviour, and failure state.
- **Mount-crossing policy.** A tree can follow another storage domain, exclude it, or leave it unloaded until a caller requests it.
- **Stuck-worker accounting.** A blocked filesystem call keeps its physical slot in the accounting after its logical job is cancelled.
- **Bounded update streams.** The stream buffers a bounded number of updates. `LagMode` makes a slow consumer either disconnect or receive a reset to a current snapshot.
- **Runtime-neutral core.** The crate supplies a `Runtime` abstraction and an optional Tokio adapter.

[`rfc/tree-fucker.txt`](rfc/tree-fucker.txt) specifies the normative behaviour.

## Quick start

Add the dependency with Tokio integration:

```toml
[dependencies]
tree-fucker = { version = "0.1", features = ["tokio"] }
tokio       = { version = "1", features = ["macros", "rt", "time"] }
```

Cargo also builds this minimal tree as [`examples/tree.rs`](examples/tree.rs):

<!-- example: tree -->

```rust
use std::{path::PathBuf, sync::Arc};

use tree_fucker::{Config, LoadAll, Tree, runtime::TokioRuntime, std_fs::StdFileSystem};

#[tokio::main(flavor = "current_thread")]
async fn main() -> tree_fucker::Result<()> {
    let filesystem = Arc::new(StdFileSystem::new());
    let runtime = Arc::new(TokioRuntime::current());

    let (tree, mut updates) =
        Tree::open(filesystem, PathBuf::from("."), Arc::new(LoadAll), Config::default(), runtime).await?;

    tree.initial_scan_complete().await?;

    let snapshot = tree.snapshot();
    let health = tree.health();
    let stats = tree.stats();

    println!("snapshot: {snapshot:?}");
    println!("health: {health:?}");
    println!("stats: {stats:?}");

    // Stop reconciliation before draining the remaining updates.
    tree.shutdown().await?;
    while let Some(event) = updates.next().await {
        println!("{event:?}");
    }

    Ok(())
}
```

`TreeHandle` also exposes explicit `refresh`, `load`, `unload`, `invalidate_policy`, `set_priority`, and `shutdown` operations.

### One-shot scans

A consumer that walks a tree once, such as a query tool, opens a `Scan`. A `Scan` is a synchronous iterator with no runtime, snapshot, watcher, or reconciliation. Every operation goes through the process-wide governor and draws on the foreground allowance. Cargo also builds the example below as [`examples/scan.rs`](examples/scan.rs).

<!-- example: scan -->

```rust
use std::{path::PathBuf, sync::Arc};

use tree_fucker::{DomainCrossing, LoadAll, Scan, ScanEvent, ScanOptions, std_fs::StdFileSystem};

fn main() -> tree_fucker::Result<()> {
    let options = ScanOptions { crossing: DomainCrossing::Exclude, ..ScanOptions::default() };
    let scan = Scan::open(Arc::new(StdFileSystem::new()), PathBuf::from("."), Arc::new(LoadAll), options)?;
    for event in scan {
        match event? {
            ScanEvent::Entry(entry) => println!("{}", entry.path),
            ScanEvent::Boundary { path, mode, .. } => println!("{path}: mount not followed ({mode})"),
            ScanEvent::Unlisted { path, failure } => eprintln!("{path}: {failure}"),
        }
    }
    Ok(())
}
```

By default, a scan yields children after each directory listing completes. Set `ScanOptions::streaming` to yield a bounded chunk after each admitted lease instead. `StdFileSystem` and the built-in policies support this mode. Adapters and custom policies must explicitly declare chunk support. Directory entry limits apply across all chunks, and the host memory ceiling covers retained buffers along a deep traversal. Use `LoadDepth` to limit descent.

On Unix, `ScanOptions::anchors` lets `StdFileSystem` retain directory descriptors for relative `*at` reads and child traversal. Choose `AnchorPolicy::Required` when absolute-path fallback is unacceptable. With it, exhausted budgets and unsupported adapters produce an `Unlisted(ResourceLimited)` outcome, and the scan emits no unanchored non-root rows. A scan reserves an anchor slot before session construction and counts it while a cursor is detached or an observation retains it. All chunks of one listing share that reservation. `anchors_live` and `anchors_peak` include pending reservations. The bootstrap root has no parent-listing anchor. Optional retention is the default. Non-Unix `StdFileSystem` cannot currently provide an identity-preserving anchor.

For lazy metadata, call `scan.read(&entry, |entry| /* one adapter-specific read */)` before exhausting the iterator. The read reserves exactly one operation under the scan's governor, domain, cancellation, and command ceiling, and the callback can use the original anchor. Reads are lazy and consumer-defined. The callback runs inline and keeps its physical grant until it returns, including when it unwinds. A returned error or panic records a failure surcharge and updates domain error history before releasing that grant. Scan accounting does not cover raw consumer syscalls made outside this API. Use one admitted callback per physical read.

For listing calls that may block, opt into a reusable worker pool after opening the scan:

```rust,ignore
let executor = tree_fucker::ListingExecutor::new(2)?;
let scan = scan.with_listing_executor(executor.clone());
```

Clones share the worker limit. The pool creates workers lazily and reuses them across leases and scans, and starts no thread per directory. When a listing reaches the governor's stuck threshold, the scan reports that subtree as `Unlisted(Quarantined)` and can continue into healthy domains if both worker and governor capacity remain. A running call keeps its worker, physical grant, and buffer allowance until it returns, even if the scan is cancelled or dropped. If all workers are blocked, the next listing waits for capacity, cancellation, or its command ceiling; detached physical work continues to count during that wait. Every admission and worker wait detects newly stuck calls, including calls an earlier scan abandoned, and same-domain waiters then report quarantine. A stuck call records one failure surcharge and one domain error, and a later error or panic from the same physical call adds no further charge.

The worker pool applies to `ListingSession::resume`. Bootstrap, domain resolution, session construction, and enrichment run inline, so the pool gives no progress guarantee past a blocked call in those operations. The default scan runs entirely inline. Bounded listings reserve `max(1, in_flight_listing_bytes / maximum_in_flight)` bytes each, capped by the host accounted-memory ceiling minus this scan's retained buffers. That value is also the adapter's result-size ceiling. Inline listings respect the remaining per-scan allowance too. When the reservation fails, the scan reports a resource limit and stays within the host envelope. Completed-lease statistics exclude abandoned results, and the governor holds the authoritative physical occupancy and charges. Cancellation and stuck checks during worker waits run at intervals of at most 50 ms, subject to thread scheduling.

The bundled `StdFileSystem` probes storage domains with platform-specific code on Linux, macOS, Windows, FreeBSD, illumos, and Solaris. Its watcher capability is currently `None`, so it converges through direct reconciliation. Custom `FileSystem` adapters can provide watcher events as low-latency hints. A backend that needs recursive repair sends `WatcherEvent::Rescan { path }`, and the core reconciles every loaded directory under the normal governor limits. `coverage_pending` and the dropped-hint statistics show event loss. Watcher health reports backend failure separately.

Protocol clients use the same `FileSystem` contract and can use `domain::DeclaredProbe` for established capabilities. Adapters own transports, credentials, and native ACL payloads. `Metadata::permissions` holds optional permission bits. Portable ACLs and effective-access checks are outside its scope.

## Storage domains

The library treats the paths beneath one root as possibly spanning several storage domains.

A tree can cross into another mount, volume, network share, FUSE filesystem, Btrfs subvolume, or other storage domain with different identity rules, case sensitivity, watcher behaviour, metadata cost, and latency. Domain probes expose those properties to the scheduler and policy layer.

The default crossing policy leaves newly encountered domains unloaded until a caller requests them.

## Resource safety

The host governor is process-wide. Multiple trees opened in one process share the same physical ceilings. The governor charges work to the storage domain that caused it and can quarantine a stuck domain while healthy domains keep making progress.

Linux, FreeBSD, and illumos applications can opt into a shared authority before opening their first Scan or Tree:

```rust
use tree_fucker::{HostConfig, HostGovernor};
use tree_fucker::coordination::{Mode, Options, Rendezvous, authority};

let local = HostConfig::default();
let limits = authority::Config::from_host(&local, 64, 256, 128)?;
let governor = HostGovernor::install_with_coordination(local, Mode::Required(Options {
    scope: Rendezvous::Discover,
    limits,
}))?;
let status = governor.coordination_status();
```

FreeBSD discovery requires an administrator-mounted tmpfs at `/var/run/tree-fucker`. Host and jail processes with the same filesystem root and effective user share the retained authority. Processes with a different root cannot join it, and capability mode receives an unavailable result.

illumos discovery uses an administrator-created sticky directory at `/var/run/tree-fucker` on tmpfs. Root identity and the zone incarnation qualify each authority; domains without cross-process identity consume the shared aggregate allowance.

The macOS adapter uses an administrator-mounted tmpfs at `/var/run/tree-fucker`. [The platform contracts](rfc/coordination-platforms.md#macos) track its native acceptance. Physical sleep/wake acceptance remains outstanding in [#20](https://github.com/kjanat/tree-fucker/issues/20), so physical power transitions are unvalidated for this configuration. Shared coordination is unavailable on Solaris ([#19](https://github.com/kjanat/tree-fucker/issues/19)), and Solaris supports process-only operation.

The Windows adapter retains its journal under the effective user's OS-configured local application-data directory, verifies local NTFS/ReFS storage and protected permissions, and uses exclusive file handles for operation ownership. [The Windows contract](rfc/coordination-platforms.md#windows) tracks native acceptance and retained accounting across reboot.

`ProcessOnly` is the default. `Required` makes every governed operation use shared admission. `Auto` falls back to process-only operation when the native backend is unavailable before joining and reports the reason in `coordination_status()`. A busy, full, incompatible, or damaged authority returns an error. Once joined, a failed authority stops new work, and existing physical operations keep their ownership. `HostGovernor::configured` constructs the same policy for an explicit Scan or Tree governor. See the [coordination protocol](rfc/coordination.md) for scope lifetime, identity, and recovery.

If configured limits make required work impossible, the tree reports `ResourceLimited`.

## Compatibility and licensing

Shared coordination has an independent format contract: protocol 1, journal 1, and authority snapshots 2 (without clock binding) or 3 (with clock binding). See [coordination compatibility](rfc/coordination.md#release-compatibility) for joining and recovery rules. Authority names contain no crate version. The library preserves and rejects an incompatible or damaged authority and never replaces it with a new budget. After joining, an authority failure never falls back to process-only governance.

Copyright (c) 2026 Kaj Kowalski. Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

## Specification

The RFC is the contract:

- [`rfc/tree-fucker.txt`](rfc/tree-fucker.txt) is the canonical plaintext.
- The `rfc` workspace builds the generated HTML version, and GitHub Pages deploys it.

The implementation and tests aim to follow the RFC, which specifies consistency and resource-safety behaviour.

## Contributing

See [CONTRIBUTING.md](https://github.com/kjanat/tree-fucker/blob/master/CONTRIBUTING.md) for development setup, checks, package verification, and benchmarks.

## Name

Yes, the crate is called `tree-fucker`.

## Performance

Shared coordination trades extra CPU, allocation, and filesystem transactions for cross-process resource safety. Historical Linux measurements show the largest relative overhead for cheap cached reads, much smaller relative overhead for slow filesystem calls, and zero authority access while idle. See the [recorded baseline and optimizations](https://github.com/kjanat/tree-fucker/blob/master/benchmarks/coordination-baseline.md). Process-only governance is the default.

[crates]: https://crates.io/crates/tree-fucker
