# tree-fucker

`tree-fucker` is a Rust library for maintaining an immutable, versioned, diffable view of a filesystem tree without trusting filesystem watchers for correctness.

It combines direct directory reconciliation, optional watcher hints, explicit storage-domain semantics, and a process-wide resource governor behind one interface. The goal is simple: keep converging on reality without accidentally turning a slow, remote, gigantic, or broken filesystem into a six-hour RAM-and-I/O bonfire.

> **Status:** experimental. The specification is currently a draft and the API is not yet stable.

## What it does

A `Tree` represents a filesystem subtree as immutable `Snapshot`s. Changes are published through an `UpdateStream`, while the current snapshot, health state, and operational statistics remain directly queryable from a `TreeHandle`.

The important bit is that watcher events are only hints. A loaded directory is eventually listed directly from the filesystem during reconciliation, so a missed, coalesced, overflowing, or unavailable watcher does not silently become the source of truth.

`tree-fucker` also treats resource usage as part of correctness. Filesystem work is admitted through a shared host governor with bounded worker occupancy, background duty, burst capacity, listing size, represented entries, memory, and per-domain behaviour. A sick SMB mount should be able to ruin its own afternoon, not everyone else's.

## Design properties

- **Immutable snapshots** with stable versions and explicit diffs.
- **Watcher-independent correctness.** Watchers reduce latency; reconciliation establishes truth.
- **Bounded filesystem work.** Listings, metadata reads, domain probes, and watch registrations are accounted before they run.
- **Per-storage-domain isolation.** Local disks, remote mounts, userspace filesystems, and other domains can have independent capabilities, budgets, latency behaviour, and failure state.
- **Mount-crossing policy.** Crossing into another storage domain can be followed, excluded, or left unloaded until explicitly requested.
- **Stuck-worker accounting.** A blocked filesystem call keeps consuming the physical slot it actually occupies instead of disappearing from accounting because its logical job was cancelled.
- **Bounded update streams.** Slow consumers can either disconnect or receive a reset to a current snapshot rather than forcing unbounded buffering.
- **Runtime-neutral core.** The crate supplies a `Runtime` abstraction and an optional Tokio adapter.

The normative behaviour is specified in [`rfc/tree-fucker.txt`](rfc/tree-fucker.txt).

## Quick start

The crate currently uses Rust nightly. With Tokio integration:

```toml
[dependencies]
tree-fucker = { git = "https://github.com/kjanat/tree-fucker", features = ["tokio"] }
tokio       = { version = "1", features = ["macros", "rt-multi-thread", "time"] }
```

A minimal tree:

```rust
use std::{path::PathBuf, sync::Arc};

use tree_fucker::{Config, LoadAll, Tree, runtime::TokioRuntime, std_fs::StdFileSystem};

#[tokio::main]
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

    while let Some(event) = updates.next().await {
        println!("{event:?}");
    }

    Ok(())
}
```

`TreeHandle` also exposes explicit `refresh`, `load`, `unload`, `invalidate_policy`, `set_priority`, and `shutdown` operations.

### One-shot scans

A consumer that walks a tree once, such as a query tool, opens a `Scan` instead of a `Tree`. It is a synchronous iterator with no runtime, snapshot, watcher, or reconciliation. Every operation still goes through the process-wide governor and draws on the foreground allowance.

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

By default, a scan yields children after each directory listing completes. Set `ScanOptions::streaming` to yield a bounded chunk after each admitted lease instead. `StdFileSystem` and the built-in policies support this mode; adapters and custom policies must explicitly declare chunk support. Directory entry limits still apply across all chunks, and retained buffers along a deep traversal remain subject to the host memory ceiling. Use `LoadDepth` to limit descent.

On Unix, `ScanOptions::anchors` lets `StdFileSystem` retain directory descriptors for relative `*at` reads and child traversal. Choose `AnchorPolicy::Required` when absolute-path fallback is unacceptable: exhausted budgets and unsupported adapters produce an explicit `Unlisted(ResourceLimited)` outcome instead of unanchored non-root rows. An anchor slot is reserved before session construction and remains counted while a cursor is detached or an observation retains it. All chunks of one listing share that reservation. `anchors_live` and `anchors_peak` include pending reservations. The bootstrap root has no parent-listing anchor. Optional retention remains the default; non-Unix `StdFileSystem` currently cannot provide an identity-preserving anchor.

For lazy metadata, call `scan.read(&entry, |entry| /* one adapter-specific read */)` before exhausting the iterator. The read reserves exactly one operation using the scan's governor, domain, cancellation and command ceiling, and the callback can use the original anchor. Reads remain lazy and consumer-defined. The callback runs inline and keeps its physical grant until it returns, including unwinding. A returned error or panic records a failure surcharge and updates domain error history before releasing that grant. Raw consumer syscalls outside this API are outside scan accounting; use one admitted callback per physical read.

For listing calls that may block, opt into a reusable worker pool after opening the scan:

```rust,ignore
let executor = tree_fucker::ListingExecutor::new(2)?;
let scan = scan.with_listing_executor(executor.clone());
```

Clones share the worker limit. Workers are created lazily and reused across leases and scans; there is no thread per directory. When a listing reaches the governor's stuck threshold, the scan reports that subtree as `Unlisted(Quarantined)` and can continue into healthy domains if both worker and governor capacity remain. Cancelling or dropping the scan does not reclaim a running call's worker, physical grant, or buffer allowance. Those remain held until the call returns. If all workers are blocked, the next listing waits for capacity, cancellation, or its command ceiling; detached physical work continues to count during that wait. All admission and worker waits also detect newly stuck calls, including calls abandoned by an earlier scan. Same-domain waiters then report quarantine. A stuck call records one failure surcharge and one domain error; a later error or panic from that same physical call does not charge it again.

This opt-in applies to `ListingSession::resume`. Bootstrap, domain resolution, session construction, and enrichment still run inline, so it does not promise progress past a blocked call in those operations. The default scan remains entirely inline. Bounded listings reserve `max(1, in_flight_listing_bytes / maximum_in_flight)` bytes each, capped further by the host accounted-memory ceiling minus this scan's retained buffers. The resulting value is also the adapter's result-size ceiling. Inline listings likewise respect the remaining per-scan allowance. Reservation failure reports a resource limit rather than exceeding the host envelope. Completed-lease statistics exclude abandoned results; the governor retains authoritative physical occupancy and charges. Cancellation and stuck checks during worker waits occur at intervals of at most 50 ms, subject to thread scheduling.

The bundled `StdFileSystem` performs real platform-specific storage-domain probing on Linux, macOS, Windows, FreeBSD, illumos, and Solaris. Its current watcher capability is `None`, so it converges through direct reconciliation; custom `FileSystem` adapters can provide watcher events as low-latency hints.

## Storage domains

The library does not assume that every path beneath one root behaves like one filesystem.

A tree can cross into another mount, volume, network share, FUSE filesystem, Btrfs subvolume, or other storage domain with different identity rules, case sensitivity, watcher behaviour, metadata cost, and latency. Domain probes expose those properties to the scheduler and policy layer instead of burying them in heuristics.

The default crossing policy is deliberately conservative: newly encountered domains are left unloaded until requested rather than blindly walking from a local root into an arbitrary mounted subtree.

## Resource safety

This project exists partly because "walk the whole tree periodically" is a surprisingly effective way to make a machine miserable.

The host governor is process-wide. Multiple trees opened in one process share the same physical ceilings instead of each multiplying the allowed load. Work is charged to the storage domain that caused it, and a stuck domain can be quarantined without preventing healthy domains from making progress.

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

FreeBSD discovery requires an administrator-mounted tmpfs at `/var/run/tree-fucker`. Host and jail processes with the same filesystem root and effective user share the retained authority. Different roots cannot join that authority; capability mode receives an explicit unavailable result.

illumos discovery uses an administrator-created sticky directory at `/var/run/tree-fucker` on tmpfs. Root identity and the zone incarnation qualify each authority; domains without cross-process identity still consume the shared aggregate allowance.

The macOS adapter uses an administrator-mounted tmpfs at `/var/run/tree-fucker`; its native acceptance is tracked in [the platform contracts](rfc/coordination-platforms.md#macos).

The Windows adapter retains its journal under the effective user's OS-configured local application-data directory, verifies local NTFS/ReFS storage and protected permissions, and uses exclusive file handles for operation ownership. Native acceptance and retained accounting across reboot are tracked in [the Windows contract](rfc/coordination-platforms.md#windows).

`ProcessOnly` remains the default. `Required` requires shared admission for every governed operation. `Auto` permits process-only fallback when the native backend is unavailable before joining and reports the reason in `coordination_status()`. Busy, full, incompatible, or damaged authorities return errors. Once joined, a failed authority stops new work while existing physical operations retain their ownership. `HostGovernor::configured` constructs the same policy for an explicit Scan or Tree governor. See the [coordination protocol](rfc/coordination.md) for scope lifetime, identity, and recovery.

Hard limits do not masquerade as eventual convergence. If configured limits make required work impossible, the tree reports `ResourceLimited` rather than promising to finish someday.

## Specification

The RFC is the contract:

- [`rfc/tree-fucker.txt`](rfc/tree-fucker.txt) — canonical plaintext
- the generated HTML version is built by the `rfc` workspace and deployed through GitHub Pages

The implementation and tests are intended to follow the RFC rather than leave important consistency or resource-safety behaviour implicit in code.

## Development

The repository pins Rust nightly and includes `rustfmt`, Clippy, and `rust-analyzer` components.

Typical checks:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test --all-features
cargo doc --no-deps --all-features
```

The RFC site tooling uses Bun.

```sh
bun install
```

See the workflows in [`.github/workflows`](.github/workflows) for the platform matrix and site build used by CI.

## Name

Yes, the crate is called `tree-fucker`.

## Performance probes

The [benchmark guide](benchmarks/README.md) documents `cargo bench:layers` and `cargo bench:alloc` for raw Scan, anchor budgets, path materialization, allocation counts and profiling. Both probes run correctness smoke checks in CI.
