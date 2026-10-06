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

A scan yields each listing's children as soon as that listing completes, and it keeps only the listings on the current path. Use `LoadDepth` to limit depth. With `ScanOptions::anchors` set, `StdFileSystem` attaches an anchor to each entry, holding the descriptor of the directory it was listed from, so follow-up reads can use `*at` calls. The scan also opens and probes each child directory through its parent's anchor instead of resolving the path again. The number of live anchors is capped.

The bundled `StdFileSystem` performs real platform-specific storage-domain probing on Linux, macOS, Windows, FreeBSD, illumos, and Solaris. Its current watcher capability is `None`, so it converges through direct reconciliation; custom `FileSystem` adapters can provide watcher events as low-latency hints.

## Storage domains

The library does not assume that every path beneath one root behaves like one filesystem.

A tree can cross into another mount, volume, network share, FUSE filesystem, Btrfs subvolume, or other storage domain with different identity rules, case sensitivity, watcher behaviour, metadata cost, and latency. Domain probes expose those properties to the scheduler and policy layer instead of burying them in heuristics.

The default crossing policy is deliberately conservative: newly encountered domains are left unloaded until requested rather than blindly walking from a local root into an arbitrary mounted subtree.

## Resource safety

This project exists partly because "walk the whole tree periodically" is a surprisingly effective way to make a machine miserable.

The host governor is process-wide. Multiple trees opened in one process share the same physical ceilings instead of each multiplying the allowed load. Work is charged to the storage domain that caused it, and a stuck domain can be quarantined without preventing healthy domains from making progress.

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
