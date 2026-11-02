//! Benchmarks for admission, ownership, accounting, and native coordination.

use std::hint::black_box;
use std::io::Cursor;
use std::time::{Duration, Instant};

use tree_fucker::coordination::authority::{Authority, Config as SharedConfig, Origin, Request};
use tree_fucker::coordination::journal::Journal;
use tree_fucker::coordination::protocol::{
    Generation, Ledger, Limits, Progress, Reservation as SharedReservation, VERSION, Work,
};
use tree_fucker::core::{GrantId, MonotonicTime, Reservation, WorkOrigin};
use tree_fucker::{HostConfig, HostGovernor, RelativePath};

fn host_config() -> HostConfig {
    HostConfig {
        foreground_duty: 1.0,
        foreground_burst: Duration::from_secs(3600),
        domain_foreground_burst: Duration::from_secs(3600),
        bootstrap_allowance: Duration::from_secs(3600),
        initial_cost_estimate: Duration::from_nanos(1),
        ..Default::default()
    }
}

fn local(iterations: u32, prepare: bool) -> Duration {
    let governor = HostGovernor::independent(&host_config());
    let start = Instant::now();
    for _ in 0..iterations {
        let id = GrantId::Bootstrap(governor.next_bootstrap());
        let request = Reservation {
            id,
            path: RelativePath::root(),
            reads: 1,
            registrations: 0,
            operations: 0,
            ceiling: None,
            lease: 0,
            domain: None,
            origin: WorkOrigin::Foreground,
            listing: false,
        };
        let now = MonotonicTime(start.elapsed());
        if prepare {
            black_box(governor.try_prepare(request, now).unwrap().commit(now).unwrap());
        } else {
            black_box(governor.try_admit(request, now).unwrap());
        }
        governor.try_start(id, now).unwrap();
        governor.release(id, MonotonicTime(start.elapsed()));
    }
    let elapsed = start.elapsed();
    let view = governor.view(MonotonicTime(elapsed));
    assert_eq!(view.grants, u64::from(iterations));
    assert_eq!(view.in_flight, 0);
    assert_eq!(view.preparations, 0);
    elapsed
}

fn ownership(iterations: u32) -> Duration {
    let mut ledger = Ledger::new(Generation([1; 16]), Limits { participants: 2, operations: 8, physical: 2 }).unwrap();
    let participant = ledger.join(VERSION).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let id = ledger.next_operation(participant).unwrap();
        ledger.prepare(id, SharedReservation { work: Work::Listing, operations: 1, estimated_ns: 1 }).unwrap();
        black_box(ledger.authorize(id, u64::try_from(start.elapsed().as_nanos()).unwrap()).unwrap());
        ledger.running(id).unwrap();
        black_box(ledger.settle(id, Progress { revision: 1, operations: 1, elapsed_ns: 1, failed: false }).unwrap());
    }
    let elapsed = start.elapsed();
    assert_eq!(ledger.physical(), 0);
    assert_eq!(ledger.records().count(), 0);
    ledger.leave(participant).unwrap();
    elapsed
}

fn shared(iterations: u32, journal: bool) -> Duration {
    let config = SharedConfig::from_host(&host_config(), 2, 16, 8).unwrap();
    let mut authority = Authority::new(Generation([1; 16]), config, 0).unwrap();
    let participant = authority.join(VERSION).unwrap();
    let mut journal = journal.then(|| Journal::create(Cursor::new(Vec::new()), &authority).unwrap());
    let request = Request {
        work: Work::LazyRead,
        origin: Origin::Foreground,
        domain: None,
        required: 1,
        desired: 0,
        ceiling_ns: u64::MAX,
    };
    let start = Instant::now();
    for _ in 0..iterations {
        let now = u64::try_from(start.elapsed().as_nanos()).unwrap();
        let id = if let Some(journal) = journal.as_mut() {
            journal
                .transaction(|authority| {
                    let id = authority.ledger().next_operation(participant)?;
                    authority.prepare(id, request, now)?;
                    Ok(id)
                })
                .unwrap()
        } else {
            let id = authority.ledger().next_operation(participant).unwrap();
            authority.prepare(id, request, now).unwrap();
            id
        };
        if let Some(journal) = journal.as_mut() {
            journal.transaction(|authority| authority.authorize(id, now)).unwrap();
        } else {
            authority.authorize(id, now).unwrap();
        }
        let completed_at = u64::try_from(start.elapsed().as_nanos()).unwrap();
        let progress = Progress { revision: 1, operations: 1, elapsed_ns: completed_at - now, failed: false };
        if let Some(journal) = journal.as_mut() {
            journal.transaction(|authority| authority.settle(id, progress, completed_at)).unwrap();
        } else {
            authority.settle(id, progress, completed_at).unwrap();
        }
    }
    let elapsed = start.elapsed();
    if let Some(journal) = journal.as_mut() {
        authority = journal.load().unwrap();
    }
    assert_eq!(authority.view().physical, 0);
    assert_eq!(authority.view().prepared, 0);
    black_box(authority.view());
    elapsed
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos"))]
fn native(iterations: u32) -> Duration {
    #[cfg(target_os = "freebsd")]
    use tree_fucker::coordination::freebsd::{Completion, Scope};
    #[cfg(target_os = "illumos")]
    use tree_fucker::coordination::illumos::{Completion, Scope};
    #[cfg(target_os = "linux")]
    use tree_fucker::coordination::linux::{Completion, Scope};
    #[cfg(target_os = "macos")]
    use tree_fucker::coordination::macos::{Completion, Scope};
    #[cfg(target_os = "linux")]
    const RENDEZVOUS: &str = "/dev/shm";
    #[cfg(any(target_os = "freebsd", target_os = "illumos", target_os = "macos"))]
    const RENDEZVOUS: &str = "/var/run/tree-fucker";

    let directory = tempfile::Builder::new().prefix("tree-fucker-bench-").tempdir_in(RENDEZVOUS).unwrap();
    let config = SharedConfig::from_host(&host_config(), 2, 16, 8).unwrap();
    let scope = Scope::open(directory.path().join("scope"), config).unwrap();
    let client = scope.join().unwrap();
    let request = Request {
        work: Work::LazyRead,
        origin: Origin::Foreground,
        domain: None,
        required: 1,
        desired: 0,
        ceiling_ns: u64::MAX,
    };
    let start = Instant::now();
    for _ in 0..iterations {
        client
            .prepare(request)
            .unwrap()
            .try_run(|admission| {
                black_box(admission);
                Completion { value: (), operations: 1, failed: false }
            })
            .unwrap();
    }
    let elapsed = start.elapsed();
    let view = scope.view().unwrap();
    assert_eq!(view.physical, 0);
    assert_eq!(view.prepared, 0);
    assert!(!scope.diagnostics().unwrap().bookkeeping_active);
    elapsed
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).filter(|arg| arg != "--bench").collect();
    if args.iter().any(|arg| arg == "--help") {
        println!(
            "Usage: cargo bench --bench coordination -- [--test|ITERATIONS]\nDefault: 100000 iterations, 2 warmups, 7 alternating measured rounds."
        );
        return;
    }
    assert!(args.len() <= 1, "expected --test or ITERATIONS");
    let smoke = args.first().is_some_and(|arg| arg == "--test");
    let iterations =
        if smoke { 16 } else { args.first().map_or(100_000, |arg| arg.parse().expect("positive iterations")) };
    assert!((1..=10_000_000).contains(&iterations), "iterations must be between 1 and 10000000");
    type Benchmark = (&'static str, fn(u32) -> Duration);
    let modes: Vec<Benchmark> = vec![
        ("local-admission", |n| local(n, false)),
        ("local-prepared-admission", |n| local(n, true)),
        ("ownership-protocol", ownership),
        ("shared-authority", |n| shared(n, false)),
        ("snapshot-journal", |n| shared(n, true)),
        #[cfg(target_os = "linux")]
        ("linux-tmpfs", native),
        #[cfg(target_os = "freebsd")]
        ("freebsd-tmpfs", native),
        #[cfg(target_os = "illumos")]
        ("illumos-tmpfs", native),
        #[cfg(target_os = "macos")]
        ("macos-tmpfs", native),
    ];
    let mut samples = vec![Vec::new(); modes.len()];
    let warmups = if smoke { 0 } else { 2 };
    let runs = if smoke { 1 } else { 7 };
    for round in 0..warmups + runs {
        let mut order: Vec<_> = (0..modes.len()).collect();
        if round % 2 != 0 {
            order.reverse();
        }
        for mode in order {
            let elapsed = modes[mode].1(iterations);
            if round >= warmups {
                samples[mode].push(elapsed.as_secs_f64() * 1e9 / f64::from(iterations));
            }
        }
    }
    println!("mode\titerations\tmedian_ns_per_operation\tmin_ns\tmax_ns");
    for ((name, _), mut timings) in modes.into_iter().zip(samples) {
        timings.sort_by(f64::total_cmp);
        println!(
            "{name}\t{iterations}\t{:.1}\t{:.1}\t{:.1}",
            timings[timings.len() / 2],
            timings[0],
            timings[timings.len() - 1]
        );
    }
}
