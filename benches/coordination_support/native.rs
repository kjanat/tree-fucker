use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use tree_fucker::coordination::authority::Config as SharedConfig;
#[cfg(target_os = "freebsd")]
use tree_fucker::coordination::freebsd::{Error, Scope};
#[cfg(target_os = "illumos")]
use tree_fucker::coordination::illumos::{Error, Scope};
#[cfg(target_os = "linux")]
use tree_fucker::coordination::linux::{Error, Scope};
#[cfg(target_os = "macos")]
use tree_fucker::coordination::macos::{Error, Scope};
#[cfg(windows)]
use tree_fucker::coordination::windows::{Error, Scope};

#[cfg(target_os = "linux")]
const RENDEZVOUS: &str = "/dev/shm";
#[cfg(any(target_os = "freebsd", target_os = "illumos", target_os = "macos"))]
const RENDEZVOUS: &str = "/var/run/tree-fucker";
use tree_fucker::{DomainCrossing, HostConfig, HostGovernor, LoadAll, Scan, ScanEvent, ScanOptions, SystemClock};

const SCENARIOS: &[&str] = &["tiny", "disjoint", "contention", "churn", "slow", "idle"];
const TIMEOUT: Duration = Duration::from_secs(60);

struct Options {
    scenario: String,
    mode: String,
    workers: usize,
    iterations: usize,
    files: usize,
    runs: usize,
    warmups: usize,
    waves: usize,
    hold_ms: u64,
    ready_hold_ms: u64,
}

impl Options {
    fn parse(args: &[String]) -> Self {
        let mut options = Self {
            scenario: "all".into(),
            mode: "both".into(),
            workers: 8,
            iterations: 100,
            files: 64,
            runs: 5,
            warmups: 1,
            waves: 4,
            hold_ms: 100,
            ready_hold_ms: 0,
        };
        if args == ["--test"] {
            return Self { workers: 2, iterations: 2, files: 4, runs: 1, warmups: 0, waves: 2, hold_ms: 20, ..options };
        }
        assert!(args.len().is_multiple_of(2), "options require a value; use --help");
        for pair in args.as_chunks::<2>().0 {
            let value = &pair[1];
            match pair[0].as_str() {
                "--scenario" => options.scenario = value.clone(),
                "--mode" => options.mode = value.clone(),
                "--workers" => options.workers = value.parse().expect("workers"),
                "--iterations" => options.iterations = value.parse().expect("iterations"),
                "--files" => options.files = value.parse().expect("files"),
                "--runs" => options.runs = value.parse().expect("runs"),
                "--warmups" => options.warmups = value.parse().expect("warmups"),
                "--waves" => options.waves = value.parse().expect("waves"),
                "--hold-ms" => options.hold_ms = value.parse().expect("hold milliseconds"),
                "--ready-hold-ms" => options.ready_hold_ms = value.parse().expect("ready hold milliseconds"),
                other => panic!("unknown option {other}"),
            }
        }
        assert!(options.scenario == "all" || SCENARIOS.contains(&options.scenario.as_str()), "unknown scenario");
        assert!(["local", "shared", "both"].contains(&options.mode.as_str()), "unknown mode");
        for (name, value, maximum) in [
            ("workers", options.workers, 64),
            ("iterations", options.iterations, 1_000_000),
            ("files", options.files, 100_000),
            ("runs", options.runs, 100),
            ("waves", options.waves, 1_000),
        ] {
            assert!((1..=maximum).contains(&value), "{name} must be in 1..={maximum}");
        }
        assert!(options.warmups <= 100);
        assert!((1..=10_000).contains(&options.hold_ms));
        assert!(options.ready_hold_ms <= 10_000);
        options
    }
}

fn local_config() -> HostConfig {
    HostConfig {
        maximum_in_flight: 2,
        per_domain_concurrency: 2,
        foreground_duty: 1.0,
        domain_foreground_duty: 1.0,
        foreground_burst: Duration::from_secs(3600),
        domain_foreground_burst: Duration::from_secs(3600),
        bootstrap_allowance: Duration::from_secs(3600),
        stuck_threshold: Duration::from_secs(30),
        initial_cost_estimate: Duration::from_nanos(1),
        ..HostConfig::default()
    }
}

fn shared_config() -> SharedConfig {
    SharedConfig::from_host(&local_config(), 64, 128, 128).unwrap()
}

fn retry<T>(mut operation: impl FnMut() -> Result<T, Error>) -> T {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match operation() {
            Ok(value) => return value,
            Err(Error::Busy) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
            Err(Error::Io(ref error)) if error.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("coordination: {error}"),
        }
    }
}

fn scan(root: &Path, governor: &HostGovernor) -> Scan {
    Scan::open_outside_host_governor(
        Arc::new(tree_fucker::std_fs::StdFileSystem::new()),
        root.to_path_buf(),
        Arc::new(LoadAll),
        ScanOptions {
            crossing: DomainCrossing::Follow,
            streaming: true,
            ceiling: Duration::MAX,
            ..ScanOptions::default()
        },
        governor.clone(),
        Arc::new(SystemClock),
    )
    .unwrap()
}

fn inventory(root: &Path, governor: &HostGovernor, verify: bool, files: usize) -> usize {
    let mut names = Vec::new();
    let mut count = 0;
    for event in scan(root, governor) {
        match event.unwrap() {
            ScanEvent::Entry(entry) => {
                count += 1;
                if verify {
                    names.push(entry.path.path().to_string());
                }
            }
            ScanEvent::Unlisted { failure, .. } => panic!("incomplete scan: {failure:?}"),
            _ => {}
        }
    }
    assert_eq!(count, files + 1);
    if verify {
        names.sort();
        let mut expected: Vec<_> =
            std::iter::once(".".into()).chain((0..files).map(|i| format!("file-{i:06}"))).collect();
        expected.sort();
        assert_eq!(names, expected);
    }
    count
}

fn drain(scope: &Scope) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let state = scope.diagnostics().unwrap();
        assert!(!state.failed);
        if state.pending_settlements == 0 && !state.bookkeeping_active {
            return;
        }
        assert!(Instant::now() < deadline, "settlement did not drain");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[derive(Default)]
struct Sample {
    elapsed_ns: u128,
    join_ns: u128,
    operations: u64,
    rows: u64,
    allocations: u64,
    reallocations: u64,
    allocated_bytes: u64,
    attempts: u64,
    acquired: u64,
    busy: u64,
    user_cpu_ns: u64,
    system_cpu_ns: u64,
}

#[cfg(unix)]
fn cpu_time() -> (u64, u64) {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: RUSAGE_SELF fills one correctly aligned native rusage value.
    assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) }, 0);
    // SAFETY: successful getrusage initialized the output.
    let usage = unsafe { usage.assume_init() };
    let nanos = |time: libc::timeval| {
        u64::try_from(time.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(time.tv_usec).unwrap() * 1_000
    };
    (nanos(usage.ru_utime), nanos(usage.ru_stime))
}

#[cfg(windows)]
fn cpu_time() -> (u64, u64) {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    let mut created = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut exited = created;
    let mut kernel = created;
    let mut user = created;
    // SAFETY: the current-process pseudo-handle is valid and all four outputs
    // point to distinct live FILETIME values. Times include all worker threads.
    let ok = unsafe { GetProcessTimes(GetCurrentProcess(), &mut created, &mut exited, &mut kernel, &mut user) };
    assert_ne!(ok, 0, "cannot read worker CPU time: {}", std::io::Error::last_os_error());
    let nanos = |time: FILETIME| {
        (u64::from(time.dwHighDateTime) << 32 | u64::from(time.dwLowDateTime)).checked_mul(100).unwrap()
    };
    (nanos(user), nanos(kernel))
}

fn worker(args: &[String], allocations: bool) {
    let [scenario, mode, scope_path, root, iterations, files] = args else { panic!("worker arguments") };
    let root = Path::new(root);
    let iterations: usize = iterations.parse().unwrap();
    let files: usize = files.parse().unwrap();
    let joined = Instant::now();
    let scope = (mode == "shared").then(|| retry(|| Scope::open(scope_path, shared_config())));
    let governor = match &scope {
        Some(scope) => retry(|| HostGovernor::with_coordination(&local_config(), scope.clone())),
        None => HostGovernor::independent(&local_config()),
    };
    let join_ns = joined.elapsed().as_nanos();
    if scenario == "disjoint" {
        inventory(root, &governor, true, files);
    }
    let mut reader = if ["tiny", "contention", "churn", "slow"].contains(&scenario.as_str()) {
        let mut scan = scan(root, &governor);
        let ScanEvent::Entry(entry) = scan.next().unwrap().unwrap() else { panic!("root observation") };
        Some((scan, entry))
    } else {
        None
    };
    if let Some(scope) = &scope {
        drain(scope);
    }
    println!("READY {join_ns}");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_exact(&mut [0]).unwrap();
    let before = scope.as_ref().map(|scope| scope.diagnostics().unwrap().access).unwrap_or_default();
    let region = allocations.then(|| stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM));
    let cpu_before = cpu_time();
    let start = Instant::now();
    let mut sample = Sample { join_ns, ..Sample::default() };
    match scenario.as_str() {
        "idle" => {
            std::io::stdin().read_exact(&mut [0]).unwrap();
        }
        "slow" => {
            let (scan, entry) = reader.as_mut().unwrap();
            scan.read(entry, |_| {
                std::io::stdin().read_exact(&mut [0]).unwrap();
                Ok(())
            })
            .unwrap();
            sample.operations = 1;
        }
        "disjoint" => {
            for _ in 0..iterations {
                sample.rows += inventory(root, &governor, false, files) as u64;
            }
            sample.operations = iterations as u64;
        }
        _ => {
            let (scan, entry) = reader.as_mut().unwrap();
            for _ in 0..iterations {
                let bytes = scan.read(entry, |_| Ok(fs::read(root.join("file-000000")).unwrap())).unwrap();
                assert_eq!(bytes, b"tree-fucker benchmark\n");
                sample.rows += 1;
            }
            sample.operations = iterations as u64;
        }
    }
    if scenario != "idle"
        && let Some(scope) = &scope
    {
        drain(scope);
    }
    sample.elapsed_ns = start.elapsed().as_nanos();
    let cpu_after = cpu_time();
    sample.user_cpu_ns = cpu_after.0 - cpu_before.0;
    sample.system_cpu_ns = cpu_after.1 - cpu_before.1;
    if let Some(region) = region {
        let stats = region.change();
        sample.allocations = stats.allocations as u64;
        sample.reallocations = stats.reallocations as u64;
        sample.allocated_bytes = stats.bytes_allocated as u64;
    }
    let after = scope.as_ref().map(|scope| scope.diagnostics().unwrap().access).unwrap_or_default();
    sample.attempts = after.attempts - before.attempts;
    sample.acquired = after.acquired - before.acquired;
    sample.busy = after.busy - before.busy;
    if scenario == "idle" {
        assert_eq!(after, before, "idle participant contacted the authority");
    }
    assert!(governor.coordination_error().is_none());
    println!(
        "DONE {} {} {} {} {} {} {} {} {} {} {} {}",
        sample.elapsed_ns,
        sample.join_ns,
        sample.operations,
        sample.rows,
        sample.allocations,
        sample.reallocations,
        sample.allocated_bytes,
        sample.attempts,
        sample.acquired,
        sample.busy,
        sample.user_cpu_ns,
        sample.system_cpu_ns
    );
}

struct Children(Vec<Child>);
impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn cohort(scenario: &str, mode: &str, options: &Options, scope: &Path, roots: &[PathBuf]) -> (Duration, Vec<Sample>) {
    let mut children = Children(Vec::new());
    let mut readers = Vec::new();
    let (send, receive) = mpsc::channel();
    let iterations = if scenario == "churn" { 1 } else { options.iterations };
    for (index, root) in roots.iter().enumerate() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--worker")
            .args([scenario, mode])
            .arg(scope)
            .arg(root)
            .arg(iterations.to_string())
            .arg(options.files.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let output = child.stdout.take().unwrap();
        children.0.push(child);
        let send = send.clone();
        readers.push(std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if send.send((index, line)).is_err() {
                    return;
                }
            }
        }));
    }
    drop(send);
    let mut ready = vec![false; roots.len()];
    for _ in roots {
        let (index, line) = receive.recv_timeout(TIMEOUT).expect("worker readiness timed out");
        assert!(!ready[index]);
        ready[index] = true;
        assert!(line.unwrap().starts_with("READY "));
    }
    // Resource collectors need a bounded window in which the whole cohort
    // exists. Normal timing runs leave this at zero; the cohort timer starts
    // after the optional sampling hold.
    if options.ready_hold_ms != 0 {
        std::thread::sleep(Duration::from_millis(options.ready_hold_ms));
    }
    let start = Instant::now();
    for child in &mut children.0 {
        child.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
    }
    if scenario == "idle" || scenario == "slow" {
        std::thread::sleep(Duration::from_millis(options.hold_ms));
        for child in &mut children.0 {
            child.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
        }
    }
    let mut samples = Vec::new();
    let mut completed = vec![false; roots.len()];
    for _ in roots {
        let (index, line) = receive.recv_timeout(TIMEOUT).expect("worker completion timed out");
        assert!(!completed[index]);
        completed[index] = true;
        let line = line.unwrap();
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 13, "invalid worker report: {line}");
        assert_eq!(fields[0], "DONE");
        let number = |i: usize| fields[i].parse::<u64>().unwrap();
        samples.push(Sample {
            elapsed_ns: fields[1].parse().unwrap(),
            join_ns: fields[2].parse().unwrap(),
            operations: number(3),
            rows: number(4),
            allocations: number(5),
            reallocations: number(6),
            allocated_bytes: number(7),
            attempts: number(8),
            acquired: number(9),
            busy: number(10),
            user_cpu_ns: number(11),
            system_cpu_ns: number(12),
        });
    }
    let elapsed = start.elapsed();
    for child in &mut children.0 {
        assert!(child.wait().unwrap().success());
    }
    for reader in readers {
        reader.join().unwrap();
    }
    (elapsed, samples)
}

pub fn main(allocations: bool) {
    let args: Vec<_> = std::env::args().skip(1).filter(|arg| arg != "--bench").collect();
    if args.first().is_some_and(|arg| arg == "--worker") {
        worker(&args[1..], allocations);
        return;
    }
    if args == ["--help"] {
        println!(
            "Usage: cargo bench --bench coordination_processes -- [--test | OPTIONS]\n\
            --scenario all|tiny|disjoint|contention|churn|slow|idle --mode both|local|shared\n\
            --workers 8 --iterations 100 --files 64 --runs 5 --warmups 1 --waves 4 --hold-ms 100\n\
            --ready-hold-ms 0 (resource sampling only; maximum 10000)"
        );
        return;
    }
    let options = Options::parse(&args);
    let artifacts = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/benchmarks");
    fs::create_dir_all(&artifacts).unwrap();
    let scenarios: Vec<_> =
        SCENARIOS.iter().copied().filter(|name| options.scenario == "all" || options.scenario == *name).collect();
    println!(
        "scenario\tmode\tprofile\tround\tworkers\twaves\toperations\trows\tcohort_ns\twall_ns\tworker_p50_ns\tworker_p95_ns\tjoin_p95_ns\tallocations\treallocations\tallocated_bytes\tlock_attempts\tlock_acquired\tlock_busy\tuser_cpu_ns\tsystem_cpu_ns"
    );
    for scenario in scenarios {
        for round in 0..options.warmups + options.runs {
            let mut modes = match options.mode.as_str() {
                "both" => vec!["local", "shared"],
                mode => vec![mode],
            };
            if round % 2 != 0 {
                modes.reverse();
            }
            for mode in modes {
                let fixture = tempfile::Builder::new().prefix("coordination-workload-").tempdir_in(&artifacts).unwrap();
                let mut authority_builder = tempfile::Builder::new();
                authority_builder.prefix("tree-fucker-bench-");
                #[cfg(windows)]
                let authority = authority_builder.tempdir().unwrap();
                #[cfg(not(windows))]
                let authority = authority_builder.tempdir_in(RENDEZVOUS).unwrap();
                let workers = if scenario == "tiny" { 1 } else { options.workers };
                let roots: Vec<_> = (0..workers)
                    .map(|index| {
                        let root = fixture.path().join(if scenario == "contention" { 0 } else { index }.to_string());
                        fs::create_dir_all(&root).unwrap();
                        for file in 0..options.files {
                            fs::write(root.join(format!("file-{file:06}")), b"tree-fucker benchmark\n").unwrap();
                        }
                        root
                    })
                    .collect();
                let waves = if scenario == "churn" { options.waves } else { 1 };
                let wall = Instant::now();
                let mut elapsed = Duration::ZERO;
                let mut samples = Vec::new();
                for _ in 0..waves {
                    let (duration, wave) = cohort(scenario, mode, &options, &authority.path().join("scope"), &roots);
                    elapsed += duration;
                    samples.extend(wave);
                }
                let wall_ns = wall.elapsed().as_nanos();
                if mode == "shared" {
                    let scope = retry(|| Scope::open(authority.path().join("scope"), shared_config()));
                    for _ in 0..32 {
                        let view = retry(|| scope.view());
                        if view.physical == 0 && view.prepared == 0 && view.participants == 0 {
                            break;
                        }
                    }
                    let view = retry(|| scope.view());
                    assert_eq!((view.physical, view.prepared, view.participants), (0, 0, 0));
                }
                if round < options.warmups {
                    continue;
                }
                let mut times: Vec<_> = samples.iter().map(|sample| sample.elapsed_ns).collect();
                let mut joins: Vec<_> = samples.iter().map(|sample| sample.join_ns).collect();
                times.sort_unstable();
                joins.sort_unstable();
                let p95 = (times.len() * 95).div_ceil(100) - 1;
                let sum = |f: fn(&Sample) -> u64| samples.iter().map(f).sum::<u64>();
                let profile = if allocations { "allocations" } else { "timing" };
                println!(
                    "{scenario}\t{mode}\t{profile}\t{}\t{workers}\t{waves}\t{}\t{}\t{}\t{wall_ns}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    round - options.warmups,
                    sum(|s| s.operations),
                    sum(|s| s.rows),
                    elapsed.as_nanos(),
                    times[times.len() / 2],
                    times[p95],
                    joins[p95],
                    sum(|s| s.allocations),
                    sum(|s| s.reallocations),
                    sum(|s| s.allocated_bytes),
                    sum(|s| s.attempts),
                    sum(|s| s.acquired),
                    sum(|s| s.busy),
                    sum(|s| s.user_cpu_ns),
                    sum(|s| s.system_cpu_ns)
                );
            }
        }
    }
}
