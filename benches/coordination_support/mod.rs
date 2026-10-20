#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos"))]
mod native;

pub fn main(_allocations: bool) {
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos"))]
    native::main(_allocations);
    #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos")))]
    {
        eprintln!("the process coordination benchmark requires a native coordination backend");
        std::process::exit(2);
    }
}
