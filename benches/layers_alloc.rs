//! Allocation-only probe; do not compare its timings with the normal
//! executable.
mod layers_support;
#[global_allocator]
static ALLOCATOR: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;
fn main() {
    layers_support::main(true);
}
