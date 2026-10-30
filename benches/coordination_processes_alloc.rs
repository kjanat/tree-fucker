//! Allocation probe for independent-process coordination workloads.
mod coordination_support;
#[global_allocator]
static ALLOCATOR: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;
fn main() {
    coordination_support::main(true);
}
