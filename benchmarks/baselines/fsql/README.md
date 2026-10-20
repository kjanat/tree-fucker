# Original fsql traversal baseline

This directory is a frozen comparison input for the `fsql-walk-baseline` Cargo benchmark mode. It is not part of tree-fucker's library API or a compatibility implementation. There are no production callers. Both benchmark executables compile these modules directly on Linux; other targets omit this mode.

[Issue #2](https://github.com/kjanat/tree-fucker/issues/2) requests a comparison between the original fsql traversal, governed one-shot scans, and persistent Tree initialization. Keeping the reference implementation here makes that comparison reproducible without a sibling checkout or a download during a benchmark run.

## Provenance and adaptations

`walk.rs` comes from [`crates/fsql/src/walk.rs` at fsql commit `d5ac9c80a2c5d8322d9ae096d6b0d860d73a4d4f`](https://github.com/kjanat/fsql/blob/d5ac9c80a2c5d8322d9ae096d6b0d860d73a4d4f/crates/fsql/src/walk.rs). Its traversal algorithm is retained. Adaptations are limited to:

- Redirecting imports to the benchmark's `row.rs` adapter.
- Omitting the original module's tests; the harness verifies complete path multisets against an independent traversal before timing each mode.
- Applying this repository's Rust formatting.
- Adding the optional `BENCH_LISTING_DELAY_US` sleep before directory opens, shared with the other traversal controls. It is disabled by default.

`row.rs` is a purpose-built benchmark adapter, not a copy of fsql's full row type. It retains owned paths and names, shared directory descriptors, and lazy `statx` metadata. It omits SQL-only caches and column evaluation. The walker still constructs rows during measured iterations; verification alone additionally visits their paths.

## Interpreting results

This measures the original traversal algorithm with the documented adapter and current benchmark dependencies. It does not reproduce the historical fsql executable's complete row layout, dependency graph, planning, SQL evaluation, or output costs. Compare it with `scan-paths` when including absolute path materialization; `scan-count` intentionally omits that work. It also does not implement the governor, cancellation, domain-quarantine, or resource-budget contracts of Scan.

Keep this reference fixed when optimizing the current implementation. Any change to its measured work must be explained here and in the affected report. A different source revision should be an explicitly identified baseline, not a silent update to this one. There is no old public API here to maintain or migrate.

See the [benchmark guide](../../README.md) for commands and the [acceptance report](../../scan-acceptance.md) for measurements and their limits.
