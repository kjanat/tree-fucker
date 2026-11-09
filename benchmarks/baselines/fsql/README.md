# Original fsql traversal baseline

This directory is a frozen comparison input for the `fsql-walk-baseline` Cargo benchmark mode. It is neither part of tree-fucker's library API nor a compatibility implementation, and no production code calls it. Both benchmark executables compile these modules directly on Linux. Other targets omit this mode.

[Issue #2](https://github.com/kjanat/tree-fucker/issues/2) requests a comparison between the original fsql traversal, governed one-shot scans, and persistent Tree initialization. With the reference implementation in this directory, a benchmark run reproduces that comparison without a sibling checkout or a download.

## Provenance and adaptations

`walk.rs` comes from [`crates/fsql/src/walk.rs` at fsql commit `d5ac9c80a2c5d8322d9ae096d6b0d860d73a4d4f`](https://github.com/kjanat/fsql/blob/d5ac9c80a2c5d8322d9ae096d6b0d860d73a4d4f/crates/fsql/src/walk.rs). The traversal algorithm is unchanged. The only adaptations are:

- Imports point to the benchmark's `row.rs` adapter.
- This copy omits the original module's tests. The harness verifies complete path multisets against an independent traversal before timing each mode.
- This copy uses this repository's Rust formatting.
- An optional `BENCH_LISTING_DELAY_US` sleep runs before directory opens and is shared with the other traversal controls. It is off by default.

`row.rs` is a benchmark adapter written for this repository and differs from fsql's full row type. It keeps owned paths and names, shared directory descriptors, and lazy `statx` metadata, and omits SQL-only caches and column evaluation. The walker still constructs rows during measured iterations. Only verification also visits their paths.

## Interpreting results

This mode measures the original traversal algorithm with the documented adapter and current benchmark dependencies. It excludes the historical fsql executable's complete row layout, dependency graph, planning, SQL evaluation, and output costs. Compare it with `scan-paths` to include absolute path materialization, which `scan-count` omits. It has none of Scan's governor, cancellation, domain-quarantine, or resource-budget contracts.

Keep this reference fixed when optimizing the current implementation. Explain any change to its measured work here and in the affected report. Add a different source revision as a separately identified baseline.

See the [benchmark guide](../../README.md) for commands and the [acceptance report](../../scan-acceptance.md) for measurements and their limits.
