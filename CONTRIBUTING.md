# Contributing

The normative contract is [`rfc/tree-fucker.txt`](rfc/tree-fucker.txt). Changes to observable behavior should keep the implementation, regression tests, and RFC consistent. The [README](README.md) describes the consumer API and compatibility policy.

The [release process](RELEASING.md) publishes each signed `master` push that carries a new crate version to crates.io and GitHub through Beepboop. RELEASING.md also covers credential setup and retries.

## Development setup

`rust-toolchain.toml` pins a dated Rust nightly with `rustfmt`, Clippy, and `rust-analyzer`. CI and releases install that toolchain.

The RFC site tooling uses Bun. Install its dependencies from the repository root:

```sh
bun install
```

## Checks

Run the Rust checks that CI runs:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --no-fail-fast
cargo doc --no-deps --all-features
```

Use `dprint check` for the repository's other formatted files. The workflows in [`.github/workflows`](.github/workflows) define the native and cross-platform matrix, privileged coordination acceptance, and site build. A local Linux pass verifies Linux only. The other supported operating systems need native verification.

## Package verification

Run the package job's commands from a committed checkout:

```sh
cargo package --locked
cargo publish --dry-run --locked
cargo publish --dry-run --locked --features tokio
```

These commands publish nothing. For local iteration with uncommitted changes, add `--allow-dirty`. CI verifies committed source.

## Benchmarks

The [benchmark guide](benchmarks/README.md) documents `cargo bench:layers` and `cargo bench:alloc` for raw Scan, anchor budgets, path materialization, allocation counts, and profiling. Both probes run correctness smoke checks in CI. Use the [coordination baseline](benchmarks/coordination-baseline.md) for the historical measurements and optimization methodology.
