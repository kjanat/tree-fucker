# Contributing

The normative contract is [`rfc/tree-fucker.txt`](rfc/tree-fucker.txt). Changes to observable behavior should keep the implementation, regression tests, and RFC consistent. The [README](README.md) describes the consumer API and compatibility policy.

The [release process](RELEASING.md) uses Beepboop to prepare a version PR, approve an exact commit, and dispatch verified crates.io and GitHub publication. Its credential setup and retry behavior are documented separately from development checks.

## Development setup

The repository selects rolling Rust nightly through `rust-toolchain.toml` and includes `rustfmt`, Clippy, and `rust-analyzer`. The library itself supports the stable compiler stated in `Cargo.toml`; nightly is for repository development.

The RFC site tooling uses Bun. Install its dependencies from the repository root:

```sh
bun install
```

## Checks

Run the Rust checks used by CI:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --no-fail-fast
cargo doc --no-deps --all-features
```

Use `dprint check` for the repository's other formatted files. The workflows in [`.github/workflows`](.github/workflows) define the native and cross-platform matrix, privileged coordination acceptance, and site build. A local Linux pass does not replace native verification on the other supported operating systems.

## Package verification

Run these checks from a committed checkout:

```sh
python3 tests/package/verify.py --toolchain stable
python3 tests/package/verify.py --toolchain 1.99.1 --archive target/package/tree-fucker-*.crate
```

The verifier packages the crate, performs publication dry runs with default features and Tokio, and builds and runs two independent consumers from the archive outside repository Cargo configuration. It also checks that the README examples match their compiled targets in [`examples`](examples). Nothing is published. For local iteration with uncommitted changes, pass `--allow-dirty`; CI verifies committed source.

## Benchmarks

The [benchmark guide](benchmarks/README.md) documents `cargo bench:layers` and `cargo bench:alloc` for raw Scan, anchor budgets, path materialization, allocation counts, and profiling. Both probes run correctness smoke checks in CI. Use the [coordination baseline](benchmarks/coordination-baseline.md) for the historical measurements and optimization methodology.
