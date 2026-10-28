#!/bin/sh
# Native Solaris provisioning and acceptance. Invoked over the VM action's SSH
# connection so CI can upload this log even if another platform is still busy.
set -eu
pkg install curl || [ $? -eq 4 ]
mkdir -p target/native/rust
(
  cd target/native/rust
  distribution=rust-nightly-x86_64-pc-solaris.tar.xz
  curl --proto '=https' --tlsv1.2 -fsSLO "https://static.rust-lang.org/dist/$distribution"
  curl --proto '=https' --tlsv1.2 -fsSLO "https://static.rust-lang.org/dist/$distribution.sha256"
  expected=$(awk '{print $1}' "$distribution.sha256")
  test "$(digest -a sha256 "$distribution")" = "$expected"
  /usr/gnu/bin/tar -xJf "$distribution"
  bash rust-nightly-x86_64-pc-solaris/install.sh --prefix=/opt/rust --without=rust-docs
)
export PATH="/opt/rust/bin:/usr/gcc/14/bin:/usr/gnu/bin:$PATH"
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --no-fail-fast
cargo test --test coordination_socket_lifetime -- --nocapture
cargo doc --no-deps --all-features
