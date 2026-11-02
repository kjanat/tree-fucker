//! This module provides deterministic test doubles for consumer tests.
//!
//! The doubles cover the test requirements of RFC §10.5 and §17.
//!
//! [`FakeFileSystem`] is an in-memory filesystem with injectable failures,
//! costs, storage domains, and watcher behaviour. [`DeterministicRuntime`]
//! runs a [`crate::tree::Tree`] on simulated time without threads.
//! [`Harness`] drives the coordinator directly, step by step, without any
//! runtime.

pub mod fake_fs;
pub mod harness;
pub mod runtime;

pub use fake_fs::{CostScope, DomainId, FailureMode, FakeFileSystem, FakeOp, InjectedPosition};
pub use harness::{Admission, Charge, Dispatched, Harness, Ticket};
pub use runtime::{BlockingMode, DeterministicRuntime, HoldingRuntime};
