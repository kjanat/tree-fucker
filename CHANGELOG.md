# Changelog

## 0.1.0

This initial release candidate provides synchronous, governed `Scan`
traversal and persistent, reconciled `Tree` snapshots with optional Tokio
integration. Process-only governance is the default. Shared coordination is
opt-in and adds cross-process safety with additional transaction overhead.

- Shared authorities use protocol 1, journal 1, and snapshot formats 2 or 3.
  Incompatible versions preserve retained accounting and refuse participation.
- Unix initialization explicitly releases bookkeeping exclusion on success, on
  errors, and on unwinding, even when another descriptor holds the same open
  description.
  Operation-owner lifetime locks last as long as the physical work.
- macOS physical sleep/wake acceptance remains outstanding in
  [#20](https://github.com/kjanat/tree-fucker/issues/20). Solaris shared coordination
  remains unavailable ([#19](https://github.com/kjanat/tree-fucker/issues/19)).
- The crate is licensed under MIT OR Apache-2.0.

Publication requires a successful main CI run on the exact candidate SHA,
including the native macOS repetitions and the package job. The package job
packages the crate, performs both publication dry runs, and retains the `.crate`
archive. The release automation still requires maintainer approval.
