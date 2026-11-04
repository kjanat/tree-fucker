# Changelog

## Unreleased — 0.1.0

Initial release candidate. This version provides synchronous, governed `Scan`
traversal and persistent, reconciled `Tree` snapshots with optional Tokio
integration. Process-only governance is the default; shared coordination is
opt-in and adds cross-process safety with additional transaction overhead.

- Public APIs and supported platforms remain compatible within `0.1.x`;
  incompatible changes require a minor-version bump.
- Shared authorities use protocol 1, journal 1, and snapshot formats 2 or 3.
  Incompatible versions preserve retained accounting and refuse participation.
- Unix initialization explicitly releases bookkeeping exclusion on success,
  errors, and unwinding, even when another descriptor retains the same open
  description. Operation-owner lifetime locks continue to follow physical work.
- macOS physical sleep/wake acceptance remains outstanding in
  [#20](https://github.com/kjanat/tree-fucker/issues/20). Solaris shared coordination
  remains unavailable ([#19](https://github.com/kjanat/tree-fucker/issues/19)).
- Licensed under MIT OR Apache-2.0.

Before publication, require a successful main CI run on the exact candidate SHA,
including the native macOS repetitions and the package job. That job packages
the crate, performs both publication dry runs, and retains the `.crate` archive.
The release automation still requires maintainer approval; these changes do not
publish a crate or create a release.
