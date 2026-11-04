# Releases

[Beepboop](https://beepboop.kjanat.dev) owns release preparation, approval, and workflow dispatch. The `main` stream in [.github/beepboop.json](.github/beepboop.json) releases `cargo:tree-fucker` and its GitHub release. The RFC site's npm workspace is documentation tooling and is excluded from this stream.

## Setup

Merge the release workflows and configuration into `master`, then let the Beepboop repository webhook refresh its inventory. The workflows use the reviewed Beepboop helpers at `fb304b08fd2b622f70cac70a4ed428da143d10f2` and authenticate each execution with GitHub OIDC. A manual GitHub dispatch without a valid, approved Beepboop execution cannot publish.

Store a crates.io publishing token in Beepboop under the `crates-io` credential alias. Grant runtime access only to this repository's `main` stream, `promote` operation, `release.yml` workflow, and `master` workflow ref. The token needs permission to publish `tree-fucker`; it is requested only after release checks pass. Credential creation and grants are administrator actions in Beepboop, separate from merging this configuration.

The publication job obtains a repository-scoped Beepboop App installation token with `contents: write`, bound to the dispatched execution ID. The token attaches the crate to the draft release and creates the version tag. Annotated tags use the App's bot login and email returned by `actions/token`; the workflow's built-in GitHub token has read-only access. The repository's release policy must permit the Beepboop App to publish these refs.

## Prepare and publish

1. In Beepboop, select this repository, the `main` stream, and the intended version. Preview the plan and start preparation. The preparation workflow checks out the plan's exact source commit, applies its Cargo version edit, refreshes the lockfile, and checks all targets. Beepboop submits the resulting release PR.
2. Review and merge that PR. For the first `0.1.0`, if the manifest already has the intended version, choose the merged release-ready commit directly.
3. Require successful `CI` and `Coordination acceptance` push runs on the exact candidate commit on `master`. The commit must have a signature that GitHub verifies. A pending run or a successful run for another commit is insufficient.
4. Select and approve that exact candidate in Beepboop. Approval creates a draft GitHub release `vVERSION` for the approved commit and dispatches `release.yml`. Authorization and publication run the release script from the workflow's own commit.

The authorization job checks the version, source commit, signature, and both CI runs. A separate package job checks out the approved commit, packages and builds the crate, and performs default and Tokio publication dry runs. That job has read-only repository permissions, no OIDC permission, and no crates.io credential.

The publication job starts on a fresh runner and checks out the approved commit. It packages the crate with `cargo package --no-verify`, which compiles nothing, then rechecks the approved commit and CI. Only then does it request the crates.io token, which only the `cargo publish --no-verify` step receives. The job attests the `.crate` with GitHub build provenance and reports its SHA-256 digest. Beepboop accepts the crate publication only when the crates.io checksum matches that digest.

Next, the job uploads the `.crate` to the draft release, and Beepboop's ref helper publishes the approved annotated `vVERSION` tag, using its expected-object checks. Beepboop's release helper then publishes the draft with its attached crate. Beepboop independently verifies the publication reports. Both publications and the version tag must succeed for promotion to complete. The signed object required by this project is the candidate commit; version tags are annotated and do not require an additional signing credential.

## Failures and retries

The release job is serialized and is not cancelled by a subsequent release. It checks CI once and fails if the candidate is not ready. It does not wait for or repeatedly poll CI.

Retry a failed execution from Beepboop after resolving its cause. An already published crate is reused only when its version, non-yanked status, and checksum match the verified archive. An existing tag must be annotated and point to the approved commit. Beepboop reuses a matching draft and accepts an already published release. Conflicts fail instead of overwriting published versions or tags. If the registry has not exposed a just-published version yet, verification fails and the same execution can be retried.

The crate report is sent before the tag and GitHub release are published, so a later failure retains evidence of the successful registry upload. Credential, network, and permission failures are never treated as proof that a publication is absent.

The package job's local equivalent is:

```sh
cargo package --locked
cargo publish --dry-run --locked
cargo publish --dry-run --locked --features tokio
```
