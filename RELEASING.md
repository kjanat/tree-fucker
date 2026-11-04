# Releases

[Beepboop](https://beepboop.kjanat.dev) releases every signed `master` push that carries a new crate version. The `main` stream in [.github/beepboop.json](.github/beepboop.json) releases `cargo:tree-fucker` and its GitHub release. The RFC site's npm workspace is documentation tooling and is excluded from this stream.

## Setup

Merge the release workflows and configuration into `master`, then let the Beepboop repository webhook refresh its inventory. The workflow uses the Beepboop helpers at `kjanat/beepboop/actions/*@v1` and authenticates each execution with GitHub OIDC. A manual GitHub dispatch without a valid, approved Beepboop execution cannot publish.

Store a crates.io publishing token in Beepboop under the `crates-io` credential alias. Grant runtime access only to this repository's `main` stream, `promote` operation, `release.yml` workflow, and `master` workflow ref. The token needs permission to publish `tree-fucker`; it is requested only after release checks pass. Credential creation and grants are administrator actions in Beepboop, separate from merging this configuration.

The publication job obtains a repository-scoped Beepboop App installation token with `contents: write`, bound to the dispatched execution ID. The token attaches the crate to the draft release and creates the version tag. Annotated tags use the App's bot login and email returned by `actions/token`; the workflow's built-in GitHub token has read-only access. The repository's release policy must permit the Beepboop App to publish these refs.

## Publish

Set the new version in `Cargo.toml`, refresh `Cargo.lock`, and push the signed commit to `master`. `promote.approval` is `push`, so Beepboop creates a promotion for that commit when crates.io lacks its version. Beepboop approves it once GitHub verifies the commit signature and every check on the commit succeeds. Approval creates the draft GitHub release `vVERSION` and dispatches `release.yml`. A newer push of the same version replaces a promotion that has not run yet.

The authorization job decodes the Beepboop context, then checks the version, source commit, signature, and `CI` push run. A separate package job checks out the approved commit, packages and builds the crate, and performs default and Tokio publication dry runs. That job has read-only repository permissions, no OIDC permission, and no crates.io credential.

The publication job starts on a fresh runner and checks out the approved commit. It packages the crate with `cargo package --no-verify`, which compiles nothing, then rechecks the approved commit and CI. Only then does it request the crates.io token, which only the `cargo publish --no-verify` step receives. The job attests the `.crate` with GitHub build provenance and reports its SHA-256 digest. Beepboop accepts the crate publication only when the crates.io checksum matches that digest.

Next, the job uploads the `.crate` to the draft release by its release ID, and Beepboop's ref helper publishes the approved annotated `vVERSION` tag, using its expected-object checks. Beepboop's release helper then publishes the draft with its attached crate. Beepboop independently verifies the publication reports. Both publications and the version tag must succeed for promotion to complete. The signed object required by this project is the candidate commit; version tags are annotated and do not require an additional signing credential.

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
