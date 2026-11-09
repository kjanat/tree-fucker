# Releases

[Beepboop](https://beepboop.kjanat.dev) releases every signed `master` push that carries a new crate version. The `main` stream in [.github/beepboop.json](.github/beepboop.json) releases `cargo:tree-fucker` and its GitHub release. The RFC site's npm workspace holds documentation tooling, and the stream lists no package for it.

## Setup

Merge the release workflows and configuration into `master`, then let the Beepboop repository webhook refresh its inventory. The workflow calls the Beepboop helpers at `kjanat/beepboop/actions/*@v1` and authenticates each execution with GitHub OIDC. A manual GitHub dispatch without a valid, approved Beepboop execution cannot publish.

Store a crates.io publishing token in Beepboop under the `crates-io` credential alias. Grant runtime access only to this repository's `main` stream, `promote` operation, `release.yml` workflow, and `master` workflow ref. The token needs permission to publish `tree-fucker`. The publication job requests it only after the release checks pass. A Beepboop administrator creates the credential and its grants in a separate step from merging this configuration.

The publication job requests a repository-scoped Beepboop App installation token with `contents: write`, bound to the dispatched execution ID. The job uses that token to attach the crate to the draft release, and the Beepboop ref helper uses it to create the version tag. Annotated tags carry the bot login and email that `actions/token` returns for the App. The workflow's built-in GitHub token has read-only access. The repository's release policy must permit the Beepboop App to publish these refs.

## Publish

Set the new version in `Cargo.toml`, refresh `Cargo.lock`, and push the signed commit to `master`. With `promote.approval` set to `push`, Beepboop creates a promotion for that commit when crates.io lacks its version. Beepboop approves the promotion once GitHub verifies the commit signature and every check on the commit succeeds. Approval creates the draft GitHub release `vVERSION` and dispatches `release.yml`. A newer push of the same version replaces a promotion that has not run yet.

The authorization job decodes the Beepboop context, then checks the version, source commit, signature, and `CI` push run. A separate package job checks out the approved commit, packages and builds the crate, and performs default and Tokio publication dry runs. The package job holds only `contents: read`, has no OIDC permission, and receives no crates.io credential.

The publication job starts on a fresh runner and checks out the approved commit. It runs `cargo package --no-verify`, which skips compilation, then rechecks the approved commit and CI. Only after that recheck does it request the crates.io token, and only the `cargo publish --no-verify` step receives it. The job attests the `.crate` with GitHub build provenance and reports its SHA-256 digest. Beepboop accepts the crate publication only when the crates.io checksum matches that digest.

Next, the job uploads the `.crate` to the draft release by its release ID. Beepboop's ref helper then publishes the approved annotated `vVERSION` tag with its expected-object checks. Beepboop's release helper publishes the draft with its attached crate. Beepboop verifies the publication reports independently of the job. Promotion completes only when both publications and the version tag succeed. The signature this project requires is on the candidate commit. Version tags are annotated and need no additional signing credential.

## Failures and retries

The release job runs one at a time, and a later release waits for the running one to finish. The job checks CI once and fails if the candidate is not ready.

Retry a failed execution from Beepboop after fixing its cause. A retry reuses an already published crate when its version, non-yanked status, and checksum match the verified archive. An existing tag must be annotated and point to the approved commit. Beepboop reuses a matching draft and accepts an already published release. A conflict fails the execution and leaves published versions and tags unchanged. If the registry does not yet list a just-published version, verification fails, and you can retry the same execution.

The job sends the crate report before it publishes the tag and GitHub release, so a later failure keeps evidence of the registry upload. A credential, network, or permission failure leaves the publication state unknown.

The local equivalent of the package job is:

```sh
cargo package --locked
cargo publish --dry-run --locked
cargo publish --dry-run --locked --features tokio
```
