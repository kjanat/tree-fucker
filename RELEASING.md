# Releases

[Beepboop](https://beepboop.kjanat.dev) owns release preparation, approval, and workflow dispatch. The `main` stream in [.github/beepboop.json](.github/beepboop.json) releases `cargo:tree-fucker` and its GitHub release. The RFC site's npm workspace is documentation tooling and is excluded from this stream.

## Setup

Merge the release workflows and configuration into `master`, then let the Beepboop repository webhook refresh its inventory. The workflows use the reviewed Beepboop helpers at `dcfd2f7ff3525ec54582b32c737b44a5cc47147b` and authenticate each execution with GitHub OIDC. A manual GitHub dispatch without a valid, approved Beepboop execution cannot publish.

Store a crates.io publishing token in Beepboop under the `crates-io` credential alias. Grant runtime access only to this repository's `main` stream, `promote` operation, `release.yml` workflow, and `master` workflow ref. The token needs permission to publish `tree-fucker`; it is requested only after release checks pass. Credential creation and grants are administrator actions in Beepboop, separate from merging this configuration.

The workflow's GitHub token creates the version tag and GitHub release. The repository must allow its existing release policy to accept that token. No workflow changes repository protections or publishes through a bypass path.

## Prepare and publish

1. In Beepboop, select this repository, the `main` stream, and the intended version. Preview the plan and start preparation. The preparation workflow checks out the plan's exact source commit, applies its Cargo version edit, refreshes the lockfile, and checks all targets. Beepboop submits the resulting release PR.
2. Review and merge that PR. For the first `0.1.0`, if the manifest already has the intended version, choose the merged release-ready commit directly.
3. Require successful `CI` and `Coordination acceptance` push runs on the exact candidate commit on `master`. The commit must have a signature that GitHub verifies. A pending run or a successful run for another commit is insufficient.
4. Select and approve that exact candidate in Beepboop. Approval dispatches `release.yml`; its checkout comes from the approved context, not the current tip of the workflow branch.

The publication workflow checks the version, source commit, signature, and both CI runs. It packages the crate, performs default and Tokio publication dry runs, and runs isolated consumers on Rust 1.99.1 and stable. It then verifies the archive's commit metadata, publishes to crates.io, and checks the registry's checksum before reporting success for the crate.

Next, Beepboop's ref helper publishes the approved annotated `vVERSION` tag, using its expected-object checks. The workflow creates a GitHub release with generated notes, marks prereleases appropriately, and verifies the published release and tag target. Beepboop independently verifies the publication reports. Both publications and the version tag must succeed for promotion to complete. The signed object required by this project is the candidate commit; version tags are annotated and do not require an additional signing credential.

## Failures and retries

The release job is serialized and is not cancelled by a subsequent release. It checks CI once and fails if the candidate is not ready. It does not wait for or repeatedly poll CI.

Retry a failed execution from Beepboop after resolving its cause. An already published crate is reused only when its version, non-yanked status, and checksum match the verified archive. An existing tag must be annotated and point to the approved commit; an existing GitHub release must also match the tag and prerelease status. Conflicts fail instead of overwriting published versions or tags. If the registry has not exposed a just-published version yet, verification fails and the same execution can be retried.

The crate report is sent before tag and GitHub release publication, so a later failure retains evidence of the successful registry upload. Credential, network, and permission failures are never treated as proof that a publication is absent.

Local checks for the release scripts are:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 tests/package/verify.py --toolchain stable
python3 tests/package/verify.py --toolchain 1.99.1 --archive target/package/tree-fucker-*.crate
```
