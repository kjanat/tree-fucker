"""Exercise publication gates without credentials or remote mutations."""

import io
import json
import subprocess
import tarfile
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import release
import tomllib

SHA = "a" * 40
CONTEXT = {
    "repository": release.REPOSITORY,
    "repositoryId": 123,
    "operation": "promote",
    "stream": "main",
    "sourceSha": SHA,
    "version": "0.1.0",
}
PACKAGE = {"name": release.CRATE, "version": "0.1.0"}
PREFIX = "tree-fucker-0.1.0/"
CARGO_VERSION = tomllib.loads((release.ROOT / "Cargo.toml").read_text())["package"][
    "version"
]
CARGO_PREFIX = f"{release.CRATE}-{CARGO_VERSION}/"
CARGO_ARCHIVE = release.ROOT / f"target/package/{release.CRATE}-{CARGO_VERSION}.crate"
COMMITTED_MANIFEST = """
[package]
name = "tree-fucker"
version = "0.1.0"
edition = "2024"
description = "A test crate"
license = "MIT OR Apache-2.0"
readme = "README.md"
rust-version = "1.99.1"
authors = ["Fixture author"]
keywords = ["filesystem"]
categories = ["filesystem"]
include = ["/src/**", "/examples/*.rs", "/build.rs", "/README.md", "/Cargo.toml"]

[workspace]
[workspace.lints]
rust = { unsafe_code = "deny" }

[[example]]
name = "tree"
required-features = ["extra"]

[dependencies]
alias = { package = "original", version = "1.2.3", optional = true, default-features = false, features = ["std"] }

[dev-dependencies]
test-helper = "2.0"

[build-dependencies]
builder = "3.0"

[target.'cfg(windows)'.dependencies]
windows-sys = "0.61.2"

[features]
extra = ["dep:alias"]

[lints]
workspace = true
"""
PACKAGED_MANIFEST = """
[package]
edition = "2024"
rust-version = "1.99.1"
name = "tree-fucker"
version = "0.1.0"
authors = ["Fixture author"]
build = "build.rs"
include = ["/src/**", "/examples/*.rs", "/build.rs", "/README.md", "/Cargo.toml"]
autolib = false
autobins = false
autoexamples = false
autotests = false
autobenches = false
description = "A test crate"
readme = "README.md"
keywords = ["filesystem"]
categories = ["filesystem"]
license = "MIT OR Apache-2.0"

[features]
extra = ["dep:alias"]

[lib]
name = "tree_fucker"
path = "src/lib.rs"

[[example]]
name = "scan"
path = "examples/scan.rs"

[[example]]
name = "tree"
path = "examples/tree.rs"
required-features = ["extra"]

[dependencies.alias]
version = "1.2.3"
features = ["std"]
optional = true
default-features = false
package = "original"

[dev-dependencies.test-helper]
version = "2.0"

[build-dependencies.builder]
version = "3.0"

[target."cfg(windows)".dependencies.windows-sys]
version = "0.61.2"

[lints.rust]
unsafe_code = "deny"
"""
COMMITTED = {
    "Cargo.toml": COMMITTED_MANIFEST.encode(),
    "README.md": b"# Packaged readme\n",
    "build.rs": b'fn main() { panic!("must not execute during upload"); }',
    "examples/scan.rs": b"fn main() {}\n",
    "examples/tree.rs": b"fn main() {}\n",
    "src/lib.rs": b"pub fn approved() {}\n",
}


def archive_members(sha=SHA, dirty=False):
    git = {"sha1": sha, **({"dirty": True} if dirty else {})}
    vcs = json.dumps({"git": git, "path_in_vcs": ""})
    return [
        (f"{PREFIX}.cargo_vcs_info.json", vcs.encode()),
        (f"{PREFIX}Cargo.toml", PACKAGED_MANIFEST.encode()),
        (f"{PREFIX}Cargo.toml.orig", COMMITTED["Cargo.toml"]),
        *(
            (PREFIX + name, data)
            for name, data in COMMITTED.items()
            if name != "Cargo.toml"
        ),
    ]


def replace_member(members, name, data):
    return [(path, data if path == PREFIX + name else old) for path, old in members]


def write_archive(archive, members):
    with tarfile.open(archive, "w:gz") as target:
        for name, data in members:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            target.addfile(member, io.BytesIO(data))


def git(repository, *args):
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class ReleaseTests(unittest.TestCase):
    def test_candidate_identity_is_bound_to_the_approved_checkout(self):
        release.validate_context(CONTEXT, PACKAGE, SHA, release.REPOSITORY, "123")
        for key, value in {
            "repository": "somewhere/else",
            "repositoryId": 456,
            "operation": "prepare",
            "stream": "other",
            "sourceSha": "b" * 40,
            "version": "0.2.0",
        }.items():
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                release.validate_context(
                    {**CONTEXT, key: value}, PACKAGE, SHA, release.REPOSITORY, "123"
                )

    def test_latest_ci_run_must_have_succeeded_on_master(self):
        green = {
            "id": 10,
            "run_attempt": 1,
            "head_sha": SHA,
            "head_branch": "master",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "html_url": "https://example.invalid/run/10",
        }
        release.validate_run([green], SHA, "ci.yml")
        for change in [
            {"head_sha": "b" * 40},
            {"event": "pull_request"},
            {"head_branch": "release/package-readiness"},
            {"conclusion": "failure"},
            {"status": "in_progress", "conclusion": None},
        ]:
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                release.validate_run([{**green, **change}], SHA, "ci.yml")
        for change in [{"id": 11}, {"run_attempt": 2}]:
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                release.validate_run(
                    [green, {**green, **change, "conclusion": "failure"}], SHA, "ci.yml"
                )

    @patch("release.gh")
    def test_unsigned_commit_is_rejected_before_any_publication(self, gh):
        gh.return_value = {"sha": SHA, "commit": {"verification": {"verified": False}}}
        with self.assertRaisesRegex(RuntimeError, "signature"):
            release.check(CONTEXT)
        gh.assert_called_once()

    @patch("release.gh")
    def test_both_ci_workflows_are_required(self, gh):
        green = {
            "id": 10,
            "run_attempt": 1,
            "head_sha": SHA,
            "head_branch": "master",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "html_url": "https://example.invalid/run/10",
        }
        gh.side_effect = [
            {"sha": SHA, "commit": {"verification": {"verified": True}}},
            {"workflow_runs": [green]},
            {"workflow_runs": []},
        ]
        with self.assertRaisesRegex(RuntimeError, "coordination-acceptance.yml"):
            release.check(CONTEXT)

    def test_archive_must_reproduce_the_approved_commit(self):
        members = archive_members()
        manifest = PACKAGED_MANIFEST
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "candidate.crate"
            write_archive(archive, members)
            self.assertEqual(
                len(release.archive_digest(archive, CONTEXT, COMMITTED)), 64
            )
            cases = {
                "another commit": (archive_members(sha="b" * 40), "commit mismatch"),
                "dirty tree": (archive_members(dirty=True), "commit mismatch"),
                "changed file": (
                    replace_member(members, "src/lib.rs", b"pub fn injected() {}\n"),
                    "src/lib.rs differs",
                ),
                "added file": (
                    [*members, (f"{PREFIX}src/extra.rs", b"")],
                    "files differ",
                ),
                "missing file": (members[:-1], "files differ"),
                "changed original manifest": (
                    replace_member(members, "Cargo.toml.orig", b"[package]\n"),
                    "Cargo.toml.orig differs",
                ),
                "redirected build script": (
                    replace_member(
                        members,
                        "Cargo.toml",
                        manifest.replace(
                            'build = "build.rs"', 'build = "src/lib.rs"'
                        ).encode(),
                    ),
                    "Cargo.toml differs",
                ),
                "redirected library": (
                    replace_member(
                        members,
                        "Cargo.toml",
                        manifest.replace(
                            'path = "src/lib.rs"', 'path = "build.rs"'
                        ).encode(),
                    ),
                    "Cargo.toml differs",
                ),
                "changed dependency": (
                    replace_member(
                        members,
                        "Cargo.toml",
                        manifest.replace('"1.2.3"', '"9.9.9"').encode(),
                    ),
                    "Cargo.toml differs",
                ),
                "another version": (
                    replace_member(
                        members,
                        "Cargo.toml",
                        manifest.replace(
                            'version = "0.1.0"', 'version = "0.2.0"'
                        ).encode(),
                    ),
                    "Cargo.toml differs",
                ),
                "repeated member": (
                    [*members, (f"{PREFIX}src/lib.rs", b"pub fn injected() {}\n")],
                    "repeats a member",
                ),
                "member outside the package": (
                    [*members, ("elsewhere/src/lib.rs", b"")],
                    "outside the package",
                ),
            }
            for case, (candidate, error) in cases.items():
                write_archive(archive, candidate)
                with (
                    self.subTest(case=case),
                    self.assertRaisesRegex(RuntimeError, error),
                ):
                    release.archive_digest(archive, CONTEXT, COMMITTED)

    def test_archive_members_must_be_regular_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "candidate.crate"
            with tarfile.open(archive, "w:gz") as target:
                for name, data in archive_members():
                    member = tarfile.TarInfo(name)
                    if name == f"{PREFIX}src/lib.rs":
                        member.type = tarfile.SYMTYPE
                        member.linkname = "../build.rs"
                        target.addfile(member)
                    else:
                        member.size = len(data)
                        target.addfile(member, io.BytesIO(data))
            with self.assertRaisesRegex(RuntimeError, "regular files"):
                release.archive_digest(archive, CONTEXT, COMMITTED)

    def test_normalized_manifest_discovers_cargo_targets(self):
        manifest = {
            "package": {"name": "tree-fucker", "version": "0.1.0"},
            "lib": {"path": "src/core.rs"},
            "bin": [{"name": "helper", "test": False}],
            "dependencies": {"imbl": "7.0.2"},
            "lints": {"rust": {"unsafe_code": "deny"}},
        }
        files = {
            "Cargo.toml",
            "src/core.rs",
            "src/main.rs",
            "src/bin/helper.rs",
            "src/bin/tool/main.rs",
            "src/bin/tool/args.rs",
            "tests/scan.rs",
            "tests/common/mod.rs",
            "benches/layers/main.rs",
        }
        self.assertEqual(
            release.normalized_manifest(manifest, files),
            {
                "package": {
                    "name": "tree-fucker",
                    "version": "0.1.0",
                    "build": False,
                    "autolib": False,
                    "autobins": False,
                    "autoexamples": False,
                    "autotests": False,
                    "autobenches": False,
                },
                "dependencies": {"imbl": {"version": "7.0.2"}},
                "lints": {"rust": {"unsafe_code": "deny"}},
                "lib": {"name": "tree_fucker", "path": "src/core.rs"},
                "bin": [
                    {"name": "helper", "path": "src/bin/helper.rs", "test": False},
                    {"name": "tool", "path": "src/bin/tool/main.rs"},
                    {"name": "tree-fucker", "path": "src/main.rs"},
                ],
                "test": [{"name": "scan", "path": "tests/scan.rs"}],
                "bench": [{"name": "layers", "path": "benches/layers/main.rs"}],
            },
        )
        minimal = {"package": {"name": "tree-fucker", "version": "0.1.0"}}
        self.assertNotIn("lib", release.normalized_manifest(minimal, {"Cargo.toml"}))
        self.assertNotIn("lints", release.normalized_manifest(minimal, {"Cargo.toml"}))

    def test_committed_files_follow_the_package_include_list(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            git(repository, "init", "--quiet")
            (repository / "src/bin").mkdir(parents=True)
            (repository / "Cargo.toml").write_text(
                '[package]\nname = "fixture"\ninclude = ["/src/**", "/Cargo.toml"]\n'
            )
            (repository / "src/lib.rs").write_text("pub fn approved() {}\n")
            (repository / "src/bin/run.rs").write_text("fn main() {}\n")
            (repository / "src/bin/run.rs").chmod(0o755)
            (repository / "src/alias.rs").symlink_to("lib.rs")
            (repository / "notes.txt").write_text("repository only\n")
            git(repository, "add", ".")
            git(
                repository,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{SHA},src/vendor",
            )
            git(
                repository,
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--quiet",
                "--message",
                "Fixture",
            )
            sha = git(repository, "rev-parse", "HEAD")
            with patch("release.ROOT", repository):
                self.assertEqual(
                    release.committed_files(sha),
                    {
                        "Cargo.toml": (repository / "Cargo.toml").read_bytes(),
                        "src/bin/run.rs": b"fn main() {}\n",
                        "src/lib.rs": b"pub fn approved() {}\n",
                    },
                )
                (repository / "Cargo.toml").write_text(
                    '[package]\nname = "fixture"\ninclude = ["src/**"]\n'
                )
                git(
                    repository,
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "--quiet",
                    "--all",
                    "--message",
                    "Unanchored",
                )
                with self.assertRaisesRegex(RuntimeError, "anchored"):
                    release.committed_files(git(repository, "rev-parse", "HEAD"))

    @unittest.skipUnless(
        CARGO_ARCHIVE.is_file(), "tests/package/verify.py creates the archive in CI"
    )
    def test_cargo_archive_matches_its_commit(self):
        with (
            tarfile.open(CARGO_ARCHIVE) as source,
            source.extractfile(f"{CARGO_PREFIX}.cargo_vcs_info.json") as file,
        ):
            sha = json.load(file)["git"]["sha1"]
        release.verify_archive(
            CARGO_ARCHIVE,
            {**CONTEXT, "sourceSha": sha, "version": CARGO_VERSION},
            release.committed_files(sha),
        )

    def test_existing_publication_must_match_the_exact_archive(self):
        entry = {
            "crate": release.CRATE,
            "num": "0.1.0",
            "yanked": False,
            "checksum": "digest",
        }
        release.validate_registry(entry, "0.1.0", "digest")
        for bad in [
            None,
            {**entry, "yanked": True},
            {**entry, "checksum": "other"},
            {**entry, "num": "0.2.0"},
        ]:
            with self.subTest(entry=bad), self.assertRaises(RuntimeError):
                release.validate_registry(bad, "0.1.0", "digest")

    @patch("release.urllib.request.urlopen")
    def test_only_registry_404_means_unpublished(self, urlopen):
        for code in [404, 403, 429, 503]:
            urlopen.side_effect = urllib.error.HTTPError(
                "https://example.invalid", code, "error", None, io.BytesIO()
            )
            with self.subTest(code=code):
                if code == 404:
                    self.assertIsNone(release.registry_version("0.1.0"))
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        release.registry_version("0.1.0")

    @patch("release.subprocess.run")
    def test_github_auth_and_network_errors_are_not_missing_objects(self, run):
        for error in [
            "gh: Not Found (HTTP 404)",
            "gh: Bad credentials (HTTP 401)",
            "connection timed out",
        ]:
            run.return_value = subprocess.CompletedProcess([], 1, "", error)
            with self.subTest(error=error):
                if "404" in error:
                    self.assertIsNone(
                        release.gh("repos/example/release", optional=True)
                    )
                else:
                    with self.assertRaises(RuntimeError):
                        release.gh("repos/example/release", optional=True)

    @patch("release.gh")
    def test_conflicting_tag_is_rejected_even_without_a_github_release(self, gh):
        gh.side_effect = [
            {"object": {"type": "tag", "sha": "c" * 40}},
            {"object": {"type": "commit", "sha": "b" * 40}},
        ]
        with self.assertRaisesRegex(RuntimeError, "another commit"):
            release.version_tag(CONTEXT)

    @patch("release.gh")
    def test_matching_published_release_can_be_reused(self, gh):
        published = {"tag_name": "v0.1.0", "draft": False, "prerelease": False}
        gh.side_effect = [
            published,
            {"object": {"type": "tag", "sha": "c" * 40}},
            {"object": {"type": "commit", "sha": SHA}},
        ]
        self.assertEqual(release.github_release(CONTEXT), published)
        for change in [{"draft": True}, {"prerelease": True}, {"tag_name": "v0.2.0"}]:
            gh.side_effect = [{**published, **change}]
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                release.github_release(CONTEXT)

    def test_repository_config_requires_both_publications_and_approval(self):
        config = json.loads((release.ROOT / ".github/beepboop.json").read_text())
        stream = config["streams"]["main"]
        self.assertEqual(stream["packages"], ["cargo:tree-fucker"])
        self.assertEqual(stream["promote"]["approval"], "required")
        self.assertEqual(
            set(stream["required"]),
            {"cargo:tree-fucker", "github-release:kjanat/tree-fucker"},
        )
        self.assertEqual(
            stream["promote"]["workflow"]["publications"], stream["required"]
        )


if __name__ == "__main__":
    unittest.main()
