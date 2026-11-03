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

    def test_archive_rejects_another_commit_dirty_tree_and_wrong_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "candidate.crate"
            for sha, dirty, version in [
                (SHA, False, "0.1.0"),
                ("b" * 40, False, "0.1.0"),
                (SHA, True, "0.1.0"),
                (SHA, False, "0.2.0"),
            ]:
                with tarfile.open(archive, "w:gz") as target:
                    files = {
                        ".cargo_vcs_info.json": json.dumps({
                            "git": {"sha1": sha, "dirty": dirty}
                        }),
                        "Cargo.toml": f'[package]\nname = "tree-fucker"\nversion = "{version}"\n',
                    }
                    for name, content in files.items():
                        data = content.encode()
                        member = tarfile.TarInfo(f"tree-fucker-0.1.0/{name}")
                        member.size = len(data)
                        target.addfile(member, io.BytesIO(data))
                with self.subTest(sha=sha, dirty=dirty, version=version):
                    if (sha, dirty, version) == (SHA, False, "0.1.0"):
                        self.assertEqual(
                            len(release.archive_digest(archive, CONTEXT)), 64
                        )
                    else:
                        with self.assertRaises(RuntimeError):
                            release.archive_digest(archive, CONTEXT)

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
