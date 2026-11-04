"""Check archive-only publishing with a fake registry credential."""

import io
import json
import os
import struct
import tempfile
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch

import release
from test_release import (
    COMMITTED,
    CONTEXT,
    archive_members,
    replace_member,
    write_archive,
)


class PublishTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.archive = Path(temporary.name) / "candidate.crate"
        write_archive(self.archive, archive_members())

    def test_metadata_preserves_dependencies_and_package_details(self):
        metadata = release.publication_metadata(self.archive, CONTEXT)
        self.assertEqual(metadata["name"], "tree-fucker")
        self.assertEqual(metadata["vers"], "0.1.0")
        self.assertEqual(metadata["rust_version"], "1.99.1")
        self.assertEqual(metadata["license"], "MIT OR Apache-2.0")
        self.assertEqual(metadata["readme"], "# Packaged readme\n")
        self.assertEqual(metadata["features"], {"extra": ["dep:alias"]})
        self.assertEqual(
            metadata["deps"][0],
            {
                "name": "original",
                "explicit_name_in_toml": "alias",
                "version_req": "1.2.3",
                "optional": True,
                "default_features": False,
                "features": ["std"],
                "kind": "normal",
                "target": None,
                "registry": None,
            },
        )
        self.assertEqual(metadata["deps"][1]["kind"], "dev")
        self.assertEqual(metadata["deps"][2]["kind"], "build")
        self.assertEqual(metadata["deps"][3]["target"], "cfg(windows)")

    @patch("release.subprocess.run", side_effect=AssertionError("executed code"))
    @patch(
        "release.subprocess.check_output", side_effect=AssertionError("executed code")
    )
    def test_upload_sends_the_exact_archive_without_executing_code(self, read, run):
        received = []

        class Registry(BaseHTTPRequestHandler):
            def do_PUT(self):
                received.append((
                    self.path,
                    self.headers,
                    self.rfile.read(int(self.headers["Content-Length"])),
                ))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"warnings": {}}')

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Registry)
        thread = Thread(target=server.serve_forever)
        thread.start()
        request = release.urllib.request.Request

        def local_request(url, **kwargs):
            self.assertEqual(url, "https://crates.io/api/v1/crates/new")
            return request(
                f"http://127.0.0.1:{server.server_port}/api/v1/crates/new", **kwargs
            )

        before = self.archive.read_bytes()
        try:
            with patch("release.urllib.request.Request", side_effect=local_request):
                release.publish_archive(
                    self.archive, CONTEXT, "fixture-token", COMMITTED
                )
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
        self.assertEqual(len(received), 1)
        path, headers, body = received[0]
        self.assertEqual(path, "/api/v1/crates/new")
        self.assertEqual(headers["Authorization"], "fixture-token")
        self.assertEqual(headers["Content-Type"], "application/octet-stream")
        metadata_size = struct.unpack_from("<I", body)[0]
        metadata = json.loads(body[4 : 4 + metadata_size])
        self.assertEqual(metadata["name"], "tree-fucker")
        offset = 4 + metadata_size
        archive_size = struct.unpack_from("<I", body, offset)[0]
        self.assertEqual(archive_size, len(before))
        self.assertEqual(body[offset + 4 :], before)
        self.assertEqual(self.archive.read_bytes(), before)

    @patch("release.urllib.request.build_opener")
    def test_wrong_archive_is_rejected_before_upload(self, opener):
        with self.assertRaisesRegex(RuntimeError, "commit mismatch"):
            release.publish_archive(
                self.archive,
                {**CONTEXT, "sourceSha": "b" * 40},
                "fixture-token",
                COMMITTED,
            )
        opener.assert_not_called()

    @patch("release.urllib.request.build_opener")
    def test_altered_archive_member_is_rejected_before_upload(self, opener):
        write_archive(
            self.archive,
            replace_member(archive_members(), "src/lib.rs", b"pub fn injected() {}\n"),
        )
        with self.assertRaisesRegex(RuntimeError, "src/lib.rs differs"):
            release.publish_archive(self.archive, CONTEXT, "fixture-token", COMMITTED)
        opener.assert_not_called()

    def test_missing_credentials_fail_before_upload(self):
        with self.assertRaisesRegex(RuntimeError, "token is missing"):
            release.publish_archive(self.archive, CONTEXT, None, COMMITTED)

    @patch("release.urllib.request.build_opener")
    def test_http_errors_and_registry_errors_are_failures(self, opener):
        for code in [302, 401, 403, 409, 429, 503]:
            opener.return_value.open.side_effect = urllib.error.HTTPError(
                "https://crates.io/api/v1/crates/new", code, "error", None, io.BytesIO()
            )
            with (
                self.subTest(code=code),
                self.assertRaisesRegex(RuntimeError, str(code)),
            ):
                release.publish_archive(
                    self.archive, CONTEXT, "fixture-token", COMMITTED
                )
        opener.return_value.open.side_effect = None
        opener.return_value.open.return_value = io.BytesIO(
            b'{"errors":[{"detail":"bad"}]}'
        )
        with self.assertRaisesRegex(RuntimeError, "rejected"):
            release.publish_archive(self.archive, CONTEXT, "fixture-token", COMMITTED)

    @patch("release.urllib.request.build_opener")
    def test_registry_warnings_are_failures(self, opener):
        opener.return_value.open.return_value = io.BytesIO(
            b'{"warnings":{"invalid_categories":[],"other":["unexpected"]}}'
        )
        with self.assertRaisesRegex(RuntimeError, "reported other"):
            release.publish_archive(self.archive, CONTEXT, "fixture-token", COMMITTED)

    def test_redirect_cannot_forward_credentials(self):
        request = release.urllib.request.Request(
            "https://crates.io/api/v1/crates/new",
            headers={"Authorization": "fixture-token"},
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            release.NoRedirect().redirect_request(
                request, None, 307, "redirect", {}, "https://example.invalid/collect"
            )
        caught.exception.close()

    @patch("release.committed_files", return_value=COMMITTED)
    @patch("release.publish_archive")
    @patch("release.context_from_checkout")
    def test_cli_removes_token_before_running_checkout_checks(
        self, context, publish, committed
    ):
        def inspect_context():
            self.assertNotIn("CARGO_REGISTRY_TOKEN", os.environ)
            return CONTEXT

        context.side_effect = inspect_context
        with (
            patch.dict(os.environ, {"CARGO_REGISTRY_TOKEN": "fixture-token"}),
            patch("sys.argv", ["release.py", "publish"]),
        ):
            release.main()
        self.assertEqual(publish.call_args.args[2], "fixture-token")
        self.assertIs(publish.call_args.args[3], COMMITTED)
        committed.assert_called_once_with(CONTEXT["sourceSha"])


if __name__ == "__main__":
    unittest.main()
