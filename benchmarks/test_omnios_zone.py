"""Zone setup must preserve commands streamed to its calling shell."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("omnios_zone.sh").resolve()


class ZoneInputTests(unittest.TestCase):
    def run_setup(self, chmod_status=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ["zfs", "zonecfg", "zoneadm", "zlogin"]:
                command = root / name
                command.write_text(
                    "#!/bin/sh\n"
                    'if [ "${0##*/}" = zlogin ]; then\n'
                    '  if [ "$1" = -n ]; then shift; else cat >/dev/null; fi\n'
                    f'  if [ "$2" = chmod ]; then exit {chmod_status}; fi\n'
                    "fi\n"
                )
                command.chmod(0o700)
            return subprocess.run(
                ["sh", "-e"],
                input=f"sh {shlex.quote(str(SCRIPT))}\nprintf 'tests reached\\n'\n",
                env={**os.environ, "PATH": f"{root}:{os.defpath}"},
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

    def test_setup_preserves_remaining_ci_commands(self):
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "tests reached\n")

    def test_setup_failure_stops_ci_commands(self):
        result = self.run_setup(chmod_status=42)
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
