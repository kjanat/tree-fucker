"""Run a disposable Windows guest through a real reboot and retained-state test."""

import argparse
import http.server
import ipaddress
import json
import shutil
import subprocess
import threading
from pathlib import Path

from resources import redacted


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    args = parser.parse_args()
    redacted("")
    if shutil.which("guestfish") is None:
        raise RuntimeError("guestfish is required to recover offline guest evidence")
    root = Path("target/benchmarks/windows-reboot").resolve()
    root.mkdir(parents=True, exist_ok=False)
    oem = root / "oem"
    shutil.copytree(Path(__file__).parent / "windows_reboot", oem)
    shutil.copyfile(args.executable, oem / "coordination_power.exe")
    gateway = subprocess.run(
        [
            "docker",
            "network",
            "inspect",
            "bridge",
            "--format",
            "{{(index .IPAM.Config 0).Gateway}}",
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    address = redacted(gateway.stdout).strip()
    ipaddress.IPv4Address(address)
    (oem / "controller.txt").write_text(address)
    complete = threading.Event()
    outcome = {}

    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/result" or complete.is_set():
                self.send_error(409)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1024 * 1024:
                self.send_error(413)
                return
            result = json.loads(self.rfile.read(length))
            (root / "result.json").write_text(
                redacted(json.dumps(result, indent=2)) + "\n"
            )
            outcome.update(result)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")
            complete.set()

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8765), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    # The controller remains on Linux while the Windows kernel and all its
    # processes restart. The guest disk is retained for both fixture phases.
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        "coordination-reboot",
        "--device",
        "/dev/kvm",
        "-e",
        "VERSION=2022",
        "-e",
        "RAM_SIZE=4G",
        "-e",
        "CPU_CORES=2",
        "-e",
        "DISK_SIZE=40G",
        "-e",
        "NETWORK=user",
        "-e",
        "SAMBA=N",
        "-e",
        "WEB=N",
        "-e",
        "DISPLAY=disabled",
        "-v",
        f"{oem}:/oem:ro",
        "-v",
        f"{root / 'disk'}:/storage",
        "dockurr/windows:latest",
    ]
    with (root / "guest.log").open("w") as log:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        sanitizer = subprocess.Popen(
            ["envctl", "redact"], stdin=process.stdout, stdout=log
        )
        assert process.stdout is not None
        process.stdout.close()
        try:
            for _ in range(45 * 60):
                if complete.wait(1):
                    break
                if process.poll() is not None:
                    disks = list((root / "disk").glob("*.img"))
                    if len(disks) != 1:
                        raise RuntimeError(
                            f"Guest exited {process.returncode} without one retained disk"
                        )
                    recovered = subprocess.run(
                        [
                            "guestfish",
                            "--ro",
                            "-a",
                            str(disks[0]),
                            "-i",
                            "cat",
                            "/coordination-reboot/result.json",
                        ],
                        capture_output=True,
                        timeout=120,
                    )
                    if recovered.returncode:
                        (root / "recovery.log").write_text(
                            redacted(recovered.stderr.decode(errors="replace"))
                        )
                        raise RuntimeError(
                            f"Guest exited {process.returncode} without a readable result"
                        )
                    outcome.update(
                        json.loads(redacted(recovered.stdout.decode("utf-8-sig")))
                    )
                    (root / "result.json").write_text(
                        json.dumps(outcome, indent=2) + "\n"
                    )
                    break
            else:
                raise TimeoutError(
                    "Windows did not report reboot acceptance within 45 minutes"
                )
        finally:
            if process.poll() is None:
                subprocess.run(
                    ["docker", "stop", "--timeout", "30", "coordination-reboot"],
                    check=False,
                )
            process.wait(timeout=60)
            if sanitizer.wait(timeout=60):
                raise RuntimeError("Guest log redaction failed")
            server.shutdown()
            server.server_close()
    if (
        outcome.get("status") != "passed"
        or outcome.get("phase") != "windows_after_reboot"
    ):
        raise RuntimeError(
            f"Windows reboot acceptance failed; see {root / 'result.json'}"
        )
    print(
        "Windows reboot: retained generation, debt, recovered ownership, and shared clock verified"
    )


if __name__ == "__main__":
    main()
