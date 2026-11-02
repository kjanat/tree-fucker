"""Run a disposable Windows guest through a real reboot and retained-state test."""

import argparse
import http.server
import ipaddress
import json
import os
import queue
import secrets
import shutil
import signal
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
    freerdp = shutil.which("xfreerdp3") or shutil.which("xfreerdp")
    if freerdp is None or shutil.which("xvfb-run") is None:
        raise RuntimeError(
            "FreeRDP and xvfb-run are required for real session acceptance"
        )
    root = Path("target/benchmarks/windows-reboot").resolve()
    root.mkdir(parents=True, exist_ok=False)
    oem = root / "oem"
    shutil.copytree(Path(__file__).parent / "windows_reboot", oem)
    shutil.copyfile(args.executable, oem / "coordination_power.exe")
    accounts = {
        "standard": ("CoordinationUser", "Tf!" + secrets.token_hex(16)),
        "admin": ("CoordinationAdmin", "Tf!" + secrets.token_hex(16)),
    }
    # Disposable credentials stay out of command lines, reports and artifacts.
    # The guest consumes this private OEM input; FreeRDP reads its copy on stdin.
    account_input = oem / "accounts.ps1"
    with os.fdopen(
        os.open(account_input, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as stream:
        stream.write(
            "$Accounts = @{\n"
            + "\n".join(
                f"  {role} = @{{ Name = '{name}'; Password = '{password}' }}"
                for role, (name, password) in accounts.items()
            )
            + "\n}\n"
        )
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
    rdp_requests: queue.Queue[tuple[str, int]] = queue.Queue()
    rdp_connections = []
    rdp_requested = 0

    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            nonlocal rdp_requested
            if self.path not in ("/result", "/rdp") or complete.is_set():
                self.send_error(409)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1024 * 1024:
                self.send_error(413)
                return
            result = json.loads(self.rfile.read(length))
            if self.path == "/rdp":
                role, count = result.get("role"), result.get("count")
                if (
                    role not in accounts
                    or type(count) is not int
                    or not 1 <= count <= 2
                ):
                    self.send_error(400)
                    return
                if rdp_requested + count > 4:
                    self.send_error(409)
                    return
                rdp_requested += count
                rdp_requests.put((role, count))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")
                return
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

    server = http.server.HTTPServer(("0.0.0.0", 8765), Receiver)
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
        "-p",
        "127.0.0.1:13389:3389/tcp",
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
                while not rdp_requests.empty():
                    role, count = rdp_requests.get_nowait()
                    name, password = accounts[role]
                    for _ in range(count):
                        logfile = (root / f"rdp-{len(rdp_connections)}.log").open("w")
                        connection = subprocess.Popen(
                            [
                                "xvfb-run",
                                "-a",
                                freerdp,
                                "/v:127.0.0.1:13389",
                                f"/u:{name}",
                                "/d:.",
                                f"/client-hostname:tf-fixture-{len(rdp_connections)}",
                                "/from-stdin:force",
                                "/cert:ignore",
                                "/sec:nla",
                                "/size:800x600",
                                "/log-level:WARN",
                            ],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            start_new_session=True,
                        )
                        rdp_sanitizer = subprocess.Popen(
                            ["envctl", "redact"],
                            stdin=connection.stdout,
                            stdout=logfile,
                        )
                        assert (
                            connection.stdout is not None
                            and connection.stdin is not None
                        )
                        connection.stdout.close()
                        rdp_connections.append((connection, rdp_sanitizer, logfile))
                        connection.stdin.write(password + "\n")
                        connection.stdin.close()
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
                            "sudo",
                            "env",
                            "LIBGUESTFS_BACKEND=direct",
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
                        check=False,
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
            cleanup_errors = []
            for connection, rdp_sanitizer, logfile in rdp_connections:
                try:
                    if connection.poll() is None:
                        try:
                            os.killpg(connection.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                    try:
                        connection.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(connection.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        connection.wait(timeout=10)
                    if rdp_sanitizer.wait(timeout=10):
                        cleanup_errors.append("RDP log redaction failed")
                except subprocess.TimeoutExpired:
                    cleanup_errors.append("RDP cleanup timed out")
                    rdp_sanitizer.kill()
                    rdp_sanitizer.wait(timeout=10)
                finally:
                    logfile.close()
            if process.poll() is None:
                subprocess.run(
                    ["docker", "stop", "--timeout", "30", "coordination-reboot"],
                    check=False,
                )
            process.wait(timeout=60)
            if sanitizer.wait(timeout=60):
                cleanup_errors.append("Guest log redaction failed")
            server.shutdown()
            server.server_close()
            if cleanup_errors:
                raise RuntimeError("; ".join(cleanup_errors))
    if (
        outcome.get("status") != "passed"
        or outcome.get("phase") != "windows_after_reboot"
        or outcome.get("sessions", {}).get("status") != "passed"
    ):
        raise RuntimeError(
            f"Windows reboot acceptance failed; see {root / 'result.json'}"
        )
    print(
        "Windows reboot and real user sessions: retained accounting, ownership, UAC and principal isolation verified"
    )


if __name__ == "__main__":
    main()
