"""Prepare and run a local OmniOS VM for native coordination acceptance."""

import argparse
import hashlib
import os
import shutil
import subprocess
from pathlib import Path

if __package__:
    from .vm_support import ROOT, download, run, ssh, sync
else:
    from vm_support import ROOT, download, run, ssh, sync

STATE = ROOT / "target/native/omnios"
RELEASE = "r151058"
IMAGE = f"omnios-{RELEASE}.cloud.qcow2"
BASE_URL = f"https://downloads.omnios.org/media/{RELEASE}"


def prepare() -> None:
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    STATE.chmod(0o700)
    expected = download(STATE, BASE_URL, IMAGE + ".sha256").read_text().strip()
    image = download(STATE, BASE_URL, IMAGE)
    with image.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != expected:
            raise SystemExit(f"Checksum mismatch for {IMAGE}")
    disk = STATE / "disk.qcow2"
    if not disk.exists():
        run(
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            str(image),
            str(disk),
        )
        run("qemu-img", "resize", str(disk), "24G")
    key = STATE / "id_ed25519"
    if not key.exists():
        run(
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "omnios-tests",
            "-f",
            str(key),
        )
    public = key.with_suffix(".pub").read_text().strip()
    (STATE / "meta-data").write_text(
        "instance-id: tree-fucker-omnios\nlocal-hostname: omnios-coordination\n"
    )
    (STATE / "user-data").write_text(
        "#cloud-config\n"
        "disable_root: false\n"
        "ssh_pwauth: false\n"
        "users:\n"
        "  - name: root\n"
        "    ssh_authorized_keys:\n"
        f"      - {public}\n"
    )
    run(
        "genisoimage",
        "-quiet",
        "-output",
        str(STATE / "seed.iso"),
        "-volid",
        "cidata",
        "-joliet",
        "-rock",
        str(STATE / "user-data"),
        str(STATE / "meta-data"),
    )
    print(f"Prepared {STATE.relative_to(ROOT)}", flush=True)


def provision(port: int) -> None:
    script = """set -e
pkg install build-essential curl || [ $? -eq 4 ]
if ! test -x /root/.cargo/bin/rustup; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /root/rustup-init.sh
    sh /root/rustup-init.sh -y --profile minimal --default-toolchain nightly \\
        -c rustfmt -c clippy -c rust-src -c rust-analyzer
fi
mkdir -p /var/run/tree-fucker
chmod 1777 /var/run/tree-fucker
"""
    run(*ssh(STATE, port), script)


def provision_zone(port: int) -> None:
    """Create the dedicated, network-isolated zone used by native fixtures."""
    run(*ssh(STATE, port), (ROOT / "benchmarks/omnios_zone.sh").read_text())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=40223)
    parser.add_argument(
        "--firmware-dir", type=Path, default=Path("/usr/share/edk2/x64")
    )
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ["prepare", "run", "sync", "provision", "provision-zone"]:
        commands.add_parser(name)
    commands.add_parser("exec").add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    if args.action == "prepare":
        prepare()
    elif args.action == "run":
        # UEFI avoids the Arch SeaBIOS build's illumos startup_modules panic.
        # Keep writable firmware variables private to this VM.
        firmware = args.firmware_dir / "OVMF_CODE.4m.fd"
        variables = STATE / "OVMF_VARS.4m.fd"
        if not firmware.is_file():
            parser.error("OVMF_CODE.4m.fd is missing; set --firmware-dir")
        if not variables.exists():
            shutil.copyfile(args.firmware_dir / variables.name, variables)
        command = [
            "qemu-system-x86_64",
            "-enable-kvm",
            "-cpu",
            "host",
            "-smp",
            "4",
            "-m",
            "4096",
            "-drive",
            f"if=pflash,format=raw,readonly=on,file={firmware}",
            "-drive",
            f"if=pflash,format=raw,file={variables}",
            "-drive",
            f"file={STATE / 'disk.qcow2'},format=qcow2,if=virtio",
            "-drive",
            f"file={STATE / 'seed.iso'},media=cdrom,readonly=on",
            "-netdev",
            f"user,id=net0,hostfwd=tcp:127.0.0.1:{args.port}-:22",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-nographic",
            "-no-reboot",
        ]
        os.execvp(command[0], command)
    elif args.action == "sync":
        sync(STATE, args.port)
    elif args.action == "provision":
        provision(args.port)
    elif args.action == "provision-zone":
        provision_zone(args.port)
    else:
        if not args.command:
            parser.error("exec requires a remote shell command")
        raise SystemExit(
            subprocess.run(ssh(STATE, args.port) + args.command, check=False).returncode
        )


if __name__ == "__main__":
    main()
