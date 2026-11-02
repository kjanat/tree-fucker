"""Prepare and run a local FreeBSD VM for native coordination acceptance."""

import argparse
import hashlib
import lzma
import os
import shutil
import subprocess
from pathlib import Path

if __package__:
    from .vm_support import (
        ROOT,
        run,
    )
    from .vm_support import (
        download as download_file,
    )
    from .vm_support import (
        ssh as ssh_command,
    )
    from .vm_support import (
        sync as sync_files,
    )
else:
    from vm_support import (
        ROOT,
        run,
    )
    from vm_support import (
        download as download_file,
    )
    from vm_support import (
        ssh as ssh_command,
    )
    from vm_support import (
        sync as sync_files,
    )
STATE = ROOT / "target/native/freebsd"
RELEASE = "15.0-RELEASE"
IMAGE = f"FreeBSD-{RELEASE}-amd64-BASIC-CLOUDINIT-ufs.qcow2"
BASE_URL = f"https://download.freebsd.org/releases/VM-IMAGES/{RELEASE}/amd64/Latest"


def download(name: str) -> Path:
    return download_file(STATE, BASE_URL, name)


def prepare() -> None:
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    STATE.chmod(0o700)
    checksums = download("CHECKSUM.SHA256").read_text()
    archive = download(IMAGE + ".xz")
    prefix = f"SHA256 ({archive.name}) = "
    expected = next(
        line.removeprefix(prefix)
        for line in checksums.splitlines()
        if line.startswith(prefix)
    )
    with archive.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if actual != expected:
        raise SystemExit(
            f"Checksum mismatch for {archive.name}; remove the incomplete archive and prepare again"
        )
    image = STATE / IMAGE
    if not image.exists():
        print("Expanding verified image", flush=True)
        temporary = image.with_suffix(".partial")
        with lzma.open(archive) as source, temporary.open("wb") as output:
            shutil.copyfileobj(source, output)
        temporary.replace(image)
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
            "freebsd-tests",
            "-f",
            str(key),
        )
    # The seed contains only a public key. The private key stays on the host.
    public = key.with_suffix(".pub").read_text().strip()
    (STATE / "meta-data").write_text(
        "instance-id: tree-fucker-freebsd\nlocal-hostname: freebsd-coordination\n"
    )
    (STATE / "user-data").write_text(
        "#cloud-config\n"
        "ssh_pwauth: false\n"
        "users:\n"
        "  - name: root\n"
        "    ssh_authorized_keys:\n"
        f"      - {public}\n"
        "network:\n"
        "  ethernets:\n"
        "    vtnet0:\n"
        "      dhcp4: true\n"
        "runcmd:\n"
        "  - printf '\\nPermitRootLogin prohibit-password\\nPasswordAuthentication no\\n' >> /etc/ssh/sshd_config\n"
        "  - sysrc sshd_enable=YES\n"
        "  - service sshd restart\n"
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


def ssh(port: int) -> list[str]:
    return ssh_command(STATE, port)


def sync(port: int) -> None:
    sync_files(STATE, port)


def provision(port: int) -> None:
    script = """set -e
env ASSUME_ALWAYS_YES=yes pkg bootstrap
pkg install -y curl
if ! test -x /root/.cargo/bin/rustup; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /root/rustup-init.sh
    sh /root/rustup-init.sh -y --profile minimal --default-toolchain nightly \
        -c rustfmt -c clippy -c rust-src -c rust-analyzer
fi
mkdir -p /var/run/tree-fucker
if ! mount -p | awk '$2 == "/var/run/tree-fucker" && $3 == "tmpfs" { found=1 } END { exit !found }'; then
    mount -t tmpfs -o mode=1777 tmpfs /var/run/tree-fucker
fi
"""
    run(*ssh(port), script)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=40222)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("prepare")
    commands.add_parser("run")
    commands.add_parser("sync")
    commands.add_parser("provision")
    execute = commands.add_parser("exec")
    execute.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    if args.action == "prepare":
        prepare()
    elif args.action == "run":
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
            f"file={STATE / 'disk.qcow2'},format=qcow2,if=virtio",
            "-drive",
            f"file={STATE / 'seed.iso'},media=cdrom,readonly=on",
            "-netdev",
            f"user,id=net0,hostfwd=tcp:127.0.0.1:{args.port}-:22",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-nographic",
        ]
        os.execvp(command[0], command)
    elif args.action == "sync":
        sync(args.port)
    elif args.action == "provision":
        provision(args.port)
    else:
        if not args.command:
            parser.error("exec requires a remote shell command")
        raise SystemExit(
            subprocess.run(ssh(args.port) + args.command, check=False).returncode
        )


if __name__ == "__main__":
    main()
