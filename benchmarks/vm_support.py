"""Shared image transfer and SSH helpers for repository-owned native VMs."""

import shutil
import subprocess
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args: str) -> None:
    subprocess.run(args, check=True)


def download(state: Path, base_url: str, name: str) -> Path:
    destination = state / name
    if not destination.exists():
        temporary = destination.with_suffix(destination.suffix + ".partial")
        print(f"Downloading {name}", flush=True)
        with (
            urllib.request.urlopen(f"{base_url}/{name}", timeout=60) as response,
            temporary.open("wb") as output,
        ):
            shutil.copyfileobj(response, output)
        temporary.replace(destination)
    return destination


def ssh(state: Path, port: int) -> list[str]:
    return [
        "ssh",
        "-p",
        str(port),
        "-i",
        str(state / "id_ed25519"),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={state / 'known_hosts'}",
        "root@127.0.0.1",
    ]


def sync(state: Path, port: int) -> None:
    # Explicit public build inputs avoid copying host configuration or artifacts.
    sources = [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "rustfmt.toml",
        "src",
        "tests",
        "benches",
        "benchmarks",
        ".cargo/config.toml",
    ]
    archive = state / "source.tar"
    # OmniOS's base tar accepts POSIX ustar, but not Python's default PAX
    # extended headers. Build inputs fit ustar's path and integer limits.
    with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as output:
        for source in sources:
            output.add(ROOT / source, arcname=source)
    with archive.open("rb") as source:
        subprocess.run(
            ssh(state, port)
            + ["mkdir -p /root/tree-fucker && tar -xf - -C /root/tree-fucker"],
            stdin=source,
            check=True,
        )
