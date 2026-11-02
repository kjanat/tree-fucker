"""Build and run Windows coordination histories in an isolated Wine prefix."""

import argparse
import json
import os
import shlex
import shutil
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "target/native/windows"


def prepare() -> None:
    """Extract a signature-verified MinGW runtime from Arch/Manjaro repositories."""
    STATE.mkdir(parents=True, exist_ok=True)
    url = subprocess.check_output(
        ["pacman", "-Sp", "--print-format", "%l", "mingw-w64-crt"], text=True
    ).strip()
    if not url.startswith("https://") or "\n" in url:
        raise ValueError("expected one HTTPS runtime package URL from pacman")
    package = STATE / url.rsplit("/", 1)[1]
    for suffix in ["", ".sig"]:
        destination = Path(str(package) + suffix)
        if not destination.exists():
            temporary = Path(str(destination) + ".partial")
            with (
                urllib.request.urlopen(url + suffix, timeout=60) as source,
                temporary.open("wb") as output,
            ):
                shutil.copyfileobj(source, output)
            temporary.replace(destination)
    subprocess.run(
        ["pacman-key", "--verify", str(package) + ".sig", str(package)], check=True
    )
    subprocess.run(
        ["bsdtar", "-xf", str(package), "-C", str(STATE), "usr/x86_64-w64-mingw32/lib"],
        check=True,
    )


def run(test_filter: str | None) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    # Preserve caller flags, then select the installed LLVM import-library tool.
    dlltool = shutil.which("llvm-dlltool")
    if dlltool is None:
        raise RuntimeError("llvm-dlltool is required")
    flags = (
        env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
        if env.get("CARGO_ENCODED_RUSTFLAGS")
        else shlex.split(env.get("RUSTFLAGS", ""))
    )
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join([*flags, "-C", f"dlltool={dlltool}"])
    env["CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER"] = str(
        ROOT / "benchmarks/windows_linker.sh"
    )
    build = STATE / "build.jsonl"
    with build.open("w") as output:
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--target",
                "x86_64-pc-windows-gnu",
                "--test",
                "coordination_windows",
                "--no-run",
                "--message-format=json",
            ],
            cwd=ROOT,
            env=env,
            stdout=output,
            check=False,
        )
    executable = None
    for line in build.read_text().splitlines():
        event = json.loads(line)
        if event.get("reason") == "compiler-message":
            print(event["message"]["rendered"], end="")
        if (
            event.get("reason") == "compiler-artifact"
            and event.get("executable")
            and event["target"]["name"] == "coordination_windows"
        ):
            executable = event["executable"]
    result.check_returncode()
    if executable is None:
        raise RuntimeError("Cargo did not produce the Windows coordination executable")
    env.update(
        WINEPREFIX=str(STATE / "wine"),
        WINEARCH="win64",
        WINEDEBUG="-all",
        WINEDLLOVERRIDES="mscoree,mshtml=;winemenubuilder.exe,winex11.drv,winewayland.drv=d",
        DISPLAY="",
    )
    try:
        arguments = ["wine", executable, "--nocapture"]
        if test_filter is not None:
            arguments.append(test_filter)
        subprocess.run(arguments, cwd=ROOT, env=env, check=True)
    finally:
        # Only this helper's prefix; leave the user's Wine applications alone.
        subprocess.run(["wineserver", "-k"], env=env, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "run"])
    parser.add_argument("--filter", help="Run matching Rust test names")
    arguments = parser.parse_args()
    if arguments.action == "prepare":
        if arguments.filter is not None:
            parser.error("--filter requires run")
        prepare()
    else:
        run(arguments.filter)
