"""Exercise live coordination through an observed macOS system sleep/wake."""

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


def kernel_time(name: str) -> int:
    class Timeval(ctypes.Structure):
        _fields_ = [("seconds", ctypes.c_long), ("microseconds", ctypes.c_int)]

    libc = ctypes.CDLL(None, use_errno=True)
    query = libc.sysctlbyname
    query.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    query.restype = ctypes.c_int
    value = Timeval()
    size = ctypes.c_size_t(ctypes.sizeof(value))
    if query(name.encode(), ctypes.byref(value), ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), name)
    if size.value != ctypes.sizeof(value):
        raise ValueError(f"Unexpected {name} layout")
    return value.seconds * 1_000_000 + value.microseconds


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--allow-system-sleep", action="store_true", required=True)
    args = parser.parse_args()
    output = Path("target/benchmarks/macos-sleep")
    output.mkdir(parents=True, exist_ok=False)
    root = Path(tempfile.mkdtemp(prefix="power-", dir="/var/run/tree-fucker"))
    env = os.environ.copy()
    env["TF_POWER_ROOT"] = str(root)
    with (output / "fixture.log").open("w") as log:
        child = subprocess.Popen(
            [
                str(args.executable.resolve()),
                "--exact",
                "macos_sleep_wake",
                "--ignored",
                "--nocapture",
            ],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 60
            while not (root / "ready").exists():
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Sleep fixture did not establish live ownership")
                time.sleep(0.1)
            before = {key: kernel_time(f"kern.{key}time") for key in ["sleep", "wake"]}
            subprocess.run(["sudo", "pmset", "relative", "wake", "20"], check=True)
            subprocess.run(["sudo", "pmset", "sleepnow"], check=True)
            deadline = time.monotonic() + 90
            while True:
                after = {
                    key: kernel_time(f"kern.{key}time") for key in ["sleep", "wake"]
                }
                if (
                    after["sleep"] > before["sleep"]
                    and after["wake"] > before["wake"]
                    and after["wake"] > after["sleep"]
                ):
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "Kernel did not record a new system sleep/wake cycle"
                    )
                time.sleep(0.2)
            (root / "woke").write_text("verified kernel sleep and wake timestamps\n")
            if child.wait(timeout=60) != 0 or not (root / "verified").exists():
                raise RuntimeError("Post-wake coordination assertions failed")
            (output / "result.json").write_text(
                json.dumps(
                    {"before": before, "after": after, "status": "passed"}, indent=2
                )
                + "\n"
            )
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            shutil.rmtree(root)
    print("macOS system sleep/wake: live ownership and retained accounting verified")


if __name__ == "__main__":
    main()
