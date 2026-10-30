# /// script
# dependencies = ["psutil"]
# ///
"""Sample aggregate native resources; run separately from latency measurements.

Usage: uv run benchmarks/native_resources.py OUTPUT.json BINARY [ARGS...]
Requires envctl on PATH. No process inspection is persisted before redaction.
"""

import argparse
import ctypes
import json
import subprocess
import sys
import time
from pathlib import Path

import psutil

from resources import redacted


def windows_regions(pid: int) -> list[dict[str, int]]:
    """Read address-space extents, including private and reserved regions."""
    from ctypes import wintypes

    class Region(ctypes.Structure):
        _fields_ = [
            ("base", ctypes.c_void_p),
            ("allocation_base", ctypes.c_void_p),
            ("allocation_protect", wintypes.DWORD),
            ("partition", wintypes.WORD),
            ("size", ctypes.c_size_t),
            ("state", wintypes.DWORD),
            ("protect", wintypes.DWORD),
            ("kind", wintypes.DWORD),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(Region),
        ctypes.c_size_t,
    ]
    kernel.VirtualQueryEx.restype = ctypes.c_size_t
    handle = kernel.OpenProcess(0x0400, False, pid)  # PROCESS_QUERY_INFORMATION
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    regions = []
    try:
        address = 0
        while True:
            region = Region()
            size = kernel.VirtualQueryEx(
                handle, address, ctypes.byref(region), ctypes.sizeof(region)
            )
            if not size:
                error = ctypes.get_last_error()
                if error == 87 and address:  # end of the application address space
                    break
                raise ctypes.WinError(error)
            if size != ctypes.sizeof(region) or region.size == 0:
                raise ValueError("Invalid MEMORY_BASIC_INFORMATION")
            regions.append({"bytes": region.size, "state": region.state})
            address = (region.base or 0) + region.size
    finally:
        kernel.CloseHandle(handle)
    return regions


def exited(process: psutil.Process) -> bool:
    """Boundedly verify exit using the identity captured before inspection."""
    for attempt in range(10):
        try:
            running = json.loads(redacted(json.dumps(process.is_running())))
            if not running:
                return True
            state = json.loads(redacted(json.dumps(process.status())))
        except psutil.NoSuchProcess:
            return True
        if state in (psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD):
            return True
        if attempt < 9:
            time.sleep(0.01)
    return False


def inspect(process: psutil.Process) -> dict:
    # Retain the Process identity across reads; is_running rejects PID reuse.
    raw = {"created": process.create_time(), "pid": process.pid}
    try:
        if hasattr(process, "memory_footprint"):
            raw["memory"] = (
                process.memory_info()._asdict() | process.memory_footprint()._asdict()
            )
        else:
            raw["memory"] = process.memory_full_info()._asdict()
    except RuntimeError as error:
        # macOS can lose the task's address space during USS enumeration.
        # Discard the whole sample only after confirming this identity exited.
        if (
            sys.platform != "darwin"
            or str(error) != "mach_vm_region(VM_REGION_TOP_INFO) syscall failed"
            or not exited(process)
        ):
            raise
        raise psutil.NoSuchProcess(process.pid) from error
    raw["handles"] = (
        process.num_handles() if sys.platform == "win32" else process.num_fds()
    )
    if sys.platform == "win32":
        try:
            raw["regions"] = windows_regions(process.pid)
        except PermissionError as error:
            # VirtualQueryEx can lose access when the process exits between
            # regions. Use the same bounded exit verification as psutil reads.
            raise psutil.AccessDenied(process.pid) from error
    raw["same_identity"] = process.is_running()
    # Redact before selecting fields, aggregating, logging, or persisting.
    return json.loads(redacted(json.dumps(raw)))


def sample(root: psutil.Process) -> dict[str, int]:
    descendants = json.loads(
        redacted(
            json.dumps([
                {"pid": child.pid, "created": child.create_time()}
                for child in root.children(recursive=True)
            ])
        )
    )
    processes = [root]
    for child in descendants:
        process = psutil.Process(child["pid"])
        created = json.loads(redacted(json.dumps(process.create_time())))
        if created != child["created"]:
            raise psutil.NoSuchProcess(child["pid"])
        processes.append(process)
    totals = dict(processes=0, private_bytes=0, rss_bytes=0, virtual_bytes=0, handles=0)
    for process in processes:
        data = inspect(process)
        if not data["same_identity"]:
            raise psutil.NoSuchProcess(data["pid"])
        memory = data["memory"]
        totals["processes"] += 1
        totals["private_bytes"] += memory["uss"]
        totals["rss_bytes"] += memory["rss"]
        totals["handles"] += data["handles"]
        totals["virtual_bytes"] += (
            sum(
                region["bytes"]
                for region in data["regions"]
                if region["state"] in (0x1000, 0x2000)
            )
            if sys.platform == "win32"
            else memory["vms"]
        )
    return totals


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--minimum-processes", type=int, default=2)
    parser.add_argument("output", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command or args.minimum_processes < 1:
        parser.error("provide a command and a positive minimum process count")
    redacted("")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    samples = []
    started = time.monotonic()
    with args.output.with_suffix(".stdout").open("w") as log:
        child = subprocess.Popen(
            args.command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        sanitizer = subprocess.Popen(
            ["envctl", "redact"], stdin=child.stdout, stdout=log
        )
        assert child.stdout is not None
        child.stdout.close()
        root = psutil.Process(child.pid)
        try:
            while child.poll() is None:
                if time.monotonic() - started > 300:
                    raise TimeoutError("Resource workload exceeded five minutes")
                try:
                    values = sample(root)
                    if values["processes"] >= args.minimum_processes:
                        samples.append(values)
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    # A cohort can exit during a sample. Never accept a partial
                    # cohort or silently replace denied measurements with zero.
                    pass
                except psutil.AccessDenied as error:
                    # Linux denies fd access during the live-to-zombie race.
                    # Discard that sample only after verifying the process
                    # actually exited; a live permission failure is an error.
                    for _ in range(10):
                        try:
                            state = json.loads(
                                redacted(json.dumps(psutil.Process(error.pid).status()))
                            )
                        except psutil.NoSuchProcess:
                            state = psutil.STATUS_ZOMBIE
                        if state in (psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD):
                            break
                        time.sleep(0.01)
                    else:
                        raise
                time.sleep(0.01)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
            sanitizer_code = sanitizer.wait(timeout=30)
    if child.returncode or sanitizer_code:
        raise RuntimeError(
            f"Workload exit {child.returncode}; redactor exit {sanitizer_code}"
        )
    if not samples:
        raise RuntimeError("No complete cohort sampled; increase workload duration")
    report = {
        "platform": sys.platform,
        "command": args.command,
        "samples": samples,
        "peak_aggregate": {key: max(row[key] for row in samples) for key in samples[0]},
        "minimum_processes": args.minimum_processes,
        "scope": "benchmark controller and live descendants",
        "private_bytes": "sum of unique resident bytes (USS)",
        "rss_bytes": "sum of working sets; shared pages count once per process",
        "virtual_bytes": "address-space extents including reservations; not physical memory",
        "handles": "Windows kernel handles; Unix open file descriptors",
        "sample_interval": "10 ms sleep plus native inspection and redaction",
    }
    args.output.write_text(redacted(json.dumps(report, indent=2)) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
