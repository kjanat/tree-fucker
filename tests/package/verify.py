"""Verify the release archive and run isolated README consumers."""

import argparse
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[2]


def cargo(toolchain, *args, cwd, capture=False):
    command = ["cargo", f"+{toolchain}", *args]
    print("+", " ".join(command), flush=True)
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        timeout=60 if args[0] == "run" else 600,
    ).stdout


def package(allow_dirty):
    output = ROOT / "target/package"
    output.mkdir(parents=True, exist_ok=True)
    dirty = ["--allow-dirty"] if allow_dirty else []
    listing = cargo(
        "nightly", "package", "--list", "--locked", *dirty, cwd=ROOT, capture=True
    )
    (output / "files.txt").write_text(listing)
    cargo("nightly", "package", "--locked", *dirty, cwd=ROOT)
    for features in [[], ["--features", "tokio"]]:
        cargo(
            "nightly", "publish", "--dry-run", "--locked", *features, *dirty, cwd=ROOT
        )
    metadata = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    return output / f"{metadata['name']}-{metadata['version']}.crate"


def consumers(archive, toolchain):
    # Neither repository configuration nor its dev dependencies may influence
    # the two independent downstream dependency resolutions.
    with tempfile.TemporaryDirectory(prefix="tree-fucker-consumers-") as directory:
        root = Path(directory)
        with tarfile.open(archive) as source:
            source.extractall(root, filter="data")
        packages = list(root.glob("*/Cargo.toml"))
        if len(packages) != 1:
            raise RuntimeError("expected one packaged crate")
        crate = packages[0].parent
        metadata = tomllib.loads(packages[0].read_text())["package"]
        for key in [
            "description",
            "license",
            "repository",
            "documentation",
            "rust-version",
        ]:
            if not metadata.get(key):
                raise RuntimeError(f"missing package metadata: {key}")
        for name in ["LICENSE-MIT", "LICENSE-APACHE"]:
            if not (crate / name).is_file():
                raise RuntimeError(f"missing {name}")
        for name in [".cargo", ".github", "reports", "node_modules", "rfc/site"]:
            if (crate / name).exists():
                raise RuntimeError(f"repository-only files packaged: {name}")
        cargo(
            toolchain, "check", "--locked", "--all-targets", "--all-features", cwd=crate
        )
        readme = (crate / "README.md").read_text()
        examples = dict(
            re.findall(
                r"<!-- example: (\w+) -->\n+```rust\n(.*?)\n```", readme, re.DOTALL
            )
        )
        data = root / "filesystem"
        data.mkdir()
        (data / "hello.txt").write_text("hello\n")
        (data / "nested").mkdir()
        (data / "nested/child.txt").write_text("child\n")
        for name in ["scan", "tree"]:
            code = (crate / f"examples/{name}.rs").read_text()
            if examples.get(name, "").strip() != code.strip():
                raise RuntimeError(f"README and examples/{name}.rs differ")
            consumer = root / name
            (consumer / "src").mkdir(parents=True)
            shutil.copyfile(crate / f"examples/{name}.rs", consumer / "src/main.rs")
            dependency = f"tree-fucker = {{ path = {json.dumps(str(crate))}"
            if name == "tree":
                dependency += ', features = ["tokio"]'
            dependency += " }\n"
            if name == "tree":
                dependency += (
                    'tokio = { version = "1", features = ["macros", "rt", "time"] }\n'
                )
            manifest = consumer / "Cargo.toml"
            manifest.write_text(
                f'[package]\nname = "{name}-consumer"\nversion = "0.0.0"\n'
                f'edition = "2024"\nrust-version = "{metadata["rust-version"]}"\n'
                f"\n[dependencies]\n{dependency}\n[workspace]\n"
            )
            # The initial build deliberately has no lockfile: this is normal
            # downstream resolution, independent of the crate's Cargo.lock.
            cargo(toolchain, "build", "--manifest-path", str(manifest), cwd=root)
            resolved = json.loads(
                cargo(
                    toolchain,
                    "metadata",
                    "--format-version",
                    "1",
                    "--locked",
                    "--manifest-path",
                    str(manifest),
                    cwd=root,
                    capture=True,
                )
            )
            if name == "scan" and any(
                p["name"] == "tokio" for p in resolved["packages"]
            ):
                raise RuntimeError("the default consumer unexpectedly depends on Tokio")
            output = cargo(
                toolchain,
                "run",
                "--quiet",
                "--locked",
                "--manifest-path",
                str(manifest),
                cwd=data,
                capture=True,
            )
            if "hello.txt" not in output or "child.txt" not in output:
                raise RuntimeError(
                    f"{name} did not observe the fixture files: {output}"
                )
            print(
                f"{name}: observed both fixture files and exited successfully",
                flush=True,
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", default="stable")
    parser.add_argument(
        "--archive", type=Path, help="reuse an already verified .crate archive"
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="local iteration only; never used in CI",
    )
    args = parser.parse_args()
    archive = args.archive.resolve() if args.archive else package(args.allow_dirty)
    consumers(archive, args.toolchain)


if __name__ == "__main__":
    main()
