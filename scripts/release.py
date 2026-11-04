"""Validate a Beepboop release against the checkout and publication services."""

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "kjanat/tree-fucker"
CRATE = "tree-fucker"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def gh(path, optional=False):
    result = subprocess.run(
        ["gh", "api", path], capture_output=True, text=True, check=False, timeout=60
    )
    if optional and result.returncode and "(HTTP 404)" in result.stderr:
        return None
    require(result.returncode == 0, f"GitHub query failed for {path}: {result.stderr}")
    return json.loads(result.stdout)


def validate_context(context, package, head, repository, repository_id):
    require(context["repository"] == repository == REPOSITORY, "Repository mismatch")
    require(str(context["repositoryId"]) == repository_id, "Repository ID mismatch")
    require(context["operation"] == "promote", "Expected an approved promotion")
    require(context["stream"] == "main", "Unexpected release stream")
    require(context["sourceSha"] == head, "Checkout differs from the approved commit")
    require(package["name"] == CRATE, "Unexpected crate")
    require(
        context["version"] == package["version"],
        "Manifest version differs from approval",
    )
    require(
        re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", context["version"]),
        "Expected a release version without build metadata",
    )


def context_from_checkout():
    context = json.loads(os.environ["RELEASE_CONTEXT"])
    sha = context["sourceSha"]
    require(re.fullmatch(r"[a-f0-9]{40}", sha), "Invalid source commit")
    manifest = subprocess.check_output(
        ["git", "show", f"{sha}:Cargo.toml"], cwd=ROOT, text=True, timeout=30
    )
    package = tomllib.loads(manifest)["package"]
    validate_context(
        context,
        package,
        sha,
        os.environ["GITHUB_REPOSITORY"],
        os.environ["GITHUB_REPOSITORY_ID"],
    )
    return context


def validate_run(runs, sha, workflow):
    candidates = [
        run
        for run in runs
        if run["head_sha"] == sha
        and run["head_branch"] == "master"
        and run["event"] == "push"
    ]
    require(candidates, f"No master push run for {workflow} at {sha}")
    latest = max(candidates, key=lambda run: (run["id"], run["run_attempt"]))
    require(
        latest["status"] == "completed" and latest["conclusion"] == "success",
        f"{workflow} must succeed on the approved commit: {latest['html_url']}",
    )


def check(context):
    sha = context["sourceSha"]
    commit = gh(f"repos/{REPOSITORY}/commits/{sha}")
    require(commit["sha"] == sha, "Commit identity mismatch")
    verification = commit["commit"]["verification"]
    require(
        verification["verified"] is True, "Release commit has no verified signature"
    )
    for workflow in ["ci.yml", "coordination-acceptance.yml"]:
        result = gh(
            f"repos/{REPOSITORY}/actions/workflows/{workflow}/runs"
            f"?head_sha={sha}&branch=master&event=push&per_page=100"
        )
        validate_run(result["workflow_runs"], sha, workflow)


def archive_digest(archive, context):
    prefix = f"{CRATE}-{context['version']}"
    with tarfile.open(archive) as source:
        with source.extractfile(f"{prefix}/.cargo_vcs_info.json") as file:
            vcs = json.load(file)
        with source.extractfile(f"{prefix}/Cargo.toml") as file:
            package = tomllib.loads(file.read().decode())["package"]
    require(vcs["git"]["sha1"] == context["sourceSha"], "Archive commit mismatch")
    require(not vcs["git"].get("dirty", False), "Archive contains uncommitted changes")
    require(
        package["name"] == CRATE and package["version"] == context["version"],
        "Archive version mismatch",
    )
    with archive.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def publication_metadata(archive, context):
    prefix = f"{CRATE}-{context['version']}"
    with tarfile.open(archive) as source:

        def read(name):
            member = source.getmember(f"{prefix}/{name}")
            require(member.isfile(), "Package metadata must be a regular file")
            with source.extractfile(member) as file:
                return file.read().decode()

        manifest = tomllib.loads(read("Cargo.toml"))
        package = manifest["package"]
        readme = package.get("readme")
        metadata = {
            "name": package["name"],
            "vers": package["version"],
            "deps": [],
            "features": manifest.get("features", {}),
            "authors": package.get("authors", []),
            "keywords": package.get("keywords", []),
            "categories": package.get("categories", []),
            "readme": read(readme) if readme else None,
            "readme_file": readme or None,
        }
        for key in [
            "description",
            "documentation",
            "homepage",
            "license",
            "license-file",
            "repository",
            "links",
            "rust-version",
        ]:
            metadata[key.replace("-", "_")] = package.get(key)
    tables = [(None, manifest), *manifest.get("target", {}).items()]
    for target, table in tables:
        for section, kind in [
            ("dependencies", "normal"),
            ("dev-dependencies", "dev"),
            ("build-dependencies", "build"),
        ]:
            for name, dependency in table.get(section, {}).items():
                require(
                    isinstance(dependency, dict) and "version" in dependency,
                    "Expected Cargo's normalized dependency metadata",
                )
                require(
                    not any(key in dependency for key in ["path", "git", "registry"]),
                    "Published dependencies must use registry versions",
                )
                metadata["deps"].append({
                    "name": dependency.get("package", name),
                    "version_req": dependency["version"],
                    "features": dependency.get("features", []),
                    "optional": dependency.get("optional", False),
                    "default_features": dependency.get("default-features", True),
                    "target": target,
                    "kind": kind,
                    "registry": dependency.get("registry-index"),
                    "explicit_name_in_toml": name if "package" in dependency else None,
                })
    return metadata


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "Redirect refused", headers, fp
        )


def publish_archive(archive, context, token):
    require(token, "Crates.io token is missing")
    archive_digest(archive, context)
    metadata = json.dumps(publication_metadata(archive, context)).encode()
    crate = archive.read_bytes()
    # Cargo's registry protocol sends length-prefixed metadata and archive bytes.
    body = struct.pack("<I", len(metadata)) + metadata
    body += struct.pack("<I", len(crate)) + crate
    request = urllib.request.Request(
        "https://crates.io/api/v1/crates/new",
        data=body,
        method="PUT",
        headers={
            "Authorization": token,
            "Content-Type": "application/octet-stream",
            "Accept": "application/json",
            "User-Agent": f"{CRATE}-release (https://github.com/{REPOSITORY})",
        },
    )
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=60) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        error.close()
        raise RuntimeError(f"Crates.io upload failed (HTTP {error.code})") from None
    require(not result.get("errors"), "Crates.io rejected the archive")
    for category, warnings in result.get("warnings", {}).items():
        require(not warnings, f"Crates.io reported {category}; inspect the publication")


def registry_version(version):
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{CRATE}/{version}",
        headers={"User-Agent": f"{CRATE}-release (https://github.com/{REPOSITORY})"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)["version"]
    except urllib.error.HTTPError as error:
        error.close()
        if error.code == 404:
            return None
        raise


def validate_registry(entry, version, digest):
    require(entry is not None, "Published crate version is not visible in the registry")
    require(
        entry["crate"] == CRATE
        and entry["num"] == version
        and entry["yanked"] is False
        and entry["checksum"] == digest,
        "Existing registry publication differs from the verified archive",
    )


def version_tag(context, required=False):
    tag = f"v{context['version']}"
    ref = gh(f"repos/{REPOSITORY}/git/ref/tags/{tag}", optional=not required)
    if ref is None:
        return
    target = ref["object"]
    require(target["type"] == "tag", "Release tag must be annotated")
    target = gh(f"repos/{REPOSITORY}/git/tags/{target['sha']}")["object"]
    require(
        target["type"] == "commit" and target["sha"] == context["sourceSha"],
        "Release tag points to another commit",
    )


def github_release(context):
    tag = f"v{context['version']}"
    release = gh(f"repos/{REPOSITORY}/releases/tags/{tag}", optional=True)
    if release is None:
        return None
    require(
        release["tag_name"] == tag
        and release["draft"] is False
        and release["prerelease"] == ("-" in context["version"]),
        "Existing GitHub release does not match the candidate",
    )
    version_tag(context, required=True)
    return release


def output(key, value):
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as file:
        file.write(f"{key}={value}\n")


def report(manager, name, version, digest=None):
    publication = {
        "id": f"{manager}:{name}",
        "manager": manager,
        "name": name,
        "version": version,
        "outcome": "succeeded",
        "required": True,
    }
    if digest:
        publication["digest"] = digest
    output("publications", json.dumps([publication], separators=(",", ":")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=["check", "candidate", "publish", "crate-report", "github-report"],
    )
    command = parser.parse_args().command
    # Keep the publishing credential out of all child-process environments.
    token = os.environ.pop("CARGO_REGISTRY_TOKEN", None)
    context = context_from_checkout()
    version = context["version"]
    archive = ROOT / f"target/package/{CRATE}-{version}.crate"
    if command == "check":
        check(context)
    elif command == "publish":
        publish_archive(archive, context, token)
    elif command in ["candidate", "crate-report"]:
        digest = archive_digest(archive, context)
        entry = registry_version(version)
        if entry is not None or command == "crate-report":
            validate_registry(entry, version, digest)
        if command == "candidate":
            version_tag(context)
            output("publish", str(entry is None).lower())
            output("github-release", str(github_release(context) is not None).lower())
            output("tag", f"v{version}")
            output("prerelease", str("-" in version).lower())
        else:
            report("cargo", CRATE, version, digest)
    else:
        require(github_release(context) is not None, "GitHub release is missing")
        report("github-release", REPOSITORY, f"v{version}")


if __name__ == "__main__":
    main()
