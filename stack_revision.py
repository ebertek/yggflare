"""Candidate tracked stack inputs from a trusted local read-only Git checkout.

No fetch, shell, worktree inspection, checkout, remote API, or raw object export.
"""
import os
import posixpath
import re
import subprocess
import time
import tomllib
from pathlib import Path

ROOT = Path("/compose-source")
MANIFEST = "komodo/resources.toml"
MAX_MANIFEST = 1024 * 1024
MAX_STACKS = 64
HEX = re.compile(r"[0-9a-f]{7,64}")
OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
SAFE_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")


def safe_path(value):
    return (
        isinstance(value, str)
        and len(value) <= 512
        and SAFE_PATH.fullmatch(value)
        and all(part not in {".", "..", ".git"} for part in value.split("/"))
    )


class LocalHistory:
    """Read bounded Git objects only; disable hooks, replace refs and lazy fetch."""

    def __init__(self, root):
        self.root = root
        self.deadline = time.monotonic() + 15
        self.cache = {}
        # A .git file could reference an arbitrary location outside the mount.
        if not (root / ".git").is_dir() or (root / ".git").is_symlink():
            raise ValueError("Local Git history unavailable")

    def git(self, *args):
        if args in self.cache:
            return self.cache[args]
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Git evidence deadline exceeded")
        result = subprocess.run(
            [
                "git", "--no-optional-locks", "--no-replace-objects",
                "-c", f"safe.directory={self.root}", "-C", str(self.root), *args,
            ],
            env={
                "PATH": os.defpath, "HOME": "/nonexistent",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
                "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_PROTOCOL_FROM_USER": "0", "GIT_ALLOW_PROTOCOL": "",
            },
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=True, timeout=min(2, remaining),
        ).stdout
        if len(result) > MAX_MANIFEST:
            raise ValueError("Git evidence exceeds bounds")
        self.cache[args] = result
        return result

    def revision(self, value):
        if not isinstance(value, str) or not HEX.fullmatch(value):
            raise ValueError("Invalid revision")
        resolved = self.git("rev-parse", "--verify", value + "^{commit}").decode().strip()
        if not OID.fullmatch(resolved) or not resolved.startswith(value):
            raise ValueError("Unverified commit")
        return resolved

    def object_id(self, revision, path, kind):
        if not OID.fullmatch(revision) or not safe_path(path):
            raise ValueError("Invalid Git object identity")
        oid = self.git("rev-parse", "--verify", f"{revision}:{path}").decode().strip()
        if not OID.fullmatch(oid) or self.git("cat-file", "-t", oid).strip() != kind:
            raise ValueError("Unexpected Git object type")
        return oid

    def manifest(self, revision):
        oid = self.object_id(revision, MANIFEST, b"blob")
        size = int(self.git("cat-file", "-s", oid))
        if not 0 < size <= MAX_MANIFEST:
            raise ValueError("Manifest exceeds bound")
        return tomllib.loads(self.git("cat-file", "blob", oid).decode())

    def stack_inputs(self, revision, row):
        manifest = self.manifest(revision)
        stacks = [
            item for item in manifest.get("stack", [])
            if item.get("name") == row.get("name")
            and item.get("config", {}).get("server") == row.get("server")
        ]
        if len(stacks) != 1:
            raise ValueError("Stack declaration unavailable or ambiguous")
        stack = stacks[0]
        config = stack["config"]
        linked = config.get("linked_repo")
        repos = [item for item in manifest.get("repo", []) if item.get("name") == linked]
        directory = config.get("run_directory")
        if not linked or len(repos) != 1 or not safe_path(directory):
            raise ValueError("Unverified linked repository or run directory")
        # Only tracked content within the stack directory and explicitly named
        # config_files; arbitrary external mounts/includes are not resolved.
        tree = self.object_id(revision, directory, b"tree")
        external = []
        config_files = config.get("config_files", [])
        if not isinstance(config_files, list) or len(config_files) > 32:
            raise ValueError("Invalid declared config files")
        for item in config_files:
            path = item.get("path")
            if not isinstance(path, str) or path.startswith("/"):
                raise ValueError("Invalid declared config path")
            path = posixpath.normpath(posixpath.join(directory, path))
            external.append(self.object_id(revision, path, b"blob"))
        # Compare private values in memory, never return them to API callers.
        return stack, repos[0], tree, external


def enrich_stacks(rows, root=ROOT):
    """Annotate only bounded stack rows; inability to compare is unknown."""
    try:
        history = LocalHistory(root)
    except (OSError, ValueError):
        history = None
    count = 0
    for row in rows:
        if row.get("kind") != "stacks":
            continue
        row["tracked_stack_inputs"] = "unknown"
        if row.get("revision_match") is True:
            row["tracked_stack_inputs"] = "same_reported_revision"
            continue
        if history is None or count >= MAX_STACKS:
            continue
        count += 1
        try:
            deployed = history.revision(row.get("deployed_hash"))
            latest = history.revision(row.get("latest_hash"))
            old = history.stack_inputs(deployed, row)
            new = history.stack_inputs(latest, row)
            row["tracked_stack_inputs"] = (
                "matched" if old == new else "changed"
            )
        except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
            continue
