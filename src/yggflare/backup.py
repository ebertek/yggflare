"""Restricted local snapshots of Yggflare unversioned config and state."""

import os
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

RETENTION = 14


def create_snapshot(
    config: Path, data: Path, destination: Path, secrets: Path | None = None
) -> Path:
    """Atomically create a plaintext archive. Never follow symlinks."""
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not config.is_dir() or not data.is_dir():
        raise FileNotFoundError("Config and data directories must exist for backup")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = destination / f"yggflare-{stamp}.tar.gz"
    handle, temporary = tempfile.mkstemp(prefix=".yggflare-", dir=destination)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "wb") as fileobj:
            with tarfile.open(
                mode="w:gz", fileobj=fileobj, dereference=False
            ) as archive:
                archive.add(config, arcname="config", recursive=True)
                archive.add(data, arcname="data", recursive=True)
                if secrets is not None:
                    if not secrets.is_dir():
                        raise FileNotFoundError(
                            "Secrets directory unavailable for backup"
                        )
                    archive.add(secrets, arcname="secrets", recursive=True)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target


def prune_snapshots(destination: Path, keep: int = RETENTION) -> None:
    """Remove only older, explicitly named Yggflare backup files."""
    archives = sorted(destination.glob("yggflare-????????T??????Z.tar.gz"))
    for archive in archives[:-keep]:
        if archive.is_file() and not archive.is_symlink():
            archive.unlink()


def verify_archive(archive_path: Path) -> dict:
    """Validate archive members and contents without extracting onto live paths."""
    present = set()
    count = 0
    with tarfile.open(archive_path, "r:gz") as source:
        for member in source:
            path = Path(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or path.parts[0] not in {"config", "data", "secrets"}
                or not (member.isfile() or member.isdir())
                or member.name in present
            ):
                raise ValueError("Unsafe or duplicate backup archive member")
            present.add(member.name)
            count += 1
            if member.isfile():
                stream = source.extractfile(member)
                if stream is None:
                    raise ValueError("Cannot read backup member")
                while stream.read(65536):
                    pass
    if not {"config", "data"}.issubset(present):
        raise ValueError("Backup must include config and data directories")
    return {"members": count, "has_secrets": "secrets" in present}


MAX_RESTORE_BYTES = 256 * 1024 * 1024
MAX_RESTORE_MEMBERS = 10000


def restore_test(archive_path: Path, scratch: Path) -> dict:
    """Rehearse extraction into a private temporary directory, never live mounts.

    Validate the whole archive before writing, then write regular files only
    with restrictive permissions. Temporary content is removed automatically.
    """
    import json  # pylint: disable=import-outside-toplevel

    verify_archive(archive_path)
    scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="yggflare-restore-", dir=scratch) as temp:
        target = Path(temp)
        members = 0
        total = 0
        with tarfile.open(archive_path, "r:gz") as source:
            for member in source:
                parts = Path(member.name).parts
                if (
                    not parts
                    or parts[0] not in {"config", "data", "secrets"}
                    or Path(member.name).is_absolute()
                    or ".." in parts
                    or not (member.isdir() or member.isfile())
                ):
                    raise ValueError("Unsafe restoration archive member")
                members += 1
                total += member.size if member.isfile() else 0
                if members > MAX_RESTORE_MEMBERS or total > MAX_RESTORE_BYTES:
                    raise ValueError("Restoration exceeds safe size limit")
                dest = target.joinpath(*parts)
                if member.isdir():
                    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                stream = source.extractfile(member)
                if stream is None:
                    raise ValueError("Archive file member cannot be opened")
                with dest.open("xb") as output:
                    os.chmod(dest, 0o600)
                    remaining = member.size
                    while remaining:
                        block = stream.read(min(65536, remaining))
                        if not block:
                            raise ValueError("Archive file member truncated")
                        output.write(block)
                        remaining -= len(block)
        for name in ("config", "data"):
            if not (target / name).is_dir():
                raise ValueError(f"Restored {name} directory missing")
        inventory = target / "config" / "static-hosts.json"
        if not inventory.is_file():
            raise ValueError("Restored static-hosts.json missing")
        data = json.loads(inventory.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != 1:
            raise ValueError("Restored static-hosts.json schema invalid")
        for relative in (
            "data/managed-hosts.json",
            "data/network-inventory/state.json",
        ):
            candidate = target / relative
            if candidate.is_file():
                json.loads(candidate.read_text(encoding="utf-8"))
        return {
            "members": members,
            "bytes": total,
            "has_secrets": (target / "secrets").is_dir(),
            "inventory_hosts": len(data.get("hosts", [])),
        }
