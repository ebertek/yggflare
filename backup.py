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
