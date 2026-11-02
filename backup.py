"""Restricted local snapshots of Yggflare unversioned config and state."""
from datetime import UTC, datetime
from pathlib import Path
import os
import tarfile
import tempfile

RETENTION = 14


def create_snapshot(config: Path, data: Path, destination: Path) -> Path:
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
            with tarfile.open(mode="w:gz", fileobj=fileobj, dereference=False) as archive:
                archive.add(config, arcname="config", recursive=True)
                archive.add(data, arcname="data", recursive=True)
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
