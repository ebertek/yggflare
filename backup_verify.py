"""Safely verify an existing Yggflare backup; no extraction to live data."""

import argparse
import json
import sys
from pathlib import Path

import controller
from backup import restore_test, verify_archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("filename", help="Backup basename under /backup")
    parser.add_argument("--restore-test", action="store_true")
    args = parser.parse_args()
    filename = args.filename
    if Path(filename).name != filename or not filename.startswith("yggflare-"):
        parser.error("Specify a Yggflare archive basename, not a path")
    candidate = controller.BACKUP / filename
    if candidate.is_symlink() or not candidate.is_file():
        parser.error("Archive must be an existing, regular non-symlink file")
    if args.restore_test:
        result = restore_test(candidate, controller.DATA)
        print(json.dumps(result, sort_keys=True))
        print("Isolated restoration rehearsal passed; live files unchanged.")
    else:
        print(json.dumps(verify_archive(candidate), sort_keys=True))
        print("Backup structurally verified; no files were restored.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
