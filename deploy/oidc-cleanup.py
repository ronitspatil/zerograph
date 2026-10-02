"""Remove only ownership-verified ephemeral OIDC fixture resources."""

import argparse
import json
import os
import re
import shutil
import stat
from pathlib import Path


def owned(path: Path, directory: bool = False, private: bool = False):
    if path.is_symlink():
        raise ValueError("Symlink fixture resources must not be removed")
    metadata = path.lstat()
    if metadata.st_uid != os.getuid():
        raise ValueError("Fixture resources must belong to the current user")
    if directory != stat.S_ISDIR(metadata.st_mode) or (
        not directory and not stat.S_ISREG(metadata.st_mode)
    ):
        raise ValueError("Unexpected fixture resource type")
    if private and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("Private fixture resources must deny group/other access")


def cleanup(directory: Path, env_file: Path):
    if directory.is_symlink() or env_file.is_symlink():
        raise ValueError("Symlink fixture directory/environment is refused")
    path = directory.resolve()
    if path.parent != Path("/tmp").resolve() or not path.name.startswith(
        "zerograph-oidc-qualification."
    ):
        raise ValueError("Only a dedicated temporary OIDC fixture may be removed")
    owned(path, directory=True, private=True)
    marker_path = path / ".owner.json"
    owned(marker_path, private=True)
    if marker_path.stat().st_size > 4096:
        raise ValueError("Invalid fixture ownership marker")
    try:
        marker = json.loads(marker_path.read_text())
    except (ValueError, OSError) as exc:
        raise ValueError("Invalid fixture ownership marker") from exc
    if (
        marker.get("kind") != "zerograph-oidc-qualification"
        or marker.get("directory") != str(path)
        or marker.get("env_file") != str(env_file.resolve())
        or marker.get("uid") != os.getuid()
        or not re.fullmatch(r"[0-9a-f]{64}", marker.get("nonce", ""))
    ):
        raise ValueError("Fixture ownership marker does not match this operation")
    # Verify BOTH resources and all descendants before any deletion.
    for parent, dirs, files in os.walk(path, followlinks=False):
        for name in dirs:
            owned(Path(parent) / name, directory=True)
        for name in files:
            owned(Path(parent) / name)
    if env_file.exists():
        owned(env_file, private=True)
        if env_file.stat().st_size > 65536:
            raise ValueError("Unexpected fixture environment size")
        values = env_file.read_text().splitlines()
        if (
            values.count(f"ZG_OIDC_FIXTURE_DIR={path}") != 1
            or values.count(f"ZG_OIDC_FIXTURE_OWNER={marker['nonce']}") != 1
        ):
            raise ValueError("Environment file does not belong to this fixture")
    shutil.rmtree(path)
    if env_file.exists():
        env_file.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        cleanup(args.directory, args.env_file)
    except (ValueError, OSError):
        parser.error("Ownership validation refused cleanup; resources were preserved")
    print("Ownership-verified disposable OIDC fixture configuration removed.")


if __name__ == "__main__":
    main()
