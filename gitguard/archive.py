"""Safe ZIP extraction with path-traversal (zip-slip) protection."""

from __future__ import annotations

import stat
import zipfile
from pathlib import Path

from .utils import GitGuardError


def _is_within(base: Path, target: Path) -> bool:
    """True if ``target`` is inside ``base`` (after resolving)."""

    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def safe_extract_zip(zip_path: Path, dest: Path) -> Path:
    """Extract ``zip_path`` into ``dest`` safely.

    Rejects absolute paths and ``..`` traversal (zip-slip), and skips
    symlink entries. Returns the destination directory.
    """

    if not zip_path.exists():
        raise GitGuardError(
            f"ZIP file not found: {zip_path}",
            fixes=["Check the path", "Make sure the file extension is .zip"],
        )

    dest.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(zip_path) as zf:
            bad = zf.testzip()
            if bad is not None:
                raise GitGuardError(
                    f"ZIP archive is corrupt (bad entry: {bad}).",
                    fixes=["Re-download the archive", "Try re-zipping the source"],
                )
            for member in zf.infolist():
                _extract_member(zf, member, dest)
    except zipfile.BadZipFile as exc:
        raise GitGuardError(
            f"Could not read ZIP archive: {zip_path.name}",
            reason=str(exc),
            fixes=["Confirm the file is a valid .zip", "Re-download the archive"],
        ) from exc
    return dest


def _extract_member(zf: zipfile.ZipFile, member: zipfile.ZipInfo, dest: Path) -> None:
    name = member.filename

    # Reject absolute paths and drive letters outright.
    if name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
        raise GitGuardError(
            f"Refusing to extract absolute path from ZIP: {name!r}",
            fixes=["The archive may be malicious; inspect it manually"],
        )

    target = (dest / name).resolve()
    if not _is_within(dest, target):
        raise GitGuardError(
            f"Refusing to extract path-traversal entry from ZIP: {name!r}",
            fixes=["The archive may be malicious; inspect it manually"],
        )

    # Skip symlinks inside the archive (mode high bits indicate a symlink).
    mode = member.external_attr >> 16
    if mode and stat.S_ISLNK(mode):
        return

    if member.is_dir():
        target.mkdir(parents=True, exist_ok=True)
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    with zf.open(member) as src, target.open("wb") as out:
        out.write(src.read())
