"""Resource-bounded readers for repository security scanners."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator
import tarfile
import zipfile


MAX_ARCHIVE_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_REGULAR_FILE_BYTES = 32 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024


class ArchiveLimitError(ValueError):
    """An input exceeds the scanners' fixed resource budget."""


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    data: bytes | None


def read_bounded(handle: BinaryIO, *, limit: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = handle.read(min(READ_CHUNK_BYTES, limit - total + 1))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise ArchiveLimitError(f"{label} exceeds {limit} bytes")
        chunks.append(chunk)


def read_bounded_file(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_REGULAR_FILE_BYTES:
        raise ArchiveLimitError(
            f"regular file exceeds {MAX_REGULAR_FILE_BYTES} bytes"
        )
    with path.open("rb") as handle:
        return read_bounded(
            handle, limit=MAX_REGULAR_FILE_BYTES, label=str(path)
        )


def _check_archive_size(path: Path) -> int:
    compressed_size = path.stat().st_size
    if compressed_size > MAX_ARCHIVE_COMPRESSED_BYTES:
        raise ArchiveLimitError(
            f"archive exceeds {MAX_ARCHIVE_COMPRESSED_BYTES} compressed bytes"
        )
    return max(1, compressed_size)


def _check_expanded_budget(
    *,
    member_size: int,
    total_size: int,
    compressed_size: int,
) -> None:
    if member_size < 0 or member_size > MAX_ARCHIVE_MEMBER_BYTES:
        raise ArchiveLimitError(
            f"archive member exceeds {MAX_ARCHIVE_MEMBER_BYTES} bytes"
        )
    if total_size > MAX_ARCHIVE_EXPANDED_BYTES:
        raise ArchiveLimitError(
            f"archive exceeds {MAX_ARCHIVE_EXPANDED_BYTES} expanded bytes"
        )
    if total_size > compressed_size * MAX_COMPRESSION_RATIO:
        raise ArchiveLimitError(
            f"archive exceeds {MAX_COMPRESSION_RATIO}:1 compression ratio"
        )


def iter_bounded_archive(path: Path) -> Iterator[ArchiveMember]:
    compressed_size = _check_archive_size(path)
    lower_name = path.name.lower()
    if lower_name.endswith(".zip") or zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise ArchiveLimitError(
                    f"archive exceeds {MAX_ARCHIVE_MEMBERS} members"
                )
            total_size = 0
            for info in infos:
                if info.flag_bits & 0x1:
                    raise ArchiveLimitError("encrypted zip members are not scannable")
                if not info.is_dir():
                    total_size += info.file_size
                    _check_expanded_budget(
                        member_size=info.file_size,
                        total_size=total_size,
                        compressed_size=compressed_size,
                    )
                    if info.file_size > max(1, info.compress_size) * MAX_COMPRESSION_RATIO:
                        raise ArchiveLimitError(
                            f"zip member exceeds {MAX_COMPRESSION_RATIO}:1 compression ratio"
                        )
                    with archive.open(info, "r") as handle:
                        data = read_bounded(
                            handle,
                            limit=MAX_ARCHIVE_MEMBER_BYTES,
                            label=f"{path}!{info.filename}",
                        )
                    if len(data) != info.file_size:
                        raise ArchiveLimitError("zip member size changed while scanning")
                else:
                    data = None
                yield ArchiveMember(info.filename, data)
        return

    with tarfile.open(path, "r:*") as archive:
        member_count = 0
        total_size = 0
        for member in archive:
            member_count += 1
            if member_count > MAX_ARCHIVE_MEMBERS:
                raise ArchiveLimitError(
                    f"archive exceeds {MAX_ARCHIVE_MEMBERS} members"
                )
            if member.isfile():
                total_size += member.size
                _check_expanded_budget(
                    member_size=member.size,
                    total_size=total_size,
                    compressed_size=compressed_size,
                )
                handle = archive.extractfile(member)
                if handle is None:
                    raise ArchiveLimitError("tar member cannot be read")
                with handle:
                    data = read_bounded(
                        handle,
                        limit=MAX_ARCHIVE_MEMBER_BYTES,
                        label=f"{path}!{member.name}",
                    )
                if len(data) != member.size:
                    raise ArchiveLimitError("tar member size changed while scanning")
            else:
                data = None
            yield ArchiveMember(member.name, data)


__all__ = [
    "ArchiveLimitError",
    "ArchiveMember",
    "iter_bounded_archive",
    "read_bounded_file",
]
