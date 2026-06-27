from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from fastapi import UploadFile

from .settings import Settings, get_settings

_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class StoredFile:
    path: Path
    size_bytes: int


def ensure_storage_dirs(settings: Settings | None = None) -> None:
    cfg = settings or get_settings()
    (cfg.storage_dir / "documents").mkdir(parents=True, exist_ok=True)
    (cfg.storage_dir / "audio").mkdir(parents=True, exist_ok=True)


def safe_filename(filename: str) -> str:
    name = Path(filename or "document.pdf").name
    cleaned = _FILENAME_SAFE_RE.sub("_", name).strip("._")
    return cleaned or "document.pdf"


async def save_upload_file(upload: UploadFile, document_id: str, settings: Settings | None = None) -> StoredFile:
    cfg = settings or get_settings()
    ensure_storage_dirs(cfg)
    filename = safe_filename(upload.filename or "document.pdf")
    destination = cfg.storage_dir / "documents" / f"{document_id}_{filename}"
    size = 0
    try:
        with destination.open("wb") as handle:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > cfg.max_pdf_size_bytes:
                    raise ValueError("PDF exceeds 50 MB limit.")
                handle.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await upload.seek(0)
    return StoredFile(path=destination, size_bytes=size)


def save_audio_bytes(audio: bytes, message_id: str, extension: str = ".mp3", settings: Settings | None = None) -> str:
    cfg = settings or get_settings()
    ensure_storage_dirs(cfg)
    suffix = extension if extension.startswith(".") else f".{extension}"
    filename = f"{message_id}{suffix}"
    path = cfg.storage_dir / "audio" / filename
    path.write_bytes(audio)
    return f"{cfg.audio_url_prefix.rstrip('/')}/{filename}"


def find_stored_document(document_id: str, settings: Settings | None = None) -> Path | None:
    cfg = settings or get_settings()
    document_dir = cfg.storage_dir / "documents"
    if not document_dir.exists():
        return None
    matches = sorted(document_dir.glob(f"{document_id}_*"))
    return matches[0] if matches else None
