from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_url: str
    storage_dir: Path
    openai_api_key: str | None
    openai_base_url: str
    embedding_model: str
    chat_model: str
    tts_model: str
    tts_voice: str
    transcription_model: str
    max_pdf_size_bytes: int
    chunk_target_tokens: int
    chunk_overlap_tokens: int
    audio_url_prefix: str


def _default_storage_dir() -> Path:
    return Path(os.getenv("STORAGE_DIR", "./backend/storage")).resolve()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        database_url=os.getenv("DATABASE_URL", "sqlite:///./backend/data/app.db"),
        storage_dir=_default_storage_dir(),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        openai_base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
        embedding_model=os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small"),
        chat_model=os.getenv("OPENAI_CHAT_MODEL", "gpt-4o-mini"),
        tts_model=os.getenv("OPENAI_TTS_MODEL", "gpt-4o-mini-tts"),
        tts_voice=os.getenv("OPENAI_TTS_VOICE", "alloy"),
        transcription_model=os.getenv("OPENAI_TRANSCRIPTION_MODEL", "gpt-4o-mini-transcribe"),
        max_pdf_size_bytes=int(os.getenv("MAX_PDF_SIZE_BYTES", str(50 * 1024 * 1024))),
        chunk_target_tokens=int(os.getenv("CHUNK_TARGET_TOKENS", "800")),
        chunk_overlap_tokens=int(os.getenv("CHUNK_OVERLAP_TOKENS", "120")),
        audio_url_prefix=os.getenv("AUDIO_URL_PREFIX", "/media/audio"),
    )
