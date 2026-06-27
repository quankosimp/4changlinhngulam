from __future__ import annotations

from pydantic import BaseModel, Field


class DocumentUploadResponse(BaseModel):
    document_id: str
    status: str


class DocumentRead(BaseModel):
    id: str
    filename: str
    mime_type: str
    size_bytes: int
    status: str
    error_message: str | None = None


class DocumentChapterRead(BaseModel):
    document_id: str
    chapter_index: int
    chapter_title: str
    page_start: int | None
    page_end: int | None
    markdown: str


class ChatRequest(BaseModel):
    session_id: str | None = None
    message: str = Field(min_length=1)


class Citation(BaseModel):
    document_id: str
    filename: str
    page_start: int | None
    page_end: int | None


class ChatDoneEvent(BaseModel):
    message_id: str
    audio_url: str | None
    citations: list[Citation]
    session_id: str
