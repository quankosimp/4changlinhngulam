from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .constants import ChatRole, DocumentStatus, INSUFFICIENT_CONTEXT_MESSAGE
from .database import SessionLocal, init_db
from .ingestion import run_ingestion_job
from .models import ChatMessage, ChatSession, Document, DocumentChapter
from .openai_service import OpenAIService
from .retrieval import RetrievedChunk, retrieve_context
from .schemas import ChatRequest, DocumentChapterRead, DocumentRead, DocumentUploadResponse, TranscriptionResponse
from .settings import get_settings
from .storage import ensure_storage_dirs, save_audio_bytes, save_upload_file

logger = logging.getLogger(__name__)
settings = get_settings()
ensure_storage_dirs(settings)

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    ensure_storage_dirs()
    init_db()
    yield


app = FastAPI(title="PDF Knowledge Base API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/media", StaticFiles(directory=settings.storage_dir), name="media")


def _service() -> OpenAIService:
    return getattr(app.state, "openai_service", None) or OpenAIService()


def _sse(event: str, payload: dict[str, object]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _document_read(document: Document) -> DocumentRead:
    return DocumentRead(
        id=document.id,
        filename=document.filename,
        mime_type=document.mime_type,
        size_bytes=document.size_bytes,
        status=document.status,
        error_message=document.error_message,
    )


def _get_or_create_session(db: Session, session_id: str | None) -> ChatSession:
    if session_id is not None:
        session = db.get(ChatSession, session_id)
        if session is None:
            raise ValueError("Chat session was not found.")
        return session
    session = ChatSession()
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def _citation_payload(chunks: list[RetrievedChunk]) -> list[dict[str, object]]:
    seen: set[tuple[str, int | None, int | None]] = set()
    citations: list[dict[str, object]] = []
    for chunk in chunks:
        key = (chunk.document_id, chunk.page_start, chunk.page_end)
        if key in seen:
            continue
        seen.add(key)
        citations.append(
            {
                "document_id": chunk.document_id,
                "filename": chunk.filename,
                "page_start": chunk.page_start,
                "page_end": chunk.page_end,
            }
        )
    return citations


def _build_messages(question: str, chunks: list[RetrievedChunk]) -> list[dict[str, str]]:
    context = "\n\n".join(
        "[Nguồn: "
        f"{chunk.filename}, chương {chunk.chapter_index or '?'} ({chunk.chapter_title or 'Không có tiêu đề'}) - "
        f"trang {chunk.page_start or '?'}-{chunk.page_end or '?'}]\n{chunk.content}"
        for chunk in chunks
    )
    return [
        {
            "role": "system",
            "content": (
                "Bạn là trợ lý hỏi đáp tài liệu. Chỉ trả lời dựa trên ngữ cảnh được cung cấp. "
                f"Nếu ngữ cảnh không đủ, trả lời chính xác: {INSUFFICIENT_CONTEXT_MESSAGE}"
            ),
        },
        {"role": "user", "content": f"Ngữ cảnh:\n{context}\n\nCâu hỏi: {question}"},
    ]


def _store_message(db: Session, session_id: str, role: str, content: str, audio_url: str | None = None) -> ChatMessage:
    message = ChatMessage(session_id=session_id, role=role, content=content, audio_url=audio_url)
    db.add(message)
    db.commit()
    db.refresh(message)
    return message


@app.post("/api/documents", response_model=DocumentUploadResponse)
async def upload_document(background_tasks: BackgroundTasks, file: UploadFile = File(...)) -> DocumentUploadResponse:
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only application/pdf uploads are supported.")

    db = SessionLocal()
    try:
        document = Document(
            filename=file.filename or "document.pdf",
            mime_type=file.content_type,
            size_bytes=0,
            status=DocumentStatus.UPLOADED,
        )
        db.add(document)
        db.commit()
        db.refresh(document)

        try:
            stored = await save_upload_file(file, document.id)
        except ValueError as exc:
            db.delete(document)
            db.commit()
            raise HTTPException(status_code=413, detail=str(exc)) from exc

        document.size_bytes = stored.size_bytes
        db.add(document)
        db.commit()
        background_tasks.add_task(run_ingestion_job, document.id, stored.path)
        return DocumentUploadResponse(document_id=document.id, status=document.status)
    finally:
        db.close()


@app.get("/api/documents", response_model=list[DocumentRead])
def list_documents() -> list[DocumentRead]:
    db = SessionLocal()
    try:
        documents = db.query(Document).order_by(Document.created_at.desc()).all()
        return [_document_read(document) for document in documents]
    finally:
        db.close()


@app.get("/api/documents/{document_id}", response_model=DocumentRead)
def get_document(document_id: str) -> DocumentRead:
    db = SessionLocal()
    try:
        document = db.get(Document, document_id)
        if document is None:
            raise HTTPException(status_code=404, detail="Document not found.")
        return _document_read(document)
    finally:
        db.close()


@app.get("/api/documents/{document_id}/chapters", response_model=list[DocumentChapterRead])
def list_document_chapters(document_id: str) -> list[DocumentChapterRead]:
    db = SessionLocal()
    try:
        document = db.get(Document, document_id)
        if document is None:
            raise HTTPException(status_code=404, detail="Document not found.")

        chapters = (
            db.query(DocumentChapter)
            .filter(DocumentChapter.document_id == document_id)
            .order_by(DocumentChapter.chapter_index.asc(), DocumentChapter.created_at.asc())
            .all()
        )
        return [
            DocumentChapterRead(
                document_id=chapter.document_id,
                chapter_index=chapter.chapter_index,
                chapter_title=chapter.chapter_title,
                page_start=chapter.page_start,
                page_end=chapter.page_end,
                markdown=chapter.markdown,
            )
            for chapter in chapters
        ]
    finally:
        db.close()


@app.post("/api/transcribe", response_model=TranscriptionResponse)
async def transcribe_audio(file: UploadFile = File(...)) -> TranscriptionResponse:
    audio = await file.read()
    if not audio:
        raise HTTPException(status_code=400, detail="Audio file is empty.")
    if len(audio) > 25 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Audio exceeds 25 MB limit.")
    text = _service().transcribe_audio(audio, file.filename or "question.webm")
    return TranscriptionResponse(text=text)


async def _chat_events(payload: ChatRequest) -> AsyncIterator[str]:
    db = SessionLocal()
    try:
        session = _get_or_create_session(db, payload.session_id)
        _store_message(db, session.id, ChatRole.USER, payload.message)

        ready_count = db.query(Document).filter(Document.status == DocumentStatus.READY).count()
        if ready_count == 0:
            yield _sse("error", {"message": "Chưa có tài liệu nào sẵn sàng để hỏi đáp."})
            return

        chunks = retrieve_context(payload.message, limit=6)
        citations = _citation_payload(chunks) if chunks else []
        provider = _service()

        if not chunks:
            answer = INSUFFICIENT_CONTEXT_MESSAGE
            yield _sse("delta", {"text": answer})
            assistant = _store_message(db, session.id, ChatRole.ASSISTANT, answer, None)
            yield _sse(
                "done",
                {"message_id": assistant.id, "audio_url": None, "citations": citations, "session_id": session.id},
            )
            return

        answer_parts: list[str] = []
        async for delta in provider.stream_chat(_build_messages(payload.message, chunks)):
            answer_parts.append(delta)
            yield _sse("delta", {"text": delta})

        answer = "".join(answer_parts).strip() or INSUFFICIENT_CONTEXT_MESSAGE
        audio_url: str | None = None
        assistant = ChatMessage(session_id=session.id, role=ChatRole.ASSISTANT, content=answer, audio_url=None)
        db.add(assistant)
        db.commit()
        db.refresh(assistant)

        if answer != INSUFFICIENT_CONTEXT_MESSAGE:
            try:
                audio = provider.text_to_speech(answer)
                audio_url = save_audio_bytes(audio, assistant.id)
                assistant.audio_url = audio_url
                db.add(assistant)
                db.commit()
            except Exception as exc:
                logger.warning("TTS generation failed for chat message %s: %s", assistant.id, exc)
                audio_url = None

        yield _sse(
            "done",
            {"message_id": assistant.id, "audio_url": audio_url, "citations": citations, "session_id": session.id},
        )
    except ValueError as exc:
        yield _sse("error", {"message": str(exc)})
    except Exception as exc:
        logger.exception("Chat request failed")
        yield _sse("error", {"message": str(exc)})
    finally:
        db.close()


@app.post("/api/chat")
async def chat(payload: ChatRequest) -> StreamingResponse:
    return StreamingResponse(_chat_events(payload), media_type="text/event-stream")
