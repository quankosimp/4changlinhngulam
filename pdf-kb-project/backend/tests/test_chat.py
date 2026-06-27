from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.constants import DocumentStatus, INSUFFICIENT_CONTEXT_MESSAGE
from app.database import SessionLocal
from app.main import app
from app.models import ChatMessage, Document, DocumentChapter
from app.retrieval import RetrievedChunk

from .fakes import FakeOpenAIService


def _events(response_text: str) -> list[tuple[str, dict]]:
    events: list[tuple[str, dict]] = []
    for block in response_text.strip().split("\n\n"):
        event_name = "message"
        data = None
        for line in block.splitlines():
            if line.startswith("event: "):
                event_name = line.removeprefix("event: ")
            elif line.startswith("data: "):
                data = json.loads(line.removeprefix("data: "))
        if data is not None:
            events.append((event_name, data))
    return events


def _ready_document() -> str:
    db = SessionLocal()
    document = Document(filename="alpha.pdf", mime_type="application/pdf", size_bytes=100, status=DocumentStatus.READY)
    db.add(document)
    db.commit()
    db.refresh(document)
    document_id = document.id
    db.close()
    return document_id


def test_chat_requires_ready_documents(temp_backend):
    db = SessionLocal()
    document = Document(filename="draft.pdf", mime_type="application/pdf", size_bytes=80, status=DocumentStatus.UPLOADED)
    db.add(document)
    db.commit()
    db.close()

    app.state.openai_service = FakeOpenAIService()
    client = TestClient(app)
    response = client.post("/api/chat", json={"session_id": None, "message": "Giá bao nhiêu?"})

    assert response.status_code == 200
    events = _events(response.text)
    assert events == [("error", {"message": "Chưa có tài liệu nào sẵn sàng để hỏi đáp."})]
    del app.state.openai_service


def test_chat_insufficient_context_streams_grounded_fallback(monkeypatch, temp_backend):
    _ready_document()
    monkeypatch.setattr("app.main.retrieve_context", lambda query, limit=6: [])
    app.state.openai_service = FakeOpenAIService()
    client = TestClient(app)

    response = client.post("/api/chat", json={"session_id": None, "message": "Không liên quan"})

    assert response.status_code == 200
    events = _events(response.text)
    assert events[0] == ("delta", {"text": INSUFFICIENT_CONTEXT_MESSAGE})
    assert events[-1][0] == "done"
    assert events[-1][1]["audio_url"] is None
    assert events[-1][1]["citations"] == []
    assert events[-1][1]["session_id"]
    del app.state.openai_service


def test_chat_tts_failure_keeps_text_answer_and_null_audio(monkeypatch, temp_backend):
    document_id = _ready_document()
    monkeypatch.setattr(
        "app.main.retrieve_context",
        lambda query, limit=6: [
            RetrievedChunk(
                document_id=document_id,
                filename="alpha.pdf",
                page_start=1,
                page_end=1,
                content="Alpha pricing is annual.",
                score=0.99,
            )
        ],
    )
    app.state.openai_service = FakeOpenAIService(answer="Alpha pricing is annual.", fail_tts=True)
    client = TestClient(app)

    response = client.post("/api/chat", json={"session_id": None, "message": "Alpha pricing?"})

    assert response.status_code == 200
    events = _events(response.text)
    deltas = [payload["text"] for event, payload in events if event == "delta"]
    assert "".join(deltas) == "Alpha pricing is annual."
    done = events[-1]
    assert done[0] == "done"
    assert done[1]["audio_url"] is None
    assert done[1]["citations"] == [
        {"document_id": document_id, "filename": "alpha.pdf", "page_start": 1, "page_end": 1}
    ]

    db = SessionLocal()
    assistant = db.query(ChatMessage).filter(ChatMessage.role == "assistant").one()
    assert assistant.content == "Alpha pricing is annual."
    assert assistant.audio_url is None
    db.close()
    del app.state.openai_service


def test_list_document_chapters_returns_markdown(temp_backend):
    db = SessionLocal()
    document = Document(filename="chaptered.pdf", mime_type="application/pdf", size_bytes=100, status=DocumentStatus.READY)
    db.add(document)
    db.commit()
    db.refresh(document)
    db.add(
        DocumentChapter(
            document_id=document.id,
            chapter_index=1,
            chapter_title="Chương 1: Giới thiệu",
            page_start=1,
            page_end=1,
            markdown="# Chương 1: Giới thiệu\n\n- Tóm tắt",
        )
    )
    db.commit()
    db.close()

    client = TestClient(app)
    response = client.get(f"/api/documents/{document.id}/chapters")

    assert response.status_code == 200
    payload = response.json()
    assert payload == [
        {
            "document_id": document.id,
            "chapter_index": 1,
            "chapter_title": "Chương 1: Giới thiệu",
            "page_start": 1,
            "page_end": 1,
            "markdown": "# Chương 1: Giới thiệu\n\n- Tóm tắt",
        }
    ]
