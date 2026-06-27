from __future__ import annotations

import json

from app.constants import DocumentStatus
from app.database import SessionLocal
from app.models import Document, DocumentChunk
from app.retrieval import retrieve_context, set_embedding_service

from .fakes import FakeOpenAIService, vector_for


def test_retrieve_context_returns_best_ready_chunk(temp_backend):
    db = SessionLocal()
    document = Document(filename="handbook.pdf", mime_type="application/pdf", size_bytes=123, status=DocumentStatus.READY)
    db.add(document)
    db.commit()
    db.refresh(document)
    db.add_all(
        [
            DocumentChunk(
                document_id=document.id,
                chunk_index=0,
                page_start=1,
                page_end=1,
                content="Alpha pricing policy is described here.",
                token_count=6,
                chapter_index=1,
                chapter_title="Chương 1: pricing",
                embedding=json.dumps(vector_for("alpha pricing")),
            ),
            DocumentChunk(
                document_id=document.id,
                chunk_index=1,
                page_start=2,
                page_end=2,
                content="Beta onboarding checklist is described here.",
                token_count=6,
                chapter_index=2,
                chapter_title="Chương 2: onboarding",
                embedding=json.dumps(vector_for("beta onboarding")),
            ),
        ]
    )
    db.commit()
    document_id = document.id
    db.close()

    set_embedding_service(FakeOpenAIService())
    try:
        chunks = retrieve_context("What is the alpha pricing policy?", limit=1)
    finally:
        set_embedding_service(None)

    assert len(chunks) == 1
    assert chunks[0].document_id == document_id
    assert chunks[0].filename == "handbook.pdf"
    assert chunks[0].page_start == 1
    assert chunks[0].chapter_index == 1
    assert chunks[0].chapter_title == "Chương 1: pricing"
    assert "Alpha pricing" in chunks[0].content
    assert chunks[0].score > 0.9
