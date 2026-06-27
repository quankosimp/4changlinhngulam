from __future__ import annotations

import json

from app.constants import DocumentStatus, OCR_DISABLED_MESSAGE
from app.database import SessionLocal
from app.ingestion import PDFOutlineItem, PDFPageText, chunk_pages, run_ingestion_job
from app.models import Document, DocumentChunk, DocumentChapter

from .fakes import FakeOpenAIService
from .pdf_helpers import make_pdf


def test_ingestion_marks_document_ready_and_stores_chunks(temp_backend):
    pdf_path = make_pdf(
        temp_backend / "alpha.pdf",
        ["Alpha pricing policy explains the yearly subscription and renewal terms in detail." * 4],
    )
    db = SessionLocal()
    document = Document(filename="alpha.pdf", mime_type="application/pdf", size_bytes=pdf_path.stat().st_size, status=DocumentStatus.UPLOADED)
    db.add(document)
    db.commit()
    db.refresh(document)
    document_id = document.id
    db.close()

    run_ingestion_job(document_id, pdf_path, service=FakeOpenAIService())

    db = SessionLocal()
    stored = db.get(Document, document_id)
    chunks = db.query(DocumentChunk).filter(DocumentChunk.document_id == document_id).all()
    assert stored.status == DocumentStatus.READY
    assert stored.error_message is None
    assert chunks
    assert all(chunk.content for chunk in chunks)
    assert all(len(json.loads(chunk.embedding)) == 1536 for chunk in chunks)
    assert chunks[0].page_start == 1
    assert chunks[0].chapter_index == 1
    assert chunks[0].chapter_title is not None
    db.close()


def test_ingestion_detects_markers_and_stores_chapter_notes(temp_backend):
    pdf_path = make_pdf(
        temp_backend / "chaptered.pdf",
        [
            "Chương 1: Giới thiệu\nĐây là nền tảng của hệ thống.\nMục tiêu bài học được giới thiệu rõ.",
            "Chương 2: Bài tập\nBài tập thực hành được mô tả.\nVí dụ và lưu ý.",
        ],
    )
    db = SessionLocal()
    document = Document(filename="chaptered.pdf", mime_type="application/pdf", size_bytes=pdf_path.stat().st_size, status=DocumentStatus.UPLOADED)
    db.add(document)
    db.commit()
    db.refresh(document)
    document_id = document.id
    db.close()

    run_ingestion_job(document_id, pdf_path, service=FakeOpenAIService())

    db = SessionLocal()
    stored = db.get(Document, document_id)
    chunks = db.query(DocumentChunk).filter(DocumentChunk.document_id == document_id).order_by(DocumentChunk.chunk_index).all()
    notes = db.query(DocumentChapter).filter(DocumentChapter.document_id == document_id).order_by(DocumentChapter.chapter_index).all()
    assert stored.status == DocumentStatus.READY
    assert chunks
    assert any(chunk.chapter_index == 1 for chunk in chunks)
    assert any(chunk.chapter_index == 2 for chunk in chunks)
    assert len(notes) >= 2
    assert notes[0].chapter_title == "Chương 1: Giới thiệu"
    assert "Chương 1: Giới thiệu" in notes[0].markdown
    db.close()


def test_outline_drives_chapter_chunks():
    chunks = chunk_pages(
        [
            PDFPageText(page_number=1, text="Cover and table of contents"),
            PDFPageText(page_number=2, text="Intro alpha " * 40),
            PDFPageText(page_number=3, text="Technique beta " * 40),
        ],
        target_tokens=80,
        overlap_tokens=0,
        outline=[PDFOutlineItem(level=1, title="Introduction", page_number=2), PDFOutlineItem(level=1, title="Techniques", page_number=3)],
    )

    assert [chunk.chapter_title for chunk in chunks] == ["Front matter", "Introduction", "Techniques"]
    assert [chunk.page_start for chunk in chunks] == [1, 2, 3]


def test_adaptive_chunking_ignores_code_comments_as_headings():
    chunks = chunk_pages(
        [
            PDFPageText(
                page_number=1,
                text=("# Ask for the folder name\nprint('ok')\n" * 80),
            )
        ],
        target_tokens=80,
        overlap_tokens=0,
    )

    assert chunks
    assert {chunk.chapter_index for chunk in chunks} == {1}
    assert all(chunk.chapter_title == "Tài liệu" for chunk in chunks)


def test_ingestion_fails_empty_pdf_without_ocr(temp_backend):
    pdf_path = make_pdf(temp_backend / "empty.pdf", [""])
    db = SessionLocal()
    document = Document(filename="empty.pdf", mime_type="application/pdf", size_bytes=pdf_path.stat().st_size, status=DocumentStatus.UPLOADED)
    db.add(document)
    db.commit()
    db.refresh(document)
    document_id = document.id
    db.close()

    run_ingestion_job(document_id, pdf_path, service=FakeOpenAIService())

    db = SessionLocal()
    stored = db.get(Document, document_id)
    assert stored.status == DocumentStatus.FAILED
    assert stored.error_message == OCR_DISABLED_MESSAGE
    assert db.query(DocumentChunk).filter(DocumentChunk.document_id == document_id).count() == 0
    db.close()
