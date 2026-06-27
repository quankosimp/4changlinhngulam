from __future__ import annotations

import json
import math
from dataclasses import dataclass

from sqlalchemy import text

from .constants import DocumentStatus
from .database import SessionLocal, engine
from .models import Document, DocumentChunk
from .openai_service import OpenAIService


@dataclass(frozen=True)
class RetrievedChunk:
    document_id: str
    filename: str
    page_start: int | None
    page_end: int | None
    content: str
    score: float
    chapter_index: int | None = None
    chapter_title: str | None = None


_embedding_service: OpenAIService | None = None


def set_embedding_service(service: OpenAIService | None) -> None:
    global _embedding_service
    _embedding_service = service


def _embed_query(query: str) -> list[float]:
    service = _embedding_service or OpenAIService()
    return service.embed_texts([query])[0]


def _vector_literal(vector: list[float]) -> str:
    return "[" + ",".join(f"{value:.9f}" for value in vector) + "]"


def _cosine_similarity(left: list[float], right: list[float]) -> float:
    dot = sum(a * b for a, b in zip(left, right, strict=False))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return dot / (left_norm * right_norm)


def _retrieve_sqlite(query_embedding: list[float], limit: int) -> list[RetrievedChunk]:
    db = SessionLocal()
    try:
        rows = (
            db.query(DocumentChunk, Document)
            .join(Document, Document.id == DocumentChunk.document_id)
            .filter(Document.status == DocumentStatus.READY)
            .all()
        )
        scored: list[RetrievedChunk] = []
        for chunk, document in rows:
            embedding = json.loads(chunk.embedding)
            score = _cosine_similarity(query_embedding, embedding)
            scored.append(
                RetrievedChunk(
                    document_id=document.id,
                    filename=document.filename,
                    page_start=chunk.page_start,
                    page_end=chunk.page_end,
                    content=chunk.content,
                    score=score,
                    chapter_index=chunk.chapter_index,
                    chapter_title=chunk.chapter_title,
                )
            )
        scored.sort(key=lambda item: item.score, reverse=True)
        return scored[:limit]
    finally:
        db.close()


def _retrieve_sqlite_by_chapter(query_embedding: list[float], limit: int) -> list[RetrievedChunk]:
    ranked = _retrieve_sqlite(query_embedding, limit * 2)
    return ranked[:limit]


def _retrieve_pgvector(query_embedding: list[float], limit: int) -> list[RetrievedChunk]:
    db = SessionLocal()
    try:
        result = db.execute(
            text(
                """
                SELECT d.id AS document_id,
                       d.filename AS filename,
                       c.page_start AS page_start,
                       c.page_end AS page_end,
                       c.content AS content,
                       c.chapter_index AS chapter_index,
                       c.chapter_title AS chapter_title,
                       1 - (c.embedding <=> CAST(:embedding AS vector)) AS score
                FROM document_chunks c
                JOIN documents d ON d.id = c.document_id
                WHERE d.status = 'ready'
                ORDER BY c.embedding <=> CAST(:embedding AS vector)
                LIMIT :limit
                """
            ),
            {"embedding": _vector_literal(query_embedding), "limit": limit},
        )
        return [
            RetrievedChunk(
                document_id=str(row.document_id),
                filename=row.filename,
                page_start=row.page_start,
                page_end=row.page_end,
                content=row.content,
                score=float(row.score),
                chapter_index=row.chapter_index,
                chapter_title=row.chapter_title,
            )
            for row in result
        ]
    finally:
        db.close()


def retrieve_context(query: str, limit: int = 6) -> list[RetrievedChunk]:
    query_embedding = _embed_query(query)
    bounded_limit = max(1, min(limit, 20))
    if engine.url.get_backend_name().startswith("sqlite"):
        return _retrieve_sqlite_by_chapter(query_embedding, bounded_limit)
    return _retrieve_pgvector(query_embedding, bounded_limit)
