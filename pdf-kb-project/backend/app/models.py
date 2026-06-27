from __future__ import annotations

import uuid

from sqlalchemy import BigInteger, CheckConstraint, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import relationship

from .database import Base


def uuid_str() -> str:
    return str(uuid.uuid4())


class Document(Base):
    __tablename__ = "documents"
    __table_args__ = (CheckConstraint("status IN ('uploaded', 'processing', 'ready', 'failed')", name="ck_documents_status"),)

    id = Column(String(36), primary_key=True, default=uuid_str)
    filename = Column(Text, nullable=False)
    mime_type = Column(Text, nullable=False)
    size_bytes = Column(BigInteger, nullable=False)
    status = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    error_message = Column(Text, nullable=True)

    chunks = relationship("DocumentChunk", back_populates="document", cascade="all, delete-orphan")
    chapter_notes = relationship("DocumentChapter", back_populates="document", cascade="all, delete-orphan")


class DocumentChunk(Base):
    __tablename__ = "document_chunks"
    __table_args__ = (UniqueConstraint("document_id", "chunk_index", name="uq_document_chunks_document_index"),)

    id = Column(String(36), primary_key=True, default=uuid_str)
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    chunk_index = Column(Integer, nullable=False)
    chapter_index = Column(Integer, nullable=False, default=1)
    chapter_title = Column(Text, nullable=True)
    page_start = Column(Integer, nullable=True)
    page_end = Column(Integer, nullable=True)
    content = Column(Text, nullable=False)
    token_count = Column(Integer, nullable=False)
    embedding = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    document = relationship("Document", back_populates="chunks")


class DocumentChapter(Base):
    __tablename__ = "document_chapters"
    __table_args__ = (UniqueConstraint("document_id", "chapter_index", name="uq_document_chapters_document_index"),)

    id = Column(String(36), primary_key=True, default=uuid_str)
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    chapter_index = Column(Integer, nullable=False)
    chapter_title = Column(Text, nullable=False)
    page_start = Column(Integer, nullable=True)
    page_end = Column(Integer, nullable=True)
    markdown = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    document = relationship("Document", back_populates="chapter_notes")


class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id = Column(String(36), primary_key=True, default=uuid_str)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    messages = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan")


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    __table_args__ = (CheckConstraint("role IN ('user', 'assistant')", name="ck_chat_messages_role"),)

    id = Column(String(36), primary_key=True, default=uuid_str)
    session_id = Column(String(36), ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False)
    role = Column(Text, nullable=False)
    content = Column(Text, nullable=False)
    audio_url = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    session = relationship("ChatSession", back_populates="messages")
