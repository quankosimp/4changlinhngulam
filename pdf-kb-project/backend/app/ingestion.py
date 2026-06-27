from __future__ import annotations

import json
import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from .constants import DocumentStatus, OCR_DISABLED_MESSAGE
from .database import SessionLocal
from .models import Document, DocumentChunk, DocumentChapter
from .openai_service import OpenAIService
from .settings import Settings, get_settings
from .storage import find_stored_document, safe_filename


@dataclass(frozen=True)
class PDFPageText:
    page_number: int
    text: str


@dataclass(frozen=True)
class PDFOutlineItem:
    level: int
    title: str
    page_number: int


@dataclass(frozen=True)
class TextChunk:
    content: str
    token_count: int
    page_start: int | None
    page_end: int | None
    chapter_index: int
    chapter_title: str | None


@dataclass(frozen=True)
class _ChapterDraft:
    index: int
    title: str
    tokens: list[tuple[str, int]]


_MARKDOWN_HEADING_RE = re.compile(r"^\s*#{1,6}\s+(.+)\s*$")
_NUMBERED_CHAPTER_RE = re.compile(
    r"^\s*(chapter|chuong|chng)\s+([0-9]{1,3}|[ivxlcdm]+|[a-z])(?:\s*[:\-–—\.]?\s*(.*))?$",
    re.IGNORECASE,
)

def _strip_marks_for_heading(line: str) -> str:
    return unicodedata.normalize("NFKD", line).encode("ascii", "ignore").decode("ascii")


def _extract_chapter_title(line: str) -> str | None:
    stripped = line.strip()
    if not stripped:
        return None

    markdown = _MARKDOWN_HEADING_RE.match(stripped)
    candidate = markdown.group(1).strip() if markdown else stripped
    match = _NUMBERED_CHAPTER_RE.match(_strip_marks_for_heading(candidate))
    if not match:
        return None

    number = match.group(2).strip()
    suffix_match = re.match(
        r"^\s*.+?\s+([0-9]{1,3}|[ivxlcdm]+|[a-z])\s*[:\-–—\.]?\s*(.*)$",
        candidate,
        re.IGNORECASE,
    )
    suffix = suffix_match.group(2).strip() if suffix_match and suffix_match.group(2) else ""
    prefix = "Chapter" if match.group(1).lower() == "chapter" else "Chương"
    return f"{prefix} {number}: {suffix}" if suffix else f"{prefix} {number}"


def _tokens_for_pages(pages: list[PDFPageText]) -> list[tuple[str, int]]:
    return [(token, page.page_number) for page in pages for token in page.text.split()]


def _outline_chapters(pages: list[PDFPageText], outline: list[PDFOutlineItem]) -> list[_ChapterDraft]:
    if not pages or not outline:
        return []

    top_level = min(item.level for item in outline)
    items = [item for item in outline if item.level == top_level and item.page_number >= pages[0].page_number]
    if not items:
        return []

    by_page = {page.page_number: page for page in pages}
    last_page = pages[-1].page_number
    chapters: list[_ChapterDraft] = []

    if items[0].page_number > pages[0].page_number:
        front_pages = [page for page in pages if pages[0].page_number <= page.page_number < items[0].page_number]
        tokens = _tokens_for_pages(front_pages)
        if tokens:
            chapters.append(_ChapterDraft(index=len(chapters) + 1, title="Front matter", tokens=tokens))

    for index, item in enumerate(items):
        end_page = (items[index + 1].page_number - 1) if index + 1 < len(items) else last_page
        section_pages = [by_page[number] for number in range(item.page_number, end_page + 1) if number in by_page]
        tokens = _tokens_for_pages(section_pages)
        if tokens:
            chapters.append(_ChapterDraft(index=len(chapters) + 1, title=item.title.strip() or f"Section {len(chapters) + 1}", tokens=tokens))

    return chapters


def _split_into_chapters(pages: list[PDFPageText]) -> list[_ChapterDraft]:
    chapters: list[_ChapterDraft] = []
    chapter_index = 1
    chapter_title = "Chương 1"
    current_tokens: list[tuple[str, int]] = []

    for page in pages:
        lines = page.text.splitlines() if page.text else []
        if not lines and page.text:
            lines = [page.text]
        for line in lines:
            detected_title = _extract_chapter_title(line)
            if detected_title is not None:
                if current_tokens:
                    chapters.append(_ChapterDraft(index=chapter_index, title=chapter_title, tokens=current_tokens))
                    chapter_index += 1
                    current_tokens = []
                chapter_title = detected_title

            for token in line.split():
                current_tokens.append((token, page.page_number))

    if current_tokens:
        chapters.append(_ChapterDraft(index=chapter_index, title=chapter_title, tokens=current_tokens))

    if not chapters:
        return [ _ChapterDraft(index=1, title="Chương 1", tokens=[]) ]

    return chapters


def _chunk_chapter(
    tokens: list[tuple[str, int]],
    chapter_index: int,
    chapter_title: str,
    target_tokens: int,
    overlap_tokens: int,
) -> list[TextChunk]:
    if not tokens:
        return []

    chunk_size = max(1, target_tokens)
    stride = max(1, chunk_size - max(0, min(overlap_tokens, chunk_size - 1)))
    chunks: list[TextChunk] = []

    start = 0
    while start < len(tokens):
        window = tokens[start : start + chunk_size]
        words = [word for word, _page in window]
        pages_in_window = [page for _word, page in window]
        chunks.append(
            TextChunk(
                content=" ".join(words),
                token_count=len(words),
                page_start=min(pages_in_window) if pages_in_window else None,
                page_end=max(pages_in_window) if pages_in_window else None,
                chapter_index=chapter_index,
                chapter_title=chapter_title,
            )
        )
        if start + chunk_size >= len(tokens):
            break
        start += stride
    return chunks


def _flatten_tokens(pages: list[PDFPageText]) -> list[tuple[str, int]]:
    return _tokens_for_pages(pages)


def _chunk_chapters(chapters: list[_ChapterDraft], target_tokens: int, overlap_tokens: int) -> list[TextChunk]:
    chunks: list[TextChunk] = []
    for chapter in chapters:
        chunks.extend(
            _chunk_chapter(
                chapter.tokens,
                chapter.index,
                chapter.title,
                target_tokens=target_tokens,
                overlap_tokens=overlap_tokens,
            )
        )
    return chunks


def _candidate_sizes(target_tokens: int) -> list[int]:
    return sorted({max(1, target_tokens), 600, 1100})


def _chunk_score(chunks: list[TextChunk], target_tokens: int, structured: bool) -> float:
    if not chunks:
        return -1.0

    min_tokens = min(100, max(20, target_tokens // 5))
    max_tokens = max(target_tokens, int(target_tokens * 1.25))
    size_compliance = sum(min_tokens <= chunk.token_count <= max_tokens for chunk in chunks) / len(chunks)
    fill = sum(min(chunk.token_count / max(1, target_tokens), 1.0) for chunk in chunks) / len(chunks)
    tiny_penalty = sum(chunk.token_count < 50 for chunk in chunks) / len(chunks)
    fragmentation_penalty = min(len(chunks) / 200, 0.2)
    structure_bonus = 0.25 if structured and len({chunk.chapter_index for chunk in chunks}) > 1 else 0.0
    return (0.6 * size_compliance) + (0.4 * fill) + structure_bonus - (0.5 * tiny_penalty) - fragmentation_penalty


def _adaptive_chunks(
    pages: list[PDFPageText],
    target_tokens: int,
    overlap_tokens: int,
    outline: list[PDFOutlineItem] | None = None,
) -> list[TextChunk]:
    outline_sections = _outline_chapters(pages, outline or [])
    if outline_sections:
        return _chunk_chapters(outline_sections, target_tokens, overlap_tokens)

    chapters = _split_into_chapters(pages)
    document_tokens = _flatten_tokens(pages)
    candidates: list[tuple[float, list[TextChunk]]] = []

    for size in _candidate_sizes(target_tokens):
        document_chunks = _chunk_chapter(document_tokens, 1, "Tài liệu", size, overlap_tokens)
        candidates.append((_chunk_score(document_chunks, size, structured=False), document_chunks))

        chapter_chunks = _chunk_chapters(chapters, size, overlap_tokens)
        candidates.append((_chunk_score(chapter_chunks, size, structured=True), chapter_chunks))

    return max(candidates, key=lambda candidate: candidate[0])[1]


_STOPWORDS = {
    "about", "after", "again", "also", "and", "are", "because", "been", "before", "between", "could", "each",
    "from", "have", "into", "more", "not", "only", "other", "should", "that", "the", "their", "there", "these",
    "this", "through", "with", "would", "your", "bạn", "các", "cho", "của", "được", "khi", "một", "này", "trong",
}
_KNOWN_CONCEPTS = (
    "Prompt Engineering",
    "Large Language Model",
    "Gemini",
    "Vertex AI",
    "Temperature",
    "Top-K",
    "Top-P",
    "Zero-Shot Prompting",
    "One-Shot Prompting",
    "Few-Shot Prompting",
    "System Prompting",
    "Role Prompting",
    "Contextual Prompting",
    "Step-Back Prompting",
    "Chain Of Thought",
    "Self-Consistency",
    "Tree Of Thoughts",
    "ReAct",
    "Automatic Prompt Engineering",
    "Code Prompting",
    "Multimodal Prompting",
    "JSON",
    "Schema",
    "Best Practices",
)


def _sentences(text: str) -> list[str]:
    compact = " ".join(text.split())
    return [sentence.strip() for sentence in re.split(r"(?<=[.!?。])\s+", compact) if len(sentence.split()) >= 8]


def _words(text: str) -> list[str]:
    return [word.lower() for word in re.findall(r"[A-Za-z][A-Za-z\-]{2,}", text) if word.lower() not in _STOPWORDS]


def _trim_sentence(sentence: str, limit: int = 260) -> str:
    compact = " ".join(sentence.split())
    if len(compact) <= limit:
        return compact
    return compact[:limit].rsplit(" ", 1)[0].rstrip(" ,;") + "..."


def _summary_bullets(title: str, chunks: list[TextChunk], subtopics: list[str], limit: int = 4) -> list[str]:
    if subtopics:
        groups = [subtopics[index : index + 5] for index in range(0, min(len(subtopics), 15), 5)]
        labels = ["Bao quát", "Mở rộng với", "Các mục bổ sung"]
        return [f"{labels[index]}: {', '.join(group)}." for index, group in enumerate(groups) if group][:limit]

    body = " ".join(chunk.content for chunk in chunks)
    sentences = _sentences(body)
    if not sentences:
        return [_trim_sentence(chunk.content) for chunk in chunks[:limit] if chunk.content.strip()]

    frequencies: dict[str, int] = defaultdict(int)
    for word in _words(body):
        frequencies[word] += 1
    focus = set(_words(title))

    scored: list[tuple[float, int, str]] = []
    seen: set[str] = set()
    for index, sentence in enumerate(sentences):
        normalized = _strip_marks_for_heading(sentence).lower()[:80]
        if normalized in seen:
            continue
        seen.add(normalized)
        words = set(_words(sentence))
        if not words:
            continue
        score = sum(frequencies[word] for word in words) / len(words)
        score += 3 * len(words & focus)
        scored.append((score, index, sentence))

    picked = sorted(sorted(scored, reverse=True)[:limit], key=lambda item: item[1])
    return [_trim_sentence(sentence) for _score, _index, sentence in picked]


def _concept_links(title: str, chunks: list[TextChunk], subtopics: list[str], limit: int = 8) -> list[str]:
    concepts = [topic for topic in [title.strip(), *subtopics] if topic]
    text = f"{title} " + " ".join(chunk.content for chunk in chunks)
    lowered = text.lower()

    for concept in _KNOWN_CONCEPTS:
        if concept.lower() in lowered and concept not in concepts:
            concepts.append(concept)

    deduped = list(dict.fromkeys(concepts))[:limit]
    return [f"[[{item}]]" for item in deduped]


def _tag_slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", _strip_marks_for_heading(text).lower()).strip("-")
    return slug or "note"


def _build_chapter_markdown(
    chapter_index: int,
    title: str | None,
    chunks: list[TextChunk],
    subtopics: list[str] | None = None,
) -> str:
    first_page = min((chunk.page_start for chunk in chunks if chunk.page_start is not None), default=None)
    last_page = max((chunk.page_end for chunk in chunks if chunk.page_end is not None), default=None)
    heading = title or f"Chương {chapter_index}"
    section_topics = subtopics or []
    links = _concept_links(heading, chunks, section_topics)
    tags = ["pdf-kb", _tag_slug(heading)]
    bullets = _summary_bullets(heading, chunks, section_topics)
    excerpts = [" ".join(chunk.content.split())[:360].rstrip() for chunk in chunks[:2] if chunk.content.strip()]

    lines = [
        "---",
        f"chapter: {chapter_index}",
        f"pages: {first_page or '?'}-{last_page or '?'}",
        "tags: [" + ", ".join(tags) + "]",
        "---",
        "",
        f"# {heading}",
        "",
        f"Nguồn: trang {first_page or '?'}-{last_page or '?'}",
        "",
        "## Tóm tắt",
    ]

    lines.extend(f"- {bullet}" for bullet in bullets)
    if not bullets:
        lines.append("- Không có nội dung đủ để tạo ghi chú.")

    if section_topics:
        lines.extend(["", "## Mục chính"])
        lines.extend(f"- [[{topic}]]" for topic in section_topics[:12])

    if links:
        lines.extend(["", "## Liên kết kiến thức", " ".join(links)])

    if excerpts:
        lines.extend(["", "## Trích đoạn nguồn"])
        lines.extend(f"> {excerpt}" for excerpt in excerpts)

    return "\n".join(lines)


def _outline_subtopics(outline: list[PDFOutlineItem]) -> dict[str, list[str]]:
    if not outline:
        return {}

    top_level = min(item.level for item in outline)
    current_title: str | None = None
    grouped: dict[str, list[str]] = defaultdict(list)
    for item in outline:
        if item.level == top_level:
            current_title = item.title.strip()
            grouped.setdefault(current_title, [])
        elif current_title and item.title.strip():
            grouped[current_title].append(item.title.strip())
    return dict(grouped)


def _build_chapter_notes(
    chunks: list[TextChunk],
    outline: list[PDFOutlineItem] | None = None,
) -> list[tuple[int, str, int | None, int | None, str]]:
    chapter_buckets = defaultdict(list)
    for chunk in chunks:
        chapter_buckets[chunk.chapter_index].append(chunk)

    subtopics_by_title = _outline_subtopics(outline or [])
    notes: list[tuple[int, str, int | None, int | None, str]] = []
    for chapter_index in sorted(chapter_buckets):
        chapter_chunks = sorted(chapter_buckets[chapter_index], key=lambda chunk: chunk.chapter_index)
        if not chapter_chunks:
            continue

        title = chapter_chunks[0].chapter_title or f"Chương {chapter_index}"
        first_page = min((chunk.page_start for chunk in chapter_chunks if chunk.page_start is not None), default=None)
        last_page = max((chunk.page_end for chunk in chapter_chunks if chunk.page_end is not None), default=None)
        markdown = _build_chapter_markdown(chapter_index, title, chapter_chunks, subtopics_by_title.get(title, []))
        notes.append((chapter_index, title, first_page, last_page, markdown))
    return notes


def extract_pdf_pages(path: str | Path) -> list[PDFPageText]:
    import fitz

    pages: list[PDFPageText] = []
    with fitz.open(str(path)) as document:
        for index, page in enumerate(document, start=1):
            pages.append(PDFPageText(page_number=index, text=page.get_text("text") or ""))
    return pages


def extract_pdf_outline(path: str | Path) -> list[PDFOutlineItem]:
    import fitz

    with fitz.open(str(path)) as document:
        return [PDFOutlineItem(level=level, title=title, page_number=page) for level, title, page in document.get_toc(simple=True)]


def chunk_pages(
    pages: list[PDFPageText],
    target_tokens: int = 800,
    overlap_tokens: int = 120,
    outline: list[PDFOutlineItem] | None = None,
) -> list[TextChunk]:
    if not _flatten_tokens(pages):
        return []
    return _adaptive_chunks(pages, target_tokens, overlap_tokens, outline)


def _provider_error_summary(exc: Exception) -> str:
    message = str(exc).replace(get_settings().openai_api_key or "", "[redacted]")
    return message[:1000] or exc.__class__.__name__


def _mark_failed(db: Session, document: Document, message: str) -> None:
    document.status = DocumentStatus.FAILED
    document.error_message = message
    db.add(document)
    db.commit()


def _write_note_files(
    document_id: str,
    notes: list[tuple[int, str, int | None, int | None, str]],
    settings: Settings,
) -> None:
    note_dir = settings.storage_dir / "notes" / document_id
    note_dir.mkdir(parents=True, exist_ok=True)
    for old_note in note_dir.glob("*.md"):
        old_note.unlink()
    for chapter_index, title, _page_start, _page_end, markdown in notes:
        filename = f"{chapter_index:02d}-{safe_filename(title)}.md"
        (note_dir / filename).write_text(markdown, encoding="utf-8")


def run_ingestion_job(
    document_id: str,
    file_path: str | Path | None = None,
    service: OpenAIService | None = None,
    settings: Settings | None = None,
) -> None:
    cfg = settings or get_settings()
    provider = service or OpenAIService(cfg)
    db = SessionLocal()
    try:
        document = db.get(Document, document_id)
        if document is None:
            return
        document.status = DocumentStatus.PROCESSING
        document.error_message = None
        db.add(document)
        db.commit()

        source_path = Path(file_path) if file_path is not None else find_stored_document(document_id, cfg)
        if source_path is None:
            _mark_failed(db, document, "Stored PDF file was not found.")
            return

        pages = extract_pdf_pages(source_path)
        extracted_text = "\n".join(page.text for page in pages).strip()
        if len(extracted_text) < 50:
            _mark_failed(db, document, OCR_DISABLED_MESSAGE)
            return

        outline = extract_pdf_outline(source_path)
        chunks = chunk_pages(pages, cfg.chunk_target_tokens, cfg.chunk_overlap_tokens, outline)
        if not chunks:
            _mark_failed(db, document, OCR_DISABLED_MESSAGE)
            return

        embeddings = provider.embed_texts([chunk.content for chunk in chunks])
        if len(embeddings) != len(chunks):
            raise RuntimeError("Embedding count does not match chunk count.")

        db.query(DocumentChunk).filter(DocumentChunk.document_id == document_id).delete()
        db.query(DocumentChapter).filter(DocumentChapter.document_id == document_id).delete()
        for index, (chunk, embedding) in enumerate(zip(chunks, embeddings, strict=True)):
            db.add(
                DocumentChunk(
                    document_id=document_id,
                    chunk_index=index,
                    page_start=chunk.page_start,
                    page_end=chunk.page_end,
                    content=chunk.content,
                    token_count=chunk.token_count,
                    chapter_index=chunk.chapter_index,
                    chapter_title=chunk.chapter_title,
                    embedding=json.dumps(embedding),
                )
            )
        for chapter_index, title, page_start, page_end, markdown in _build_chapter_notes(chunks, outline):
            db.add(
                DocumentChapter(
                    document_id=document_id,
                    chapter_index=chapter_index,
                    chapter_title=title,
                    page_start=page_start,
                    page_end=page_end,
                    markdown=markdown,
                )
            )
        document.status = DocumentStatus.READY
        document.error_message = None
        db.add(document)
        db.commit()
    except Exception as exc:
        db.rollback()
        document = db.get(Document, document_id)
        if document is not None:
            _mark_failed(db, document, _provider_error_summary(exc))
    finally:
        db.close()
