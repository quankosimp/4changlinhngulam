from __future__ import annotations


class DocumentStatus:
    UPLOADED = "uploaded"
    PROCESSING = "processing"
    READY = "ready"
    FAILED = "failed"

    ALL = {UPLOADED, PROCESSING, READY, FAILED}


class ChatRole:
    USER = "user"
    ASSISTANT = "assistant"

    ALL = {USER, ASSISTANT}


OCR_DISABLED_MESSAGE = "PDF has no extractable text; OCR is not enabled in MVP."
INSUFFICIENT_CONTEXT_MESSAGE = "Mình chưa tìm thấy thông tin này trong tài liệu đã tải lên."
