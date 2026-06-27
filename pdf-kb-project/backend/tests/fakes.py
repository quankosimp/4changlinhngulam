from __future__ import annotations

from collections.abc import AsyncIterator


def vector_for(text: str) -> list[float]:
    lowered = text.lower()
    vector = [0.0] * 1536
    if "alpha" in lowered or "pricing" in lowered:
        vector[0] = 1.0
    if "beta" in lowered:
        vector[1] = 1.0
    if not any(vector):
        vector[2] = 1.0
    return vector


class FakeOpenAIService:
    def __init__(self, answer: str = "Câu trả lời từ tài liệu.", fail_tts: bool = False) -> None:
        self.answer = answer
        self.fail_tts = fail_tts
        self.tts_calls = 0

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        return [vector_for(text) for text in texts]

    async def stream_chat(self, messages: list[dict[str, str]]) -> AsyncIterator[str]:
        midpoint = max(1, len(self.answer) // 2)
        yield self.answer[:midpoint]
        yield self.answer[midpoint:]

    def text_to_speech(self, text: str) -> bytes:
        self.tts_calls += 1
        if self.fail_tts:
            raise RuntimeError("synthetic TTS failure")
        return b"fake-mp3-bytes"
