from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from .settings import Settings, get_settings


class ProviderError(RuntimeError):
    pass


class OpenAIService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def _headers(self) -> dict[str, str]:
        if not self.settings.openai_api_key:
            raise ProviderError("OPENAI_API_KEY is not configured.")
        return {
            "Authorization": f"Bearer {self.settings.openai_api_key}",
            "Content-Type": "application/json",
        }

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        payload: dict[str, Any] = {"model": self.settings.embedding_model, "input": texts}
        try:
            with httpx.Client(timeout=60) as client:
                response = client.post(
                    f"{self.settings.openai_base_url}/embeddings",
                    headers=self._headers(),
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
        except Exception as exc:  # pragma: no cover - exercised through stubs in tests
            raise ProviderError(str(exc)) from exc
        embeddings = [item["embedding"] for item in sorted(data.get("data", []), key=lambda row: row.get("index", 0))]
        if len(embeddings) != len(texts):
            raise ProviderError("Embedding provider returned an unexpected number of vectors.")
        return embeddings

    async def stream_chat(self, messages: list[dict[str, str]]) -> AsyncIterator[str]:
        payload: dict[str, Any] = {
            "model": self.settings.chat_model,
            "messages": messages,
            "stream": True,
            "temperature": 0.2,
        }
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream(
                    "POST",
                    f"{self.settings.openai_base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        raw = line.removeprefix("data: ").strip()
                        if raw == "[DONE]":
                            break
                        if not raw:
                            continue
                        chunk = json.loads(raw)
                        delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content")
                        if delta:
                            yield delta
        except Exception as exc:  # pragma: no cover - exercised through stubs in tests
            raise ProviderError(str(exc)) from exc

    def text_to_speech(self, text: str) -> bytes:
        payload: dict[str, Any] = {
            "model": self.settings.tts_model,
            "voice": self.settings.tts_voice,
            "input": text,
            "response_format": "mp3",
        }
        try:
            with httpx.Client(timeout=120) as client:
                response = client.post(
                    f"{self.settings.openai_base_url}/audio/speech",
                    headers=self._headers(),
                    json=payload,
                )
                response.raise_for_status()
                return response.content
        except Exception as exc:  # pragma: no cover - exercised through stubs in tests
            raise ProviderError(str(exc)) from exc

    def transcribe_audio(self, audio: bytes, filename: str = "question.webm") -> str:
        if not self.settings.openai_api_key:
            raise ProviderError("OPENAI_API_KEY is not configured.")
        try:
            with httpx.Client(timeout=120) as client:
                response = client.post(
                    f"{self.settings.openai_base_url}/audio/transcriptions",
                    headers={"Authorization": f"Bearer {self.settings.openai_api_key}"},
                    data={"model": self.settings.transcription_model},
                    files={"file": (filename, audio)},
                )
                response.raise_for_status()
                return str(response.json().get("text", "")).strip()
        except Exception as exc:  # pragma: no cover - exercised through stubs in tests
            raise ProviderError(str(exc)) from exc
