"use client";

type StreamEventName = "delta" | "done" | "error" | "message";

export type DocumentRead = {
  id: string;
  filename: string;
  mime_type: string;
  size_bytes: number;
  status: string;
  error_message: string | null;
};

export type Citation = {
  document_id: string;
  filename: string;
  page_start: number | null;
  page_end: number | null;
};

export type DocumentChapter = {
  document_id: string;
  chapter_index: number;
  chapter_title: string;
  page_start: number | null;
  page_end: number | null;
  markdown: string;
};

export type ChatDonePayload = {
  message_id: string;
  audio_url: string | null;
  citations: Citation[];
  session_id: string;
};

export type ParsedSSEEvent =
  | { event: "delta"; data: { text: string } }
  | { event: "done"; data: ChatDonePayload }
  | { event: "error"; data: { message: string } }
  | { event: "message"; data: Record<string, unknown> };

const API_BASE = (process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000").replace(/\/$/, "");

function normalizeAudioUrl(audioUrl: string): string {
  if (audioUrl.startsWith("http://") || audioUrl.startsWith("https://")) {
    return audioUrl;
  }

  if (audioUrl.startsWith("/")) {
    return `${API_BASE}${audioUrl}`;
  }

  return `${API_BASE}/${audioUrl}`;
}

export function sendChatMessage(sessionId: string | null, message: string): EventSource | ReadableStream<Uint8Array> {
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const encoder = new TextEncoder();

      try {
        const response = await fetch(`${API_BASE}/api/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ session_id: sessionId, message }),
        });

        if (!response.ok) {
          const message = (await response.text()) || "Chat request failed.";
          controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({ message })}\n\n`));
          controller.close();
          return;
        }

        if (!response.body) {
          controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({ message: "Missing chat stream response." })}\n\n`));
          controller.close();
          return;
        }

        const reader = response.body.getReader();
        while (true) {
          const chunk = await reader.read();
          if (chunk.done) {
            break;
          }

          if (chunk.value) {
            controller.enqueue(chunk.value);
          }
        }
        controller.close();
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unexpected chat error.";
        controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({ message })}\n\n`));
        controller.close();
      }
    },
  });

  return stream;
}

export async function getDocumentChapters(documentId: string): Promise<DocumentChapter[]> {
  const response = await fetch(`${API_BASE}/api/documents/${documentId}/chapters`);
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || "Không thể tải ghi chú chương.");
  }

  return (await response.json()) as DocumentChapter[];
}

function parseEventBlocks(raw: string): Array<{ event: string; data: Record<string, unknown> }> {
  const events: Array<{ event: string; data: Record<string, unknown> }> = [];

  const blocks = raw.split(/\n\n/);
  for (const block of blocks) {
    if (!block.trim()) {
      continue;
    }

    let eventName = "message";
    const dataLines: string[] = [];

    const lines = block.split(/\n/);
    for (const line of lines) {
      if (line.startsWith("event:")) {
        eventName = line.replace(/^event:\s*/, "");
      } else if (line.startsWith("data:")) {
        dataLines.push(line.replace(/^data:\s*/, ""));
      }
    }

    const payloadText = dataLines.join("\n");
    if (!payloadText) {
      continue;
    }

    try {
      const parsed = JSON.parse(payloadText) as Record<string, unknown>;
      events.push({ event: eventName, data: parsed });
    } catch {
      continue;
    }
  }

  return events;
}

export async function* parseChatEventStream(
  stream: ReadableStream<Uint8Array>,
): AsyncGenerator<ParsedSSEEvent> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) {
        const events = parseEventBlocks(buffer);
        for (const event of events) {
          yield event as ParsedSSEEvent;
        }
        break;
      }

      buffer += decoder.decode(chunk.value, { stream: true });
      const delimiter = "\n\n";
      let boundary = buffer.indexOf(delimiter);

      while (boundary !== -1) {
        const block = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + delimiter.length);

        const events = parseEventBlocks(block);
        for (const event of events) {
          yield event as ParsedSSEEvent;
        }

        boundary = buffer.indexOf(delimiter);
      }
    }
  } finally {
    reader.releaseLock();
  }
}

let player: HTMLAudioElement | null = null;

export async function playAssistantAudio(audioUrl: string): Promise<void> {
  if (!audioUrl) {
    return;
  }

  const nextUrl = normalizeAudioUrl(audioUrl);

  if (!player) {
    player = new Audio();
    player.preload = "auto";
  }

  if (player.src !== nextUrl) {
    player.pause();
    player.src = nextUrl;
  }

  if (player.paused) {
    await player.play();
  } else {
    player.pause();
    player.currentTime = 0;
  }
}
