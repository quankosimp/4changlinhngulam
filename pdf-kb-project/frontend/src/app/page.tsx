"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  Citation,
  DocumentChapter,
  DocumentRead,
  ParsedSSEEvent,
  getDocumentChapters,
  parseChatEventStream,
  playAssistantAudio,
  sendChatMessage,
} from "@/lib/chatService";

const API_BASE = (process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000").replace(/\/$/, "");

function normalizeDocumentStatus(status: string): string {
  return status[0].toUpperCase() + status.slice(1);
}

function statusChip(status: string) {
  const color =
    status === "ready"
      ? "#065f46"
      : status === "processing"
        ? "#92400e"
        : status === "failed"
          ? "#991b1b"
          : "#1d4ed8";

  return (
    <span
      style={{
        fontWeight: 600,
        color,
        border: `1px solid ${color}`,
        borderRadius: 999,
        padding: "2px 8px",
        fontSize: 12,
        textTransform: "lowercase",
      }}
    >
      {normalizeDocumentStatus(status)}
    </span>
  );
}

export default function Home() {
  const [documents, setDocuments] = useState<DocumentRead[]>([]);
  const [uploadError, setUploadError] = useState<string>("");
  const [uploading, setUploading] = useState(false);
  const [pickedFile, setPickedFile] = useState<File | null>(null);

  const [selectedDocumentId, setSelectedDocumentId] = useState<string | null>(null);
  const [chapters, setChapters] = useState<DocumentChapter[]>([]);
  const [chaptersError, setChaptersError] = useState("");

  const [sessionId, setSessionId] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [streamedText, setStreamedText] = useState("");
  const [citations, setCitations] = useState<Citation[]>([]);
  const [audioUrl, setAudioUrl] = useState<string | null>(null);
  const [isSending, setIsSending] = useState(false);
  const [chatError, setChatError] = useState("");
  const isStreaming = useMemo(() => isSending, [isSending]);
  const audioButtonLabel = audioUrl ? "Tạm dừng / Phát lại" : "Không có audio";

  const uploadRef = useRef<HTMLInputElement | null>(null);

  const fetchDocuments = async () => {
    const response = await fetch(`${API_BASE}/api/documents`);
    if (!response.ok) {
      return;
    }

    const data = (await response.json()) as DocumentRead[];
    setDocuments(data);
  };

  const fetchChapters = async (documentId: string) => {
    try {
      const chapterData = await getDocumentChapters(documentId);
      setChapters(chapterData);
      setChaptersError("");
    } catch (error) {
      setChapters([]);
      setChaptersError(error instanceof Error ? error.message : "Không tải được ghi chú chương.");
    }
  };

  useEffect(() => {
    fetchDocuments();
    const interval = setInterval(() => {
      const needsPoll = documents.some((doc) => doc.status === "processing" || doc.status === "uploaded");
      if (needsPoll) {
        fetchDocuments();
      }
    }, 2500);

    return () => clearInterval(interval);
  }, [documents]);

  useEffect(() => {
    if (!selectedDocumentId) {
      return;
    }

    const active = documents.some((document) => document.id === selectedDocumentId);
    if (!active) {
      setSelectedDocumentId(null);
      setChapters([]);
      return;
    }

    fetchChapters(selectedDocumentId);
  }, [selectedDocumentId, documents]);

  const handleUpload = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!pickedFile) {
      return;
    }

    const formData = new FormData();
    formData.append("file", pickedFile);
    setUploading(true);
    setUploadError("");

    try {
      const response = await fetch(`${API_BASE}/api/documents`, {
        method: "POST",
        body: formData,
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || "Upload failed.");
      }

      await fetchDocuments();
      setPickedFile(null);
      if (uploadRef.current) {
        uploadRef.current.value = "";
      }
    } catch (error) {
      setUploadError(error instanceof Error ? error.message : "Upload failed.");
    } finally {
      setUploading(false);
    }
  };

  const handleChatSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!message.trim() || isStreaming) {
      return;
    }

    const payload = message.trim();
    setMessage("");
    setStreamedText("");
    setCitations([]);
    setAudioUrl(null);
    setChatError("");
    setIsSending(true);

    try {
      const streamOrSource = sendChatMessage(sessionId, payload);

      if (streamOrSource instanceof ReadableStream) {
        for await (const event of parseChatEventStream(streamOrSource)) {
          if (event.event === "delta") {
            const next = event.data.text;
            if (typeof next === "string") {
              setStreamedText((value) => `${value}${next}`);
            }
          }

          if (event.event === "done") {
            const payload = event as ParsedSSEEvent;
            if (payload.event === "done") {
              setSessionId(payload.data.session_id);
              setAudioUrl(payload.data.audio_url);
              setCitations(payload.data.citations);
            }
          }

          if (event.event === "error") {
            setChatError(event.data.message);
          }
        }
      }
    } catch (error) {
      setChatError(error instanceof Error ? error.message : "Chat failed.");
    } finally {
      setIsSending(false);
    }
  };

  return (
    <main>
      <h1>PDF Knowledge Base MVP</h1>

      <section style={{ marginBottom: 18 }}>
        <h2>Upload PDF</h2>
        <form onSubmit={handleUpload} style={{ display: "grid", gap: 8 }}>
          <input
            ref={uploadRef}
            type="file"
            accept="application/pdf"
            onChange={(event) => setPickedFile(event.target.files?.[0] ?? null)}
          />
          <button type="submit" disabled={uploading || !pickedFile}>
            {uploading ? "Đang upload..." : "Tải lên PDF"}
          </button>
          {pickedFile ? <small>Chọn: {pickedFile.name}</small> : null}
          {uploadError ? <p style={{ color: "#b91c1c" }}>{uploadError}</p> : null}
        </form>
      </section>

      <section style={{ marginBottom: 18 }}>
        <h2>Danh sách tài liệu</h2>
        <div style={{ display: "grid", gap: 10 }}>
          {documents.length === 0 ? (
            <p>Chưa có tài liệu nào.</p>
          ) : (
            documents.map((document) => (
              <div
                key={document.id}
                style={{ border: "1px solid #e5e7eb", borderRadius: 10, padding: 10 }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
                  <strong>{document.filename}</strong>
                  {statusChip(document.status)}
                </div>
                {document.error_message ? (
                  <p style={{ color: "#991b1b", marginTop: 8 }}>{document.error_message}</p>
                ) : null}
                <small style={{ color: "#6b7280" }}>{document.size_bytes} bytes</small>
                <div style={{ marginTop: 10 }}>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedDocumentId(document.id);
                      setChapters([]);
                    }}
                  >
                    Xem ghi chú theo chương
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      <section style={{ marginBottom: 18 }}>
        <h2>Ghi chú theo chương (kiến thức nền)</h2>
        {!selectedDocumentId ? (
          <p>Chọn một tài liệu để xem tóm tắt theo chương.</p>
        ) : (
          <>
            <p>
              Tài liệu: <strong>{documents.find((document) => document.id === selectedDocumentId)?.filename}</strong>
            </p>
            {chaptersError ? <p style={{ color: "#991b1b" }}>{chaptersError}</p> : null}
            {chapters.length === 0 ? <p>Chưa có ghi chú chương hoặc chưa sẵn sàng.</p> : null}
            {chapters.map((chapter) => (
              <details key={`${chapter.document_id}-${chapter.chapter_index}`} style={{ marginBottom: 12 }}>
                <summary>
                  {chapter.chapter_title} (trang {chapter.page_start ?? "?"}-{chapter.page_end ?? "?"})
                </summary>
                <pre style={{ whiteSpace: "pre-wrap", marginTop: 8 }}>{chapter.markdown}</pre>
              </details>
            ))}
          </>
        )}
      </section>

      <section>
        <h2>Chat</h2>
        <form onSubmit={handleChatSubmit} style={{ display: "grid", gap: 8 }}>
          <textarea
            value={message}
            onChange={(event) => setMessage(event.target.value)}
            placeholder="Nhập câu hỏi tiếng Việt hoặc tiếng Anh..."
            rows={4}
            style={{ resize: "vertical" }}
          />
          <button type="submit" disabled={isSending}>
            {isSending ? "Đang sinh câu trả lời..." : "Gửi"}
          </button>
        </form>

        <div style={{ marginTop: 12, minHeight: 80, whiteSpace: "pre-wrap" }}>
          {streamedText || chatError ? <p>{chatError || streamedText}</p> : <p style={{ color: "#9ca3af" }}>Câu trả lời sẽ hiển thị tại đây.</p>}
        </div>

        <div style={{ marginBottom: 12 }}>
          {citations.length > 0 ? (
            <>
              <h3>Trích dẫn</h3>
              <ul>
                {citations.map((citation) => (
                  <li key={`${citation.document_id}-${citation.page_start}-${citation.page_end}`}>
                    {citation.filename} (trang {citation.page_start ?? "?"}-{citation.page_end ?? "?"})
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </div>

        <div>
          <button type="button" onClick={() => audioUrl && playAssistantAudio(audioUrl)} disabled={!audioUrl}>
            {audioUrl ? audioButtonLabel : "Không có audio"}
          </button>
        </div>
      </section>
    </main>
  );
}
