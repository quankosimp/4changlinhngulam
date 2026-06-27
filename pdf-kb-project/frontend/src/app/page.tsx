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
  transcribeAudio,
} from "@/lib/chatService";

const API_BASE = (process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000").replace(/\/$/, "");

function statusLabel(status: string): string {
  return status[0].toUpperCase() + status.slice(1);
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

export default function Home() {
  const [documents, setDocuments] = useState<DocumentRead[]>([]);
  const [uploadError, setUploadError] = useState("");
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
  const [isRecording, setIsRecording] = useState(false);
  const [chatError, setChatError] = useState("");
  const isStreaming = useMemo(() => isSending, [isSending]);

  const uploadRef = useRef<HTMLInputElement | null>(null);
  const recorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);

  const selectedDocument = documents.find((document) => document.id === selectedDocumentId);

  const fetchDocuments = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/documents`);
      if (!response.ok) return;
      setDocuments((await response.json()) as DocumentRead[]);
      setUploadError("");
    } catch {
      setUploadError("Không kết nối được backend.");
    }
  };

  const fetchChapters = async (documentId: string) => {
    try {
      setChapters(await getDocumentChapters(documentId));
      setChaptersError("");
    } catch (error) {
      setChapters([]);
      setChaptersError(error instanceof Error ? error.message : "Không tải được ghi chú chương.");
    }
  };

  useEffect(() => {
    fetchDocuments();
    const interval = setInterval(fetchDocuments, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!selectedDocumentId) return;
    if (!documents.some((document) => document.id === selectedDocumentId)) {
      setSelectedDocumentId(null);
      setChapters([]);
      return;
    }
    fetchChapters(selectedDocumentId);
  }, [selectedDocumentId, documents]);

  const handleUpload = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!pickedFile) return;

    const formData = new FormData();
    formData.append("file", pickedFile);
    setUploading(true);
    setUploadError("");

    try {
      const response = await fetch(`${API_BASE}/api/documents`, { method: "POST", body: formData });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.detail || "Upload failed.");
      await fetchDocuments();
      setPickedFile(null);
      if (uploadRef.current) uploadRef.current.value = "";
    } catch (error) {
      setUploadError(error instanceof Error ? error.message : "Upload failed.");
    } finally {
      setUploading(false);
    }
  };

  const handleVoiceInput = async () => {
    if (isRecording) {
      recorderRef.current?.stop();
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const recorder = new MediaRecorder(stream);
      recorderRef.current = recorder;
      audioChunksRef.current = [];
      recorder.ondataavailable = (event) => event.data.size && audioChunksRef.current.push(event.data);
      recorder.onstop = async () => {
        stream.getTracks().forEach((track) => track.stop());
        setIsRecording(false);
        try {
          const audio = new Blob(audioChunksRef.current, { type: recorder.mimeType || "audio/webm" });
          const text = await transcribeAudio(audio);
          setMessage((value) => (value ? `${value}\n${text}` : text));
        } catch (error) {
          setChatError(error instanceof Error ? error.message : "Không thể nhận dạng giọng nói.");
        }
      };
      setChatError("");
      setIsRecording(true);
      recorder.start();
    } catch (error) {
      setChatError(error instanceof Error ? error.message : "Không mở được microphone.");
    }
  };

  const handleChatSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!message.trim() || isStreaming) return;

    const payload = message.trim();
    setMessage("");
    setStreamedText("");
    setCitations([]);
    setAudioUrl(null);
    setChatError("");
    setIsSending(true);

    try {
      const stream = sendChatMessage(sessionId, payload);
      if (stream instanceof ReadableStream) {
        for await (const event of parseChatEventStream(stream)) {
          if (event.event === "delta" && typeof event.data.text === "string") {
            setStreamedText((value) => `${value}${event.data.text}`);
          }
          if (event.event === "done") {
            const payload = event as ParsedSSEEvent;
            if (payload.event === "done") {
              setSessionId(payload.data.session_id);
              setAudioUrl(payload.data.audio_url);
              setCitations(payload.data.citations);
            }
          }
          if (event.event === "error") setChatError(event.data.message);
        }
      }
    } catch (error) {
      setChatError(error instanceof Error ? error.message : "Chat failed.");
    } finally {
      setIsSending(false);
    }
  };

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">PDF Knowledge Base</p>
          <h1>Vault đọc PDF</h1>
        </div>
        <p className="topbar-meta">{documents.length} tài liệu · {documents.filter((doc) => doc.status === "ready").length} sẵn sàng</p>
      </header>

      <div className="layout">
        <section className="panel library-panel">
          <h2>Tài liệu</h2>
          <form onSubmit={handleUpload} className="upload-form">
            <input
              ref={uploadRef}
              type="file"
              accept="application/pdf"
              onChange={(event) => setPickedFile(event.target.files?.[0] ?? null)}
            />
            <button type="submit" disabled={uploading || !pickedFile}>{uploading ? "Đang đọc..." : "Tải PDF"}</button>
            {pickedFile ? <small>{pickedFile.name}</small> : null}
            {uploadError ? <p className="error-text">{uploadError}</p> : null}
          </form>

          <div className="document-list">
            {documents.length === 0 ? <p className="muted">Chưa có tài liệu.</p> : null}
            {documents.map((document) => (
              <button
                key={document.id}
                type="button"
                className={`doc-row ${document.id === selectedDocumentId ? "doc-row--active" : ""}`}
                onClick={() => {
                  setSelectedDocumentId(document.id);
                  setChapters([]);
                }}
              >
                <span>{document.filename}</span>
                <small>{statusLabel(document.status)} · {formatBytes(document.size_bytes)}</small>
                {document.error_message ? <small className="error-text">{document.error_message}</small> : null}
              </button>
            ))}
          </div>
        </section>

        <section className="panel notes-panel">
          <div className="section-head">
            <h2>Ghi chú</h2>
            {selectedDocument ? <small>{selectedDocument.filename}</small> : null}
          </div>
          {!selectedDocumentId ? <p className="muted">Chọn một tài liệu để xem ghi chú markdown.</p> : null}
          {chaptersError ? <p className="error-text">{chaptersError}</p> : null}
          {selectedDocumentId && chapters.length === 0 ? <p className="muted">Chưa có ghi chú hoặc tài liệu đang xử lý.</p> : null}
          <div className="chapter-list">
            {chapters.map((chapter) => (
              <details key={`${chapter.document_id}-${chapter.chapter_index}`} className="note">
                <summary>
                  <span>{chapter.chapter_title}</span>
                  <small>{chapter.page_start ?? "?"}-{chapter.page_end ?? "?"}</small>
                </summary>
                <pre>{chapter.markdown}</pre>
              </details>
            ))}
          </div>
        </section>

        <section className="panel chat-panel">
          <h2>Hỏi đáp</h2>
          <form onSubmit={handleChatSubmit} className="chat-form">
            <textarea
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              placeholder="Hỏi tài liệu..."
              rows={5}
            />
            <div className="actions">
              <button type="button" onClick={handleVoiceInput} disabled={isSending}>{isRecording ? "Dừng ghi âm" : "Giọng nói"}</button>
              <button type="submit" disabled={isSending}>{isSending ? "Đang trả lời..." : "Gửi"}</button>
            </div>
          </form>

          <div className={`answer ${chatError ? "answer--error" : ""}`}>
            {chatError || streamedText || "Câu trả lời sẽ hiện ở đây."}
          </div>

          {citations.length > 0 ? (
            <div className="citations">
              <h3>Nguồn</h3>
              {citations.map((citation) => (
                <p key={`${citation.document_id}-${citation.page_start}-${citation.page_end}`}>
                  {citation.filename} · trang {citation.page_start ?? "?"}-{citation.page_end ?? "?"}
                </p>
              ))}
            </div>
          ) : null}

          <button className="audio-button" type="button" onClick={() => audioUrl && playAssistantAudio(audioUrl)} disabled={!audioUrl}>
            {audioUrl ? "Phát giọng đọc" : "Chưa có audio"}
          </button>
        </section>
      </div>
    </main>
  );
}
