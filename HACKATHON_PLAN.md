# Hackathon 3h — Chia việc 3 người: Agent phát hiện mã độc trên CodeGraph

## Context

- **Mục tiêu**: Trong 3 giờ, 3 người xây một công cụ phát hiện code khả nghi/mã độc (backdoor, payload obfuscate, `eval/exec` chuỗi decode, dropper `fetch→write→exec`) trong source repo, dùng **CodeGraph** làm chỉ mục.
- **Team**: 2 backend (Python) + 1 frontend. Stack công cụ: **Python**.
- **Tham vọng đã chốt**: điểm nhấn demo là **NL-agent** — hỏi tiếng tự nhiên ("tìm chỗ decode base64 rồi exec") → gọi `codegraph_explore` (MCP) + lọc qua rule engine → trả call-path + bằng chứng.

### Sự thật quan trọng về CodeGraph (đã research, quyết định kiến trúc)
- CodeGraph = **chỉ mục cấu trúc** (tree-sitter → SQLite/FTS5). Có **symbol + call graph** (`calls/imports/extends/contains`), **KHÔNG có taint/data-flow, KHÔNG có git metadata**.
- Truy vấn qua **MCP** (`codegraph_explore` mặc định; bật thêm `codegraph_search/callers/callees/impact/node/files` bằng env `CODEGRAPH_MCP_TOOLS`) **và CLI** (`codegraph query/callers/callees/impact`, đều có `--json`).
- Cài nhanh ~2–5 phút: `npx @colbymchenry/codegraph` → `codegraph install` → `codegraph init`. Hỗ trợ Python/JS/TS/Java. Chạy native trên Windows.
- **Hệ quả thiết kế**: data-flow đa bước (download→write→exec) phải **tự dựng bằng cách traverse call-graph của CodeGraph + so khớp pattern** — CodeGraph không tự làm. Vì vậy lớp AST (1 file) là 80% tín hiệu và chạy chắc; CodeGraph + agent là lớp khác biệt nhưng rủi ro hơn → để làm safety-net rõ ràng.

---

## Kiến trúc & HỢP ĐỒNG TÍCH HỢP (làm chung 15' đầu — bắt buộc)

Cả 3 thống nhất 1 schema + 1 interface ngay phút đầu để code song song không chặn nhau.

**Repo layout (Python):**
```
malguard/
  models.py            # CONTRACT: Finding dataclass + Severity + to_dict()  ← viết CHUNG đầu tiên
  scanner.py           # walk repo → gọi rules → gom List[Finding]            (A sở hữu)
  rules/
    ast_rules.py       # A: rule AST 1-file (rule #1..#7)
    graph_rules.py     # B: rule đa bước dựa call-graph (#8..#10)
  codegraph_client.py  # B: wrap CLI/MCP codegraph (subprocess + --json)
  agent.py             # B: NL query → codegraph_explore → lọc rule
  report.py            # C: xuất JSON + bảng CLI
  cli.py               # entrypoint: python -m malguard scan <path> [--json]
  dashboard/app.py     # C: Streamlit (đọc report JSON, hiển thị)
tests/corpus/{malicious,benign}/   # C: bộ mẫu test
```

**Contract `models.py` (chốt cứng, không đổi sau phút 15):**
```python
@dataclass
class Finding:
    rule_id: str            # "PY-EXEC-B64"
    title: str
    severity: str           # "high" | "medium" | "low"
    confidence: float       # 0.0–1.0
    file: str
    line: int
    snippet: str            # đoạn code khớp + ngữ cảnh
    message: str            # vì sao đáng ngờ
    call_path: list[str] | None = None  # ["downloads.py:12 get()", "...write()", "setup.py:8 exec()"]
    def to_dict(self) -> dict: ...
```
**Interface chung**: mọi rule là hàm `detect(tree/path) -> list[Finding]`; `scanner.scan(path) -> list[Finding]`; `report.write(findings) -> report.json`. Dashboard CHỈ đọc `report.json` → tách rời hoàn toàn frontend khỏi backend.

---

## Người A — Backend: Detection Engine (AST, lõi an toàn)

**Sở hữu**: `models.py` (khởi tạo), `scanner.py`, `rules/ast_rules.py`, `cli.py`.
**Đây là safety-net**: chạy độc lập, KHÔNG phụ thuộc CodeGraph. Nếu agent của B chết, demo vẫn sống nhờ phần này.

Dùng `ast` chuẩn của Python + mượn cấu trúc `NodeVisitor` của **Bandit** và logic rule của **apiiro/malicious-code-ruleset** (đừng gọi Bandit/Semgrep như subprocess — copy ý tưởng, tự viết visitor 20–30 dòng/rule).

Rule ưu tiên (signal cao, nhanh):
1. `eval/exec` trên dữ liệu decode: `exec(base64.b64decode(...))`, `eval(binascii.unhexlify(...))` — **#1**
2. Chuỗi entropy cao (>64 ký tự, ≥4.5 bit/char) đưa vào `exec/eval/compile`
3. `__import__('os').system(...)` / `importlib.import_module` rồi gọi
4. `pickle.loads()` từ `requests.get(...).content` / `socket.recv(...)`
5. `exec/eval` trên chuỗi tái tạo (`''.join([...])`, `s[::-1]`) → arg là `BinOp` string
6. `subprocess`/`os.system` với chuỗi nối/f-string (command injection)
7. `os.environ`/`getenv` → `requests.post` (exfil credential)

Mỗi rule gắn `confidence` (vd: cùng dòng có cả `base64`+`exec` → high). `cli.py`: `python -m malguard scan <path> [--json]` in bảng + ghi `report.json`.

---

## Người B — Backend: CodeGraph + NL Agent (điểm nhấn, có fallback)

**Sở hữu**: `codegraph_client.py`, `rules/graph_rules.py`, `agent.py`.

1. **Setup CodeGraph (phút đầu, ưu tiên #1)**: `npx @colbymchenry/codegraph` → `codegraph init` trên `tests/corpus/`. Verify bằng `codegraph status` và `codegraph callers <fn> --json`. **De-risk: nếu MCP/CLI trục trặc → fallback regex call-heuristic** (cùng file có `urllib`+`open`+`exec`).
2. **`codegraph_client.py`**: wrap `subprocess.run([... '--json'])` cho `callers/callees/query`; parse JSON thành dict Python. (MCP `codegraph_explore` cho lớp agent.)
3. **`graph_rules.py`** — rule đa bước dựng call-path từ call-graph (trả `Finding` có `call_path`):
   - #8 download→write→exec (dropper): `requests.get`→`open(...,'w')`→`subprocess`
   - #9 write `.py`→`__import__` file vừa ghi (stage-2)
   - #10 `ctypes.CDLL` + path khả nghi / blob base64
4. **`agent.py` — NL agent (tham vọng)**: nhận câu hỏi tiếng tự nhiên → gọi `codegraph_explore` (MCP) lấy call-path → chiếu qua rule engine của A → trả kết quả + bằng chứng. **Fallback bắt buộc**: nếu agent chưa kịp, `graph_rules` vẫn chạy độc lập và demo dùng câu truy vấn cố định thay cho NL.

---

## Người C — Frontend: Dashboard + Test Corpus + Demo

**Sở hữu**: `dashboard/app.py`, `tests/corpus/`, kịch bản demo. **Tách rời backend**: chỉ đọc `report.json` theo schema `Finding`.

1. **Bộ mẫu test (phút đầu, để A/B có cái chạy ngay)**: clone `apiiro/malicious-code-ruleset` (lấy test cases), copy 5 mẫu thật từ Datadog GuardDog writeups, 5 mẫu lành (OWASP), tự viết 5 backdoor cố ý (base64-eval, dropper). Mục tiêu ~10 malicious + 10 benign trong `tests/corpus/`.
2. **Dashboard (Streamlit — nhanh nhất cho dev không chuyên frontend)**: đọc `report.json` → cây thư mục có badge mức độ, card mở rộng hiện snippet + `message`, hiển thị `call_path`, thanh `confidence`, nút export CSV/JSON. Trong khi chờ backend: dùng `report.json` giả đúng schema để dựng UI trước.
3. **Demo prep**: kịch bản 2 phút — quét repo có backdoor thật → dashboard sáng đèn đỏ → hỏi NL agent một câu → hiện call-path. Chuẩn bị sẵn `report.json` "đẹp" làm bản dự phòng nếu live chạy lỗi.

---

## Dòng thời gian 180 phút

| Mốc | A (engine) | B (CodeGraph/agent) | C (UI/corpus) |
|---|---|---|---|
| 0:00–0:15 | **Chung**: chốt `models.py` + interface + skeleton repo, push lên git | | |
| 0:15–1:30 | rule #1–7 + `scanner` + `cli` | setup CodeGraph + `codegraph_client` + verify | dựng corpus 20 mẫu + skeleton Streamlit trên JSON giả |
| 1:30–2:00 | hoàn thiện confidence, test trên corpus | `graph_rules` #8–10 (call-path) | dashboard đọc `report.json` thật |
| 2:00–2:30 | hỗ trợ tích hợp, sửa false-positive | `agent.py` NL → `codegraph_explore` | hoàn thiện UI + export |
| 2:30–3:00 | **Chung**: tích hợp end-to-end, demo dry-run, chuẩn bị bản dự phòng | | |

**Quy tắc cắt scope** (nếu trễ ở mốc 1:30): bỏ #9–#10 và NL agent, ship #1–8 + dashboard, nói "production sẽ thêm". Engine của A + dashboard của C luôn là phần demo được.

---

## Verification (chứng minh chạy được)

1. `python -m malguard scan tests/corpus/malicious --json > report.json` → phải bắt ≥8/10 mẫu malicious.
2. Chạy trên `tests/corpus/benign` → false-positive thấp (lý tưởng 0–2).
3. `codegraph status` báo index OK; `graph_rules` trả `call_path` ≥1 mẫu dropper.
4. Mở dashboard Streamlit (`streamlit run malguard/dashboard/app.py`) → đọc `report.json`, hiện badge + snippet + call-path.
5. NL agent: hỏi "find base64 decode then exec" → trả đúng file/line như rule #1 (nếu kịp; nếu không, dùng truy vấn cố định).

## Nguồn tham khảo nhanh (mượn pattern để đi nhanh)
- `github.com/apiiro/malicious-code-ruleset` (test cases + rule logic, 94.3% acc) — gold standard.
- `github.com/PyCQA/bandit` — mẫu `NodeVisitor`.
- Datadog GuardDog writeups — mẫu backdoor PyPI thật.
- CodeGraph docs: `colbymchenry.github.io/codegraph` (MCP server, languages, CLI).
