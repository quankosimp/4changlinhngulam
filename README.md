# RepoGuard

RepoGuard là một backend AI-assistant cho chu trình **scan → verify → self-fix → benchmark** của mã nguồn repository, nhằm phát hiện hành vi đáng ngờ, tự động đề xuất sửa, kiểm tra tính đúng đắn sau sửa và tổng hợp kết quả ra báo cáo/dashboard.

Dự án này được thiết kế theo hướng demo sản phẩm: không chỉ đưa ra cảnh báo, mà còn đóng vòng lặp với khả năng sửa chữa tự động và đo được chất lượng sửa trên toàn bộ dataset kiểm thử.

## 1) Mục tiêu dự án

- Tự động quét mã nguồn để phát hiện các mẫu hành vi có rủi ro cao.
- Đưa ra đề xuất và/hoặc áp dụng patch theo kiểu có kiểm soát.
- Chạy benchmark để đo độ chính xác phát hiện, độ phủ, tỷ lệ sửa thành công và tỷ lệ lỗi do sai.
- Hỗ trợ tích hợp ngữ cảnh theo kiểu CodeGraph để giảm false positive và tăng chất lượng đề xuất.
- Có dashboard trực quan để theo dõi sai sót theo phiên chạy.

## 2) Kiến trúc tổng quát

- `repoguard/scan.py`: quét repository, sinh findings.
- `repoguard/fix.py`: pipeline đề xuất sửa, áp dụng patch, chạy kiểm chứng.
- `repoguard/fixer.py`: logic sửa tự động của agent.
- `repoguard/benchmark.py`: chạy benchmark theo manifest, xuất báo cáo JSON/CSV.
- `repoguard/cli.py`: giao diện dòng lệnh tổng hợp.
- `repoguard/dashboard/benchmark_app.py`: dashboard phân tích kết quả benchmark.
- `repoguard/codegraph_*`: các hàm tạo/ngầm đọc context CodeGraph.
- `tests/`: corpus và manifest cho benchmark.
- `spec.txt`, `HACKATHON_PLAN.md`, `ReNewPlan.md`: tài liệu mô tả định hướng kỹ thuật, phạm vi và kế hoạch phát triển.

## 3) Chế độ chạy nhanh

### Cài đặt

```bash
python3 -m pip install -r requirements.txt
cp .env.example .env
```

Cập nhật `OPENAI_API_KEY` trong `.env` (bắt buộc cho chế độ `fix` có gọi LLM).

### Tăng tốc quét

```bash
python3 -m repoguard scan tests/corpus --json
```

### Tự sửa mã (dry-run)

```bash
python3 -m repoguard fix tests/corpus/malicious/base64_exec.py --dry-run
```

### Tự sửa & áp dụng patch

```bash
python3 -m repoguard fix tests/corpus/malicious/base64_exec.py \
  --apply --max-findings 3 --max-rounds 4 --min-severity high
```

### Benchmark toàn hệ thống

```bash
python3 -m repoguard benchmark tests/repoguard_manifest.json --out benchmark_reports/latest --strict
```

### Dashboard benchmark

```bash
python3 -m streamlit run repoguard/dashboard/benchmark_app.py -- --server.port 8502
```

## 4) CodeGraph & context enrichment

RepoGuard có khả năng enrich context cho findings bằng CodeGraph payload để giúp pipeline fix hiểu quan hệ giữa hành vi:

- `codegraph init`
- `codegraph check`
- `graph` xuất `graph.json` / `graph.dot`

RepoGuard vẫn chạy được các luồng scan/benchmark ngay cả khi không có dependency bên ngoài theo chế độ fallback.

## 5) Kiểm thử nội bộ khuyến nghị

Để đánh giá toàn diện:

1. Chạy benchmark mặc định trên manifest hiện tại.
2. Lặp lại trên các tập test mới theo domain:
   - malicious execution chain
   - persistence/loader
   - obfuscation/compression
   - sensitive data handling
3. Đánh giá theo nhóm chỉ số:
   - Detection Rate
   - False Positive / False Negative
   - Repair Success Rate
   - Verification Pass Rate
   - Regression Error Rate

## 6) Đóng góp & mở rộng

- Chưa sửa: giữ nguyên hành vi sản phẩm trước khi commit.
- Sửa lỗi: commit theo từng module (`scan`, `fix`, `benchmark`, `dashboard`) để dễ review.
- Khi mở rộng chức năng mới, ưu tiên cập nhật `spec.txt`, `HACKATHON_PLAN.md` hoặc `ReNewPlan.md` trước, sau đó cập nhật testcase/manifest tương ứng.

## 7) Lưu ý triển khai

- `scan` và `benchmark` có thể chạy không cần `OPENAI_API_KEY`.
- `fix` yêu cầu khóa API cho bước tạo patch tự động.
- Tất cả luồng đều tạo output rõ ràng, tiện tích hợp CI hoặc đánh giá demo.
