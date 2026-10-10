# smart-ppe-incident-service

> **Incident Management Microservice** cho Hệ thống Giám sát An toàn Lao động Thông minh (**Smart PPE Monitoring System**), phụ trách quản lý sự cố an toàn, vòng đời vi phạm (Pending Review -> Confirmed -> Resolved -> Closed), quy trình Human Review (True Violation vs False Alarm), lưu trữ bằng chứng số có băm SHA-256 và Transactional Outbox Pattern theo chuẩn **D08.pdf (Mục 3.5 & Task BE-06)**.

---

## 🏛️ Trách nhiệm nghiệp vụ

- **Quản lý sự cố vi phạm (`/api/v1/incidents`)**: Tiếp nhận sự cố phát hiện vi phạm PPE (Không đội mũ, không mặc áo phản quang, xâm nhập vùng cấm).
- **Máy trạng thái sự cố (State Machine & Audit Trail)**: Chuyển dịch trạng thái bất biến qua `$transaction` nguyên tử, lưu vết lịch sử `incident_status_history`.
- **Quy trình Human Review (`/api/v1/incidents/:id/review`)**: Cho phép Safety Officer duyệt xác nhận (`CONFIRMED`) hoặc bác bỏ (`DISMISSED` / False Alarm kèm lý do giải trình) để tạo dữ liệu Active Learning huấn luyện lại mô hình AI.
- **Bằng chứng số & Băm SHA-256 (`/api/v1/evidences`)**: Quản lý ảnh snapshot, video clip vi phạm trên MinIO/S3, kiểm thực mã băm SHA-256 (`/verify-checksum`), tiêu chuẩn bảo mật chống rò rỉ và chống giả mạo hồ sơ thanh tra.

---

## 🚀 Khởi chạy cục bộ (Local Development)

```bash
# 1. Cài đặt dependencies
pnpm install

# 2. Cấu hình biến môi trường
cp .env.example .env

# 3. Sinh Prisma Client từ schema
pnpm run prisma:generate

# 4. Khởi chạy chế độ phát triển
pnpm run dev
# Server lắng nghe tại http://localhost:8893
```

---

## 🧪 Kiểm thử tự động (Unit Tests)

```bash
pnpm test
```

---

## 🐳 Triển khai Docker

```bash
docker build -t smart-ppe-incident-service .
docker run -p 8893:8893 --env-file .env smart-ppe-incident-service
```
