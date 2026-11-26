# Selorson Launcher v0.1.2 — Gia Cố Toàn Diện Guardian Vault · Khôi Phục Rollback 1 Chạm · Git Drift Đa Kho Không Khóa Index

## Có gì mới
- **An toàn tuyệt đối `Guardian Vault` & Khôi phục 1 chạm (`rollback_tool`):**
  - Ghi nhật ký nguyên tử `txn-journal.json` và tự động phục hồi giao dịch sập dở ngay lúc khởi động (chống băm nhầm `cowriter-core.exe`), kèm retry `15 × 200 ms` vượt qua `os error 32 / 5` của Windows Defender.
  - Sao lưu cả tệp thực thi `.exe` ổn định trước đó kèm `snapshot-meta.json` và nút **Khôi phục (`⏪`)** trực tiếp trên thẻ công cụ; kiểm tra & hoàn trả nguyên tử cả cụm SQLite `.db + .db-wal`, bổ sung sao lưu DB/cấu hình cho `NeuroForge` và `Selorson Admin`.
- **Điều phối tiến trình chuẩn xác & Git Lock-Free:**
  - Quét đường dẫn ảnh tiến trình đầy đủ (`QueryFullProcessImageNameW`), chặn mở chồng cửa sổ trùng (tự kích hoạt cửa sổ đang mở lên tiền cảnh), tách biệt kênh `RTX` ↔ `Standard` trong sổ cái và xóa bỏ hoàn toàn `block_on` trên luồng Win32.
  - Mọi lệnh `git` chạy kèm `--no-optional-locks` + timeout `5s` (không bao giờ gây tranh chấp `.git/index.lock`), hỗ trợ theo dõi đa kho (`Selorson\backend-v3`), phát hiện `.exe` cũ trước tag và `Detached HEAD`.
- **Gia cố bảo mật `Ed25519`, CSP & Font nội bộ:**
  - Xác thực bắt buộc phiên bản và kênh trong trường `file:` của chữ ký `Ed25519 Minisign`, chặn hạ cấp phiên bản, bật `CSP` tường minh, mở đường dẫn chứa khoảng trắng qua `SHOpenFolderAndSelectItems` và nhúng sẵn bộ font `.woff2` ngoại tuyến.

---

# Selorson Launcher v0.1.1 — Tự Cập Nhật Ký Số Ed25519 · Tải Gói Lớn Không Ngắt · Chuẩn Hóa 1 Icon Taskbar

## Có gì mới
- **Tự cập nhật 1 chạm (`tauri-plugin-updater`):** Tích hợp kiểm tra và nâng cấp trực tiếp chính `Selorson Launcher` có xác thực chữ ký `Ed25519` từ `Selorson/Selorson-Launcher-Release`.
- **Tải mượt các bộ cài lớn (`200+ MB` như Co-Writer):** Chuyển HTTP client từ giới hạn tổng thời gian 12 giây sang `connect_timeout(15s)` + `read_timeout(60s)` cho từng chặng dữ liệu.
- **Tối ưu thứ tự `Guardian Vault`:** Kiểm tra tiến trình/cổng sống → tải bộ cài & xác thực chữ ký `Ed25519` + giải phóng bộ nhớ đệm RAM → mới khóa `Guardian Vault` ngay trước giây chạy NSIS (không sinh bản sao DB thừa nếu rớt mạng).
- **Đồng bộ 1 icon duy nhất trên Taskbar Windows 11:** Tự đăng ký `AppUserModelID` (`vn.selorson.launcher`) vào Registry và đồng bộ định danh cho Shortcut hệ thống.
