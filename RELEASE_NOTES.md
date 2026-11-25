# Selorson Launcher v0.1.1 — Tự Cập Nhật Ký Số Ed25519 · Tải Gói Lớn Không Ngắt · Chuẩn Hóa 1 Icon Taskbar

## Có gì mới
- **Tự cập nhật 1 chạm (`tauri-plugin-updater`):** Tích hợp kiểm tra và nâng cấp trực tiếp chính `Selorson Launcher` có xác thực chữ ký `Ed25519` từ `Selorson/Selorson-Launcher-Release`.
- **Tải mượt các bộ cài lớn (`200+ MB` như Co-Writer):** Chuyển HTTP client từ giới hạn tổng thời gian 12 giây sang `connect_timeout(15s)` + `read_timeout(60s)` cho từng chặng dữ liệu.
- **Tối ưu thứ tự `Guardian Vault`:** Kiểm tra tiến trình/cổng sống → tải bộ cài & xác thực chữ ký `Ed25519` + giải phóng bộ nhớ đệm RAM → mới khóa `Guardian Vault` ngay trước giây chạy NSIS (không sinh bản sao DB thừa nếu rớt mạng).
- **Đồng bộ 1 icon duy nhất trên Taskbar Windows 11:** Tự đăng ký `AppUserModelID` (`vn.selorson.launcher`) vào Registry và đồng bộ định danh cho Shortcut hệ thống.
