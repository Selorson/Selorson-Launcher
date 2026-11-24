# Selorson Launcher — Trung Tâm Điều Phối Hệ Sinh Thái

Ứng dụng trung tâm (**Tauri 2 + Rust + Svelte 5**) điều phối toàn bộ các công cụ trong `E:\Selorson-Ecosystem` theo hướng **Manifest-Driven** ([`ecosystem-manifest.json`](./ecosystem-manifest.json)).

## Tính Năng Cốt Lõi

1. **Khởi chạy, Cài đặt mới & Cập nhật 1 chạm chuẩn `Ed25519 Minisign`:**
   - Tự động đối chiếu phiên bản thực thi đang cài (kết hợp `Win32 PE FileVersion`, `Windows Registry Uninstall` và `Launcher Ledger`) với kênh `latest.json` / `latest-rtx.json` trên GitHub Releases.
   - Xác thực mật mã học `Ed25519 Minisign` + phiên bản ký trong `trusted_comment` trước khi chạy bộ cài NSIS (`/P /UPDATE`).
   - Khởi chạy công cụ ở chế độ độc lập (`DETACHED_PROCESS`), tắt Launcher không bao giờ kéo tắt ứng dụng đang làm việc.

2. **Kho Bảo Hộ Nguyên Tử (`Guardian Vault`) — Bảo vệ tuyệt đối DB & Sidecar sống:**
   - **Cổng khóa tiến trình & TCP:** Tự động chặn cập nhật khi công cụ hoặc sidecar đang chạy (`cowriter-core.exe`, `:8787`, luồng quay màn hình `:8788` của `CastCam`, trình duyệt tự động `:9222` của `NeuroForge`...).
   - **Khóa bất biến `immutable_files`:** Sao lưu cô lập luồng dữ liệu, hoàn trả tự động và kiểm khớp `100% SHA-256` sau khi trình cài đặt NSIS chạy xong (đảm bảo `cowriter-core.exe` 227 MB không bao giờ bị ghi đè hay xóa mất).
   - **Sao lưu lăn (`Rolling Snapshot`):** Tự động chụp bản dự phòng cho các tệp SQLite DB và khóa bảo mật (`co_writer.db*`, `master.key`, `secret.key`, `akunarch.db*`) vào `%LOCALAPPDATA%\Selorson Launcher\vault\`.

3. **Radar Đối Chiếu Mã Nguồn Cục Bộ 2 Tầng (`Git Drift Engine`):**
   - Tầng 1 neo theo Tag phiên bản (`git rev-list <tag>..HEAD -- <watch_paths>`) và Tầng 2 theo mốc thời gian phạm vi hẹp (`watch_paths`), tự động bỏ qua các commit bản thảo truyện hay tài liệu ngoài lề.
   - Nhận diện 3 trạng thái rõ ràng: `Khớp mã nguồn` · `Code mới hơn (+N commit)` · `Bản Hot-Swap cục bộ` (tự khóa chống hạ cấp nhầm khi bấm Cập nhật tất cả).

4. **Mở rộng Công cụ thứ 8 Không Cần Sửa Code (`Zero-Code Extensibility`):**
   - Chỉ cần khai báo thêm 1 phần tử vào mảng `tools` trong [`ecosystem-manifest.json`](./ecosystem-manifest.json) (có sẵn [`ecosystem-manifest.schema.json`](./ecosystem-manifest.schema.json) kiểm lỗi tự động).
   - Bộ lắng nghe tự động nạp nóng giao diện trong `< 1 giây` mà không cần biên dịch lại Launcher.

5. **Tối ưu RAM tuyệt đối cho Máy trạm `RTX 4080`:**
   - Mặc định **Đóng cửa sổ = Thoát sạch 100% (`0 MB RAM`)**.
   - Tùy chọn bật giữ ở Khay hệ thống (`System Tray`) + phím tắt toàn cục `Alt + Shift + S` sử dụng cơ chế **Hủy nhân WebView2 khi đóng**, giải phóng `~100 MB` bộ nhớ trình duyệt và chỉ giữ hạt nhân Rust `~4 MB`.

## Lệnh Phát Triển & Kiểm Thử

```powershell
# Chạy toàn bộ kiểm thử tự động lõi Rust
cargo test -j 8 --lib --manifest-path E:\Selorson-Launcher\app\src-tauri\Cargo.toml

# Kiểm tra kiểu dữ liệu giao diện & đóng gói tĩnh
cd E:\Selorson-Launcher\app
npm run check
npm run build

# Biên dịch bản Release nhúng sẵn giao diện
cargo build -j 8 --release --features custom-protocol --manifest-path E:\Selorson-Launcher\app\src-tauri\Cargo.toml
```
