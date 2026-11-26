use crate::discovery::{
    capture_running_processes, discover_tool_local, normalize_semver, path_is_within_dir,
    scan_uninstall_registry,
};
use crate::guardian_vault::{GuardianTransaction, VaultVerificationReport};
use crate::ledger::ToolLedgerEntry;
use crate::manifest::{ToolManifest, decode_tauri_pubkey};
use crate::release_probe::RemoteReleaseInfo;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use futures_util::StreamExt;
use minisign_verify::Signature;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use tokio::process::Command;

const NSIS_TIMEOUT_SECS: u64 = 300;
pub const MAX_INSTALLER_BYTES: u64 = 1_536 * 1024 * 1024; // 1.5 GB ceiling chống tràn RAM

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallProgressEvent {
    pub tool_id: String,
    pub tool_name: String,
    pub phase: String,
    pub percent: Option<u8>,
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallResultDto {
    pub tool_id: String,
    pub installed_version: String,
    pub active_exe_path: Option<String>,
    pub vault_report: VaultVerificationReport,
}

fn extract_trusted_field<'a>(trusted_comment: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    let body = trusted_comment
        .strip_prefix("trusted comment:")
        .map(|s| s.trim())
        .unwrap_or(trusted_comment.trim());
    for part in body.split('\t') {
        let p = part.trim();
        for pref in prefixes {
            if let Some(val) = p.strip_prefix(pref) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }
    }
    None
}

/// Tách `(product_prefix, version_raw)` từ tên tệp bộ cài Tauri đã ký trong `file:` của `trusted_comment`
/// (ví dụ: `"ToneForge Studio_0.1.1_x64-setup.exe"` -> `("ToneForge Studio", "0.1.1")`).
pub fn split_tauri_installer_filename(file_field: &str) -> Option<(&str, &str)> {
    let fname = file_field.rsplit(['/', '\\']).next().unwrap_or(file_field).trim();
    let mut stem = fname
        .strip_suffix(".exe")
        .or_else(|| fname.strip_suffix(".EXE"))
        .or_else(|| fname.strip_suffix(".msi"))
        .or_else(|| fname.strip_suffix(".MSI"))?;

    for sfx in ["-setup", "_setup", "-Setup", "_Setup"] {
        if let Some(s) = stem.strip_suffix(sfx) {
            stem = s;
            break;
        }
    }
    for loc in ["_en-US", "_vi-VN", "-en-US", "-vi-VN"] {
        if let Some(s) = stem.strip_suffix(loc) {
            stem = s;
            break;
        }
    }
    for arch in ["_x64", "_x86", "_arm64", "-x64", "-x86", "-arm64", "_x86_64"] {
        if let Some(s) = stem.strip_suffix(arch) {
            stem = s;
            break;
        }
    }

    let (prod, ver) = stem.rsplit_once('_')?;
    if prod.trim().is_empty() || ver.trim().is_empty() {
        return None;
    }
    Some((prod.trim(), ver.trim()))
}

pub fn verify_ed25519_package(
    bytes: &[u8],
    signature_b64: &str,
    pubkey_b64: &str,
    expected_version: &str,
    tag_prefix: &str,
    tool: Option<&ToolManifest>,
    channel_key: Option<&str>,
) -> Result<(), String> {
    if bytes.len() < 2 || &bytes[..2] != b"MZ" {
        return Err(
            "XÁC THỰC BẢO MẬT THẤT BẠI: Gói tải về không phải tệp thực thi Windows PE hợp lệ (thiếu chữ ký MZ)."
                .to_string(),
        );
    }

    let public_key = decode_tauri_pubkey(pubkey_b64)?;

    let sig_decoded_bytes = STANDARD
        .decode(signature_b64.trim())
        .map_err(|e| format!("Chữ ký số Base64 trong latest.json không hợp lệ: {e}"))?;
    let sig_str = String::from_utf8(sig_decoded_bytes)
        .map_err(|e| format!("Chữ ký số không phải định dạng Minisign UTF-8: {e}"))?;
    let signature = Signature::decode(&sig_str)
        .map_err(|e| format!("Không giải mã được chữ ký Ed25519 Minisign: {e}"))?;

    public_key.verify(bytes, &signature, true).map_err(|e| {
        format!(
            "XÁC THỰC BẢO MẬT THẤT BẠI: Bộ cài tải về không khớp chữ ký Ed25519 chính chủ ({e}). Đã hủy cài đặt ngay lập tức!"
        )
    })?;

    let expected_sv = normalize_semver(expected_version, Some(tag_prefix)).ok_or_else(|| {
        format!(
            "Không phân tích được phiên bản kỳ vọng '{}' khi đối chiếu chữ ký.",
            expected_version
        )
    })?;

    let tc = signature.trusted_comment();

    // 1. Đối chiếu trường `version:` / `v:` nếu có mặt trong trusted_comment (không bỏ qua êm nếu lỗi parse!)
    if let Some(signed_ver_raw) = extract_trusted_field(tc, &["version:", "v:"]) {
        let sv = normalize_semver(signed_ver_raw, Some(tag_prefix)).ok_or_else(|| {
            format!(
                "XÁC THỰC BẢO MẬT THẤT BẠI: Trường version:'{}' trong chữ ký số không hợp lệ.",
                signed_ver_raw
            )
        })?;
        if sv != expected_sv {
            return Err(format!(
                "XÁC THỰC BẢO MẬT THẤT BẠI: Phiên bản trong chữ ký ({sv}) khác với phiên bản công bố trong latest.json ({expected_sv})."
            ));
        }
    }

    // 2. Đối chiếu trường `file:` trong trusted_comment: chống phát lại bản cũ & chống tráo chéo kênh dùng chung khóa (RTX <-> Standard)
    if let Some(signed_file) = extract_trusted_field(tc, &["file:"]) {
        let (signed_prod, signed_file_ver_raw) =
            split_tauri_installer_filename(signed_file).ok_or_else(|| {
                format!(
                    "XÁC THỰC BẢO MẬT THẤT BẠI: Trường file:'{}' trong chữ ký số không đúng chuẩn gói cài đặt Tauri.",
                    signed_file
                )
            })?;

        let file_sv = normalize_semver(signed_file_ver_raw, Some(tag_prefix)).ok_or_else(|| {
            format!(
                "XÁC THỰC BẢO MẬT THẤT BẠI: Không đọc được số phiên bản từ trường file:'{}' trong chữ ký số.",
                signed_file
            )
        })?;

        if file_sv != expected_sv {
            return Err(format!(
                "XÁC THỰC BẢO MẬT THẤT BẠI: Phiên bản gói trong chữ ký file:'{}' ({file_sv}) không khớp latest.json ({expected_sv}).",
                signed_file
            ));
        }

        if let (Some(t), Some(ch)) = (tool, channel_key) {
            if t.updater.channels.len() > 1 {
                let prod_norm = signed_prod.replace('.', " ").to_lowercase();
                let cur_regs = t.effective_registry_names(ch);
                let matches_cur = cur_regs
                    .iter()
                    .any(|r| r.trim().eq_ignore_ascii_case(&prod_norm));

                for (other_ch, other_spec) in &t.updater.channels {
                    if other_ch == ch {
                        continue;
                    }
                    let matches_other = other_spec
                        .registry_names
                        .iter()
                        .any(|r| r.trim().eq_ignore_ascii_case(&prod_norm));
                    if matches_other && !matches_cur {
                        return Err(format!(
                            "XÁC THỰC BẢO MẬT THẤT BẠI: Gói cài đặt '{}' được ký cho kênh '{}', không khớp kênh '{}' đang chọn!",
                            signed_file, other_ch, ch
                        ));
                    }
                }

                // Lớp chắn bổ sung cho kênh RTX vs Standard nếu chưa khai báo registry_names riêng
                let has_rtx_channel = t
                    .updater
                    .channels
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("rtx"));
                if has_rtx_channel {
                    let file_has_rtx = prod_norm.split_whitespace().any(|w| w == "rtx")
                        || signed_file.to_lowercase().contains("rtx");
                    if ch.eq_ignore_ascii_case("rtx") && !file_has_rtx {
                        return Err(format!(
                            "XÁC THỰC BẢO MẬT THẤT BẠI: Đang chọn kênh RTX nhưng tệp ký số '{}' là bản Standard!",
                            signed_file
                        ));
                    }
                    if !ch.eq_ignore_ascii_case("rtx") && file_has_rtx {
                        return Err(format!(
                            "XÁC THỰC BẢO MẬT THẤT BẠI: Đang chọn kênh '{}' nhưng tệp ký số '{}' lại là bản RTX!",
                            ch, signed_file
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

fn emit_progress(app: &AppHandle, evt: InstallProgressEvent) {
    let _ = app.emit("launcher://install-progress", evt);
}

fn format_reqwest_error(e: &reqwest::Error) -> String {
    use std::error::Error as _;
    if e.is_timeout() {
        return format!("Quá thời gian chờ mạng khi đang tải dữ liệu ({e})");
    }
    if let Some(src) = e.source() {
        format!("{e} ({src})")
    } else {
        e.to_string()
    }
}

fn is_path_inside_tool_repos(exe_path: &Path, tool: &ToolManifest) -> bool {
    if path_is_within_dir(exe_path, Path::new(&tool.git.repo_path)) {
        return true;
    }
    tool.git
        .extra_repos
        .iter()
        .any(|er| path_is_within_dir(exe_path, Path::new(&er.repo_path)))
}

fn read_exe_sig(path: &Path) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((mtime, meta.len()))
}

pub async fn execute_protected_install(
    app: &AppHandle,
    client: &reqwest::Client,
    tool: &ToolManifest,
    channel_key: &str,
    pubkey_b64: &str,
    remote: &RemoteReleaseInfo,
    vault_root: &Path,
    max_backup_gens: usize,
    previous_ledger: Option<&ToolLedgerEntry>,
) -> Result<(InstallResultDto, ToolLedgerEntry), String> {
    if !remote.download_url.trim().starts_with("https://") {
        return Err(format!(
            "Từ chối tải gói cài đặt qua giao thức không mã hóa: '{}'.",
            remote.download_url
        ));
    }

    emit_progress(
        app,
        InstallProgressEvent {
            tool_id: tool.id.clone(),
            tool_name: tool.name.clone(),
            phase: "preflight".to_string(),
            percent: Some(5),
            downloaded_bytes: 0,
            total_bytes: None,
            message: format!(
                "Đang kiểm tra tiến trình sống và cổng dịch vụ của {}...",
                tool.name
            ),
        },
    );

    // Bước 1: Kiểm tra nhanh tiến trình & cổng trên luồng blocking để không nghẽn Tokio
    {
        let tool_cl = tool.clone();
        let ch_cl = channel_key.to_string();
        tokio::task::spawn_blocking(move || GuardianTransaction::preflight_check(&tool_cl, &ch_cl))
            .await
            .map_err(|e| format!("Lỗi luồng kiểm tra tiền cài đặt: {e}"))??;
    }

    let staging_dir = tempfile::Builder::new()
        .prefix(&format!("selorson-{}-", tool.id))
        .tempdir()
        .map_err(|e| format!("Không tạo được thư mục tải tạm: {e}"))?;

    let part_path = staging_dir.path().join(format!(
        "{}_{}_setup.exe.part",
        tool.id, remote.normalized_version
    ));
    let final_installer_path = staging_dir.path().join(format!(
        "{}_{}_setup.exe",
        tool.id, remote.normalized_version
    ));

    emit_progress(
        app,
        InstallProgressEvent {
            tool_id: tool.id.clone(),
            tool_name: tool.name.clone(),
            phase: "downloading".to_string(),
            percent: Some(10),
            downloaded_bytes: 0,
            total_bytes: None,
            message: format!(
                "Đang tải bộ cài {} v{} từ GitHub Releases...",
                tool.name, remote.normalized_version
            ),
        },
    );

    // Bước 2: Tải gói cài đặt về bộ nhớ (có trần bảo vệ MAX_INSTALLER_BYTES) và kiểm tra chữ ký Ed25519 TRƯỚC KHI ghi .exe
    let resp = client
        .get(&remote.download_url)
        .send()
        .await
        .map_err(|e| {
            format!(
                "Lỗi mạng khi tải bộ cài {}: {}",
                tool.name,
                format_reqwest_error(&e)
            )
        })?;

    if !resp.status().is_success() {
        return Err(format!(
            "Không tải được bộ cài (HTTP {}) từ '{}'.",
            resp.status().as_u16(),
            remote.download_url
        ));
    }

    let total_bytes = resp.content_length();
    if let Some(cl) = total_bytes {
        if cl > MAX_INSTALLER_BYTES {
            return Err(format!(
                "Từ chối tải gói cài đặt vượt trần an toàn bộ nhớ ({:.1} MB > {:.1} MB).",
                cl as f64 / 1_048_576.0,
                MAX_INSTALLER_BYTES as f64 / 1_048_576.0
            ));
        }
    }

    let mut stream = resp.bytes_stream();
    let mut downloaded_bytes: u64 = 0;
    let mut all_bytes: Vec<u8> =
        Vec::with_capacity(total_bytes.unwrap_or(32 * 1024 * 1024).min(64 * 1024 * 1024) as usize);
    let mut last_emit = Instant::now();

    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.map_err(|e| {
            format!(
                "Gián đoạn luồng tải {}: {}",
                tool.name,
                format_reqwest_error(&e)
            )
        })?;
        downloaded_bytes = downloaded_bytes.saturating_add(chunk.len() as u64);
        if downloaded_bytes > MAX_INSTALLER_BYTES {
            return Err(format!(
                "Luồng tải bộ cài {} vượt quá trần an toàn {:.1} MB — đã ngắt kết nối bảo vệ RAM!",
                tool.name,
                MAX_INSTALLER_BYTES as f64 / 1_048_576.0
            ));
        }
        all_bytes.extend_from_slice(&chunk);

        if last_emit.elapsed().as_millis() >= 110 {
            let pct = total_bytes.map(|tot| {
                if tot > 0 {
                    (10 + ((downloaded_bytes.saturating_mul(62)) / tot)).min(72) as u8
                } else {
                    40
                }
            });
            emit_progress(
                app,
                InstallProgressEvent {
                    tool_id: tool.id.clone(),
                    tool_name: tool.name.clone(),
                    phase: "downloading".to_string(),
                    percent: pct,
                    downloaded_bytes,
                    total_bytes,
                    message: format!(
                        "Đang tải {} v{} ({:.1} MB{})...",
                        tool.name,
                        remote.normalized_version,
                        downloaded_bytes as f64 / 1_048_576.0,
                        total_bytes
                            .map(|t| format!(" / {:.1} MB", t as f64 / 1_048_576.0))
                            .unwrap_or_default()
                    ),
                },
            );
            last_emit = Instant::now();
        }
    }

    emit_progress(
        app,
        InstallProgressEvent {
            tool_id: tool.id.clone(),
            tool_name: tool.name.clone(),
            phase: "verifying_signature".to_string(),
            percent: Some(76),
            downloaded_bytes,
            total_bytes: Some(downloaded_bytes),
            message: format!(
                "Đang xác thực chữ ký số Ed25519 Minisign cho {} v{}...",
                tool.name, remote.normalized_version
            ),
        },
    );

    // Bước 3: Xác thực chữ ký Ed25519 (kèm file: & kênh) + ghi tệp bộ cài ra đĩa trên spawn_blocking
    {
        let sig_cl = remote.signature.clone();
        let pub_cl = pubkey_b64.to_string();
        let exp_ver = remote.normalized_version.clone();
        let tag_pref = tool.git.tag_prefix.clone();
        let tool_for_sig = tool.clone();
        let ch_for_sig = channel_key.to_string();
        let part_cl = part_path.clone();
        let final_cl = final_installer_path.clone();

        tokio::task::spawn_blocking(move || -> Result<(), String> {
            verify_ed25519_package(
                &all_bytes,
                &sig_cl,
                &pub_cl,
                &exp_ver,
                &tag_pref,
                Some(&tool_for_sig),
                Some(&ch_for_sig),
            )?;
            {
                let mut f = std::fs::File::create(&part_cl)
                    .map_err(|e| format!("Không ghi được bộ cài tạm: {e}"))?;
                f.write_all(&all_bytes)
                    .map_err(|e| format!("Lỗi ghi dữ liệu bộ cài: {e}"))?;
                f.sync_all()
                    .map_err(|e| format!("Lỗi đồng bộ đĩa bộ cài: {e}"))?;
            }
            drop(all_bytes);
            std::fs::rename(&part_cl, &final_cl)
                .map_err(|e| format!("Không chuyển đổi được tệp cài đặt: {e}"))?;
            Ok(())
        })
        .await
        .map_err(|e| format!("Lỗi luồng xác thực/ghi bộ cài: {e}"))??;
    }

    emit_progress(
        app,
        InstallProgressEvent {
            tool_id: tool.id.clone(),
            tool_name: tool.name.clone(),
            phase: "vault_lock".to_string(),
            percent: Some(82),
            downloaded_bytes,
            total_bytes: Some(downloaded_bytes),
            message: format!(
                "Chữ ký Ed25519 hợp lệ! Đang khóa kho bảo hộ Guardian Vault cho {}...",
                tool.name
            ),
        },
    );

    // Bước 4: Mở giao dịch Guardian Vault trên spawn_blocking (băm SHA-256 & sao lưu cô lập tệp lớn không chặn UI)
    let (guard, pre_exe_pathbuf, pre_exe_sig) = {
        let tool_cl = tool.clone();
        let vroot_cl = vault_root.to_path_buf();
        let ch_cl = channel_key.to_string();
        let prev_ledger_cl = previous_ledger.cloned();

        tokio::task::spawn_blocking(move || -> Result<_, String> {
            let procs = capture_running_processes();
            let regs = scan_uninstall_registry();
            let pre_discovered = discover_tool_local(
                &tool_cl,
                &ch_cl,
                &procs,
                &regs,
                prev_ledger_cl.as_ref(),
                None,
            );
            let pre_exe = pre_discovered.active_exe_path.as_deref().map(PathBuf::from);
            let pre_sig = pre_exe.as_deref().and_then(read_exe_sig);

            let g = GuardianTransaction::begin(
                &tool_cl,
                &vroot_cl,
                max_backup_gens,
                &ch_cl,
                pre_exe.as_deref(),
                pre_discovered.installed_version.as_deref(),
            )?;
            Ok((g, pre_exe, pre_sig))
        })
        .await
        .map_err(|e| format!("Lỗi luồng khởi tạo Guardian Vault: {e}"))??
    };

    let nsis_outcome: Result<(), String> = async {
        emit_progress(
            app,
            InstallProgressEvent {
                tool_id: tool.id.clone(),
                tool_name: tool.name.clone(),
                phase: "installing_nsis".to_string(),
                percent: Some(88),
                downloaded_bytes,
                total_bytes: Some(downloaded_bytes),
                message: format!(
                    "Đang chạy trình cài đặt NSIS cho {} v{}...",
                    tool.name, remote.normalized_version
                ),
            },
        );

        let mut cmd = Command::new(&final_installer_path);
        cmd.args(["/P", "/UPDATE"]);
        cmd.kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Không khởi chạy được bộ cài NSIS: {e}"))?;

        let status =
            match tokio::time::timeout(Duration::from_secs(NSIS_TIMEOUT_SECS), child.wait()).await {
                Ok(wait_res) => {
                    wait_res.map_err(|e| format!("Lỗi chờ tiến trình NSIS kết thúc: {e}"))?
                }
                Err(_) => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    return Err(format!(
                        "Trình cài đặt NSIS của {} bị treo quá {} giây (có thể do tệp đích đang bị khóa bởi tiến trình phụ). Đã tự động hủy để bảo vệ hệ thống!",
                        tool.name, NSIS_TIMEOUT_SECS
                    ));
                }
            };

        if !status.success() {
            return Err(format!(
                "Trình cài đặt NSIS kết thúc với mã lỗi {:?}.",
                status.code()
            ));
        }

        Ok(())
    }
    .await;

    emit_progress(
        app,
        InstallProgressEvent {
            tool_id: tool.id.clone(),
            tool_name: tool.name.clone(),
            phase: "restoring_vault".to_string(),
            percent: Some(95),
            downloaded_bytes: 0,
            total_bytes: None,
            message: format!(
                "Đang hoàn trả tệp khóa bất biến và hậu kiểm toàn vẹn dữ liệu {}...",
                tool.name
            ),
        },
    );

    // Bước 5 & 6: Hoàn trả immutable_files, hậu kiểm DB, xác thực tệp .exe mới và chốt snapshot trên spawn_blocking
    let tool_cl = tool.clone();
    let ch_cl = channel_key.to_string();
    let rem_norm_ver = remote.normalized_version.clone();

    let (vault_report, exe_str, ledger_entry) =
        tokio::task::spawn_blocking(move || -> Result<_, String> {
            // LUÔN chạy restore_and_verify trước khi kiểm tra nsis_outcome!
            let (mut report, pending_snapshot) = guard.restore_and_verify()?;

            drop(staging_dir);
            nsis_outcome?;

            let procs = capture_running_processes();
            let regs = scan_uninstall_registry();
            let discovered = discover_tool_local(&tool_cl, &ch_cl, &procs, &regs, None, None);

            let exe_s = discovered.active_exe_path.ok_or_else(|| {
                format!(
                    "Trình cài đặt NSIS của {} kết thúc nhưng không tìm thấy tệp thực thi trên đĩa (hãy kiểm tra lại exe_candidates / exe_filename trong manifest).",
                    tool_cl.name
                )
            })?;

            let post_path = Path::new(&exe_s);
            let (post_mtime, post_size) = read_exe_sig(post_path).ok_or_else(|| {
                format!(
                    "Không đọc được thuộc tính tệp thực thi sau cài đặt tại '{}'.",
                    post_path.display()
                )
            })?;

            if is_path_inside_tool_repos(post_path, &tool_cl) {
                let same_path_as_pre = pre_exe_pathbuf
                    .as_deref()
                    .and_then(|pre| {
                        match (std::fs::canonicalize(pre), std::fs::canonicalize(post_path)) {
                            (Ok(a), Ok(b)) => Some(a == b),
                            _ => Some(
                                pre.to_string_lossy()
                                    .eq_ignore_ascii_case(&post_path.to_string_lossy()),
                            ),
                        }
                    })
                    .unwrap_or(false);
                if same_path_as_pre && pre_exe_sig == Some((post_mtime, post_size)) {
                    return Err(format!(
                        "Bộ cài NSIS của {} không sinh ra tệp thực thi mới trong thư mục cài đặt (chỉ tìm thấy bản phát triển cũ tại '{}' không đổi). Đã chặn ghi sổ cái mù!",
                        tool_cl.name,
                        post_path.display()
                    ));
                }
            }

            report.snapshot_dir = pending_snapshot.commit_and_prune();

            let entry = ToolLedgerEntry {
                exe_path: exe_s.clone(),
                exe_size: post_size,
                exe_mtime_secs: post_mtime,
                installed_version: rem_norm_ver,
                channel: ch_cl,
                installed_at_iso: Utc::now().to_rfc3339(),
            };

            Ok((report, exe_s, entry))
        })
        .await
        .map_err(|e| format!("Lỗi luồng hậu kiểm Guardian Vault: {e}"))??;

    emit_progress(
        app,
        InstallProgressEvent {
            tool_id: tool.id.clone(),
            tool_name: tool.name.clone(),
            phase: "completed".to_string(),
            percent: Some(100),
            downloaded_bytes: 0,
            total_bytes: None,
            message: format!(
                "Hoàn tất cài đặt {} v{} an toàn tuyệt đối!",
                tool.name, remote.normalized_version
            ),
        },
    );

    Ok((
        InstallResultDto {
            tool_id: tool.id.clone(),
            installed_version: remote.normalized_version.clone(),
            active_exe_path: Some(exe_str),
            vault_report,
        },
        ledger_entry,
    ))
}

pub fn launch_tool_detached(tool: &ToolManifest, exe_path: &Path) -> Result<(), String> {
    if !exe_path.exists() {
        return Err(format!(
            "Không tìm thấy tệp thực thi của {} tại '{}'.",
            tool.name,
            exe_path.display()
        ));
    }

    let mut cmd = std::process::Command::new(exe_path);
    if !tool.install.launch_args.is_empty() {
        cmd.args(&tool.install.launch_args);
    }
    if let Some(wd) = &tool.install.working_dir {
        let wd_path = Path::new(wd);
        if wd_path.exists() {
            cmd.current_dir(wd_path);
        }
    } else if let Some(parent) = exe_path.parent() {
        cmd.current_dir(parent);
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS (0x00000008) | CREATE_NEW_PROCESS_GROUP (0x00000200)
        cmd.creation_flags(0x00000008 | 0x00000200);
    }

    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("Không mở được {}: {e}", tool.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_or_tampered_ed25519_signatures_immediately() {
        let cowriter_pub = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDkyN0Q2MUM0NEFFOTlGMDMKUldRRG4rbEt4R0Y5a20yTUJtM1RZQlAvSkFjUGo0V3FMdW9sY20wSlU0U09LNGllY3pwZlNtZ28K";
        let fake_sig = STANDARD.encode(
            "untrusted comment: signature from tauri secret key\nRWQDn+lKxGF9km2MBm3TYBP/JAcPj4WqLuolcm0JU4SOK4ieczpfSmgoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\ntrusted comment: timestamp:1700000000\tfile:Co-Writer_1.9.0_x64-setup.exe\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==\n",
        );

        let err = verify_ed25519_package(
            b"MZ_TAMPERED_BINARY",
            &fake_sig,
            cowriter_pub,
            "1.9.0",
            "v",
            None,
            None,
        );
        assert!(err.is_err());
    }

    #[test]
    fn enforces_ed25519_trusted_comment_file_version_pe_header_and_rtx_channel_binding() {
        use crate::manifest::{
            GitSpec, InstallSpec, ProtectionSpec, ReleaseChannelSpec, UpdaterSpec,
        };
        use std::collections::BTreeMap;

        let test_pub = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDA4MDcwNjA1MDQwMzAyMDEKUldRQkFnTUVCUVlIQ0lSTTNlNGgydG1CbkFrYUJQMnpyM0JGL2ZGZ3lOcVhQYk80Z04vbEJTVmgK";
        let sig_rtx_3_0_88 = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRlc3Qga2V5ClJVUUJBZ01FQlFZSENGbE1RSm82SGZGeHpCRWFHUXB3VDUvOFA5MXBpZDY3NlNnY25LWGZlSHJkM2ZKMmh0Unp5MDdQNDRPazVzM0JwRm0xOGJXT2M5RFBDbDY1K3BEam1BWT0KdHJ1c3RlZCBjb21tZW50OiB0aW1lc3RhbXA6MTc5NTcwMDAwMAlmaWxlOk5ldXJvRm9yZ2UgUlRYXzMuMC44OF94NjQtc2V0dXAuZXhlCXZlcnNpb246My4wLjg4CldwcXhib3hSa2FWckp4Y1QyczBYZmRPdldtWnhsdEZIV1ZzcTBNeENWRnFWTEJHRmRwQURpY21lOEhqZDZtV2V5Nks4TlNRRnAzcXdtVGl0N1Vwc0N3PT0K";
        let sig_std_3_0_88 = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRlc3Qga2V5ClJVUUJBZ01FQlFZSENGbE1RSm82SGZGeHpCRWFHUXB3VDUvOFA5MXBpZDY3NlNnY25LWGZlSHJkM2ZKMmh0Unp5MDdQNDRPazVzM0JwRm0xOGJXT2M5RFBDbDY1K3BEam1BWT0KdHJ1c3RlZCBjb21tZW50OiB0aW1lc3RhbXA6MTc5NTcwMDAwMAlmaWxlOk5ldXJvRm9yZ2VfMy4wLjg4X3g2NC1zZXR1cC5leGUJdmVyc2lvbjozLjAuODgKU0xEbzBtdnVNbjZCQi9za0s1TWZuamtvbEp0WWU2aUtHaWdmc3ZEYnpUbVZMcVI4cFh4ZjVMZE5qZWxpOHJKNlFocktOWWlrZ0lZakdnc25CWUQrQVE9PQo=";
        let sig_cowriter_1_8_0_no_ver = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRlc3Qga2V5ClJVUUJBZ01FQlFZSENGbE1RSm82SGZGeHpCRWFHUXB3VDUvOFA5MXBpZDY3NlNnY25LWGZlSHJkM2ZKMmh0Unp5MDdQNDRPazVzM0JwRm0xOGJXT2M5RFBDbDY1K3BEam1BWT0KdHJ1c3RlZCBjb21tZW50OiB0aW1lc3RhbXA6MTc5NTcwMDAwMAlmaWxlOkNvLVdyaXRlcl8xLjguMF94NjQtc2V0dXAuZXhlCmlkclIxZStlYm12YW1EZi9aYTBJdGQwcU05bmFJdkQzTndsa0JKQzRnL3NoOXZsVEtOSm5qQUN2WjNzM0FiaGg2R0k5TmlhbGxqS0sxaXljbkVPeURnPT0K";
        let sig_bad_ver_syntax = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRlc3Qga2V5ClJVUUJBZ01FQlFZSENGbE1RSm82SGZGeHpCRWFHUXB3VDUvOFA5MXBpZDY3NlNnY25LWGZlSHJkM2ZKMmh0Unp5MDdQNDRPazVzM0JwRm0xOGJXT2M5RFBDbDY1K3BEam1BWT0KdHJ1c3RlZCBjb21tZW50OiB0aW1lc3RhbXA6MTc5NTcwMDAwMAlmaWxlOkNvLVdyaXRlcl8xLjkuMF94NjQtc2V0dXAuZXhlCXZlcnNpb246bm90LWEtc2VtdmVyCkZuK2wzczRSdy80MlFUOE5yTjBxWXZHL3J2ZC9PZDZMcTdjdDRzMng0bC9Cc3NsZFl3eGo5Yk1KTVhnWWc2dDZEOThXTVpsNkRvTmJJUWhaTUp5aEJRPT0K";

        let payload = b"MZ_TEST_INSTALLER_BIN";

        let mut channels = BTreeMap::new();
        channels.insert(
            "rtx".to_string(),
            ReleaseChannelSpec {
                label: "RTX".to_string(),
                endpoint: "https://example.com/latest-rtx.json".to_string(),
                pubkey: test_pub.to_string(),
                exe_candidates: vec![r"C:\Fake\NeuroForge RTX\neuroforge.exe".to_string()],
                registry_names: vec!["NeuroForge RTX".to_string()],
            },
        );
        channels.insert(
            "standard".to_string(),
            ReleaseChannelSpec {
                label: "Standard".to_string(),
                endpoint: "https://example.com/latest.json".to_string(),
                pubkey: test_pub.to_string(),
                exe_candidates: vec![r"C:\Fake\NeuroForge\neuroforge.exe".to_string()],
                registry_names: vec!["NeuroForge".to_string()],
            },
        );
        let nf_tool = ToolManifest {
            id: "neuroforge".to_string(),
            order: 5,
            name: "NeuroForge RTX".to_string(),
            subtitle: String::new(),
            category: String::new(),
            accent_color: "#EF4444".to_string(),
            icon: None,
            install: InstallSpec {
                installer_kind: "tauri-nsis".to_string(),
                exe_candidates: vec![r"C:\Fake\NeuroForge RTX\neuroforge.exe".to_string()],
                registry_names: vec!["NeuroForge RTX".to_string(), "NeuroForge".to_string()],
                exe_filename: "neuroforge.exe".to_string(),
                launch_args: vec![],
                working_dir: None,
            },
            updater: UpdaterSpec {
                default_channel: "rtx".to_string(),
                channels,
            },
            protection: ProtectionSpec::default(),
            git: GitSpec {
                repo_path: r"C:\Fake\Repo".to_string(),
                watch_paths: vec!["src".to_string()],
                extra_repos: vec![],
                tag_prefix: "v".to_string(),
                hot_swap_hint: None,
            },
        };

        // 1. Khớp hoàn toàn chữ ký + kênh RTX + phiên bản 3.0.88 -> Ok
        assert!(verify_ed25519_package(
            payload,
            sig_rtx_3_0_88,
            test_pub,
            "3.0.88",
            "v",
            Some(&nf_tool),
            Some("rtx")
        )
        .is_ok());

        // 2. Chặn tráo chéo gói Standard (cùng khóa Ed25519!) sang kênh RTX và ngược lại!
        assert!(verify_ed25519_package(
            payload,
            sig_std_3_0_88,
            test_pub,
            "3.0.88",
            "v",
            Some(&nf_tool),
            Some("rtx")
        )
        .is_err());
        assert!(verify_ed25519_package(
            payload,
            sig_rtx_3_0_88,
            test_pub,
            "3.0.88",
            "v",
            Some(&nf_tool),
            Some("standard")
        )
        .is_err());

        // 3. Chặn phát lại bản cũ qua `file:` kể cả khi chữ ký không có trường `version:` (Co-Writer 1.8.0 tráo vào 1.9.1)
        assert!(verify_ed25519_package(
            payload,
            sig_cowriter_1_8_0_no_ver,
            test_pub,
            "1.9.1",
            "v",
            None,
            None
        )
        .is_err());

        // 4. Chặn trường `version:` sai cú pháp thay vì bỏ qua êm
        assert!(verify_ed25519_package(
            payload,
            sig_bad_ver_syntax,
            test_pub,
            "1.9.0",
            "v",
            None,
            None
        )
        .is_err());

        // 5. Chặn tệp không có header PE "MZ"
        assert!(verify_ed25519_package(
            b"NOT_A_PE_FILE",
            sig_rtx_3_0_88,
            test_pub,
            "3.0.88",
            "v",
            None,
            None
        )
        .is_err());
    }
}
