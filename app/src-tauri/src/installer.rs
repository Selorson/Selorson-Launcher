use crate::discovery::{
    capture_running_processes, discover_tool_local, normalize_semver, scan_uninstall_registry,
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
use std::path::Path;
use std::time::Instant;
use tauri::{AppHandle, Emitter};
use tokio::process::Command;

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

fn extract_signed_version_from_trusted_comment(trusted_comment: &str) -> Option<&str> {
    for part in trusted_comment.split('\t') {
        if let Some(v) = part
            .strip_prefix("v:")
            .or_else(|| part.strip_prefix("version:"))
        {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

pub fn verify_ed25519_package(
    bytes: &[u8],
    signature_b64: &str,
    pubkey_b64: &str,
    expected_version: &str,
    tag_prefix: &str,
) -> Result<(), String> {
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

    // Nếu trusted_comment chứa thông tin phiên bản ký, đối chiếu chống tấn công hạ cấp / tráo bản
    if let Some(signed_ver_raw) =
        extract_signed_version_from_trusted_comment(signature.trusted_comment())
    {
        let sv = normalize_semver(signed_ver_raw, Some(tag_prefix));
        let ev = normalize_semver(expected_version, Some(tag_prefix));
        if let (Some(s), Some(e)) = (sv, ev) {
            if s != e {
                return Err(format!(
                    "XÁC THỰC BẢO MẬT THẤT BẠI: Phiên bản trong chữ ký ({s}) khác với phiên bản công bố trong latest.json ({e})."
                ));
            }
        }
    }

    Ok(())
}

fn emit_progress(app: &AppHandle, evt: InstallProgressEvent) {
    let _ = app.emit("launcher://install-progress", evt);
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
) -> Result<(InstallResultDto, Option<ToolLedgerEntry>), String> {
    emit_progress(
        app,
        InstallProgressEvent {
            tool_id: tool.id.clone(),
            tool_name: tool.name.clone(),
            phase: "vault_lock".to_string(),
            percent: Some(5),
            downloaded_bytes: 0,
            total_bytes: None,
            message: format!(
                "Đang kiểm tra tiến trình sống và khóa kho bảo hộ Guardian Vault cho {}...",
                tool.name
            ),
        },
    );

    // Bước 1: Mở giao dịch Guardian Vault (kiểm tra khóa, cất giữ cowriter-core.exe & sao lưu DB)
    let guard = GuardianTransaction::begin(tool, vault_root, max_backup_gens)?;

    // Bọc phần tải + xác thực + chạy NSIS để đảm bảo LUÔN khôi phục Vault dù bước nào lỗi
    let install_outcome: Result<(), String> = async {
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

        let resp = client
            .get(&remote.download_url)
            .send()
            .await
            .map_err(|e| format!("Lỗi mạng khi tải bộ cài {}: {e}", tool.name))?;

        if !resp.status().is_success() {
            return Err(format!(
                "Không tải được bộ cài (HTTP {}) từ '{}'.",
                resp.status().as_u16(),
                remote.download_url
            ));
        }

        let total_bytes = resp.content_length();
        let mut stream = resp.bytes_stream();
        let mut downloaded_bytes: u64 = 0;
        let mut all_bytes: Vec<u8> =
            Vec::with_capacity(total_bytes.unwrap_or(32 * 1024 * 1024) as usize);
        let mut last_emit = Instant::now();

        while let Some(chunk_res) = stream.next().await {
            let chunk =
                chunk_res.map_err(|e| format!("Gián đoạn luồng tải {}: {e}", tool.name))?;
            downloaded_bytes += chunk.len() as u64;
            all_bytes.extend_from_slice(&chunk);

            if last_emit.elapsed().as_millis() >= 110 {
                let pct = total_bytes.map(|tot| {
                    if tot > 0 {
                        (10 + ((downloaded_bytes.saturating_mul(65)) / tot)).min(75) as u8
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
                percent: Some(78),
                downloaded_bytes,
                total_bytes: Some(downloaded_bytes),
                message: format!(
                    "Đang xác thực chữ ký số Ed25519 Minisign cho {} v{}...",
                    tool.name, remote.normalized_version
                ),
            },
        );

        // Bước 3: Cổng bảo mật Ed25519 TRƯỚC KHI ghi tệp .exe thực thi ra đĩa
        verify_ed25519_package(
            &all_bytes,
            &remote.signature,
            pubkey_b64,
            &remote.normalized_version,
            &tool.git.tag_prefix,
        )?;

        {
            let mut f = std::fs::File::create(&part_path)
                .map_err(|e| format!("Không ghi được bộ cài tạm: {e}"))?;
            f.write_all(&all_bytes)
                .map_err(|e| format!("Lỗi ghi dữ liệu bộ cài: {e}"))?;
            f.sync_all()
                .map_err(|e| format!("Lỗi đồng bộ đĩa bộ cài: {e}"))?;
        }
        std::fs::rename(&part_path, &final_installer_path)
            .map_err(|e| format!("Không chuyển đổi được tệp cài đặt: {e}"))?;

        emit_progress(
            app,
            InstallProgressEvent {
                tool_id: tool.id.clone(),
                tool_name: tool.name.clone(),
                phase: "installing_nsis".to_string(),
                percent: Some(85),
                downloaded_bytes,
                total_bytes: Some(downloaded_bytes),
                message: format!(
                    "Chữ ký Ed25519 hợp lệ! Đang chạy trình cài đặt NSIS cho {} v{}...",
                    tool.name, remote.normalized_version
                ),
            },
        );

        // Bước 4: Chạy trình cài đặt NSIS ở chế độ thụ động (/P /UPDATE) chuẩn Tauri 2
        let mut cmd = Command::new(&final_installer_path);
        cmd.args(["/P", "/UPDATE"]);
        let status = cmd
            .status()
            .await
            .map_err(|e| format!("Không khởi chạy được bộ cài NSIS: {e}"))?;

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

    // Bước 5: LUÔN hoàn trả immutable_files (như cowriter-core.exe) & kiểm tra DB
    let vault_report = guard.restore_and_verify()?;

    // Nếu bước tải/ký/NSIS bên trên thất bại thì trả lỗi sau khi đã bảo toàn xong Vault
    install_outcome?;

    // Bước 6: Quét lại đường dẫn .exe vừa cài để ghi sổ cái ledger
    let procs = capture_running_processes();
    let regs = scan_uninstall_registry();
    let discovered = discover_tool_local(tool, &procs, &regs, None);

    let ledger_entry = discovered.active_exe_path.as_ref().and_then(|exe_str| {
        let p = Path::new(exe_str);
        let meta = std::fs::metadata(p).ok()?;
        let mtime = meta
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        Some(ToolLedgerEntry {
            exe_path: exe_str.clone(),
            exe_size: meta.len(),
            exe_mtime_secs: mtime,
            installed_version: remote.normalized_version.clone(),
            channel: channel_key.to_string(),
            installed_at_iso: Utc::now().to_rfc3339(),
        })
    });

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
            active_exe_path: discovered.active_exe_path,
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
            "untrusted comment: signature from tauri secret key\nRWQDn+lKxGF9km2MBm3TYBP/JAcPj4WqLuolcm0JU4SOK4ieczpfSmgoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\ntrusted comment: timestamp:1700000000\tfile:test.exe\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==\n",
        );

        let err = verify_ed25519_package(b"TAMPERED_BINARY", &fake_sig, cowriter_pub, "1.9.0", "v");
        assert!(err.is_err());
    }
}
