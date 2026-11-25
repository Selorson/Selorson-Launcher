use crate::discovery::{capture_running_processes, probe_tcp_port};
use crate::manifest::ToolManifest;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
struct StagedImmutableFile {
    original_path: PathBuf,
    staged_path: PathBuf,
    sha256_hex: String,
    size_bytes: u64,
}

#[derive(Debug, Clone)]
struct BackedUpDataFile {
    original_path: PathBuf,
    backup_path: PathBuf,
    size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultVerificationReport {
    pub restored_immutable_files: Vec<String>,
    pub verified_backup_files: Vec<String>,
    pub verified_external_paths: Vec<String>,
    pub snapshot_dir: Option<String>,
}

pub struct GuardianTransaction {
    tool_name: String,
    txn_dir: PathBuf,
    snapshot_dir: Option<PathBuf>,
    staged_immutables: Vec<StagedImmutableFile>,
    backed_up_files: Vec<BackedUpDataFile>,
    preexisting_externals: Vec<PathBuf>,
}

pub fn compute_sha256(path: &Path) -> Result<(String, u64), String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Không mở được tệp '{}' để băm SHA-256: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("Lỗi đọc tệp '{}': {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    let hex = format!("{:x}", hasher.finalize());
    Ok((hex, total))
}

fn isolated_vault_copy(src: &Path, dst: &Path) -> Result<(), String> {
    if dst.exists() {
        let _ = fs::remove_file(dst);
    }
    // BẮT BUỘC dùng fs::copy (tạo luồng dữ liệu độc lập trên NTFS) thay vì hard_link:
    // Nếu NSIS mở tệp đích với cờ CREATE_ALWAYS / TRUNCATE_EXISTING tại chỗ, hard_link dùng chung inode sẽ bị ghi đè theo!
    fs::copy(src, dst)
        .map(|_| ())
        .map_err(|e| format!("Không sao lưu cô lập được '{}' sang '{}': {e}", src.display(), dst.display()))
}

fn prune_old_snapshots(tool_vault_dir: &Path, keep: usize) {
    let Ok(entries) = fs::read_dir(tool_vault_dir) else {
        return;
    };
    let mut snaps: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("snapshot-"))
        })
        .collect();
    snaps.sort();
    if snaps.len() > keep {
        let remove_cnt = snaps.len() - keep;
        for old in snaps.into_iter().take(remove_cnt) {
            let _ = fs::remove_dir_all(old);
        }
    }
}

impl GuardianTransaction {
    /// Kiểm tra nhanh tiến trình sống & cổng dịch vụ trước khi tải bộ cài dung lượng lớn,
    /// tránh tốn băng thông hoặc sinh bản sao lưu thừa nếu công cụ đang mở.
    pub fn preflight_check(tool: &ToolManifest) -> Result<(), String> {
        let running = capture_running_processes();
        let mut active_procs = Vec::new();
        for p in &tool.protection.running_processes {
            if running.contains(&p.to_lowercase()) {
                active_procs.push(p.clone());
            }
        }
        if !active_procs.is_empty() {
            return Err(format!(
                "Không thể cập nhật khi {} đang chạy ({}). Hãy đóng ứng dụng để nhả khóa cơ sở dữ liệu / sidecar trước khi nâng cấp.",
                tool.name,
                active_procs.join(", ")
            ));
        }

        for hp in &tool.protection.health_ports {
            if hp.block_update_when_open && probe_tcp_port(hp.port) {
                return Err(format!(
                    "Cổng dịch vụ {} đang hoạt động. Hãy dừng tác vụ đang chạy trước khi cập nhật {}.",
                    hp.label, tool.name
                ));
            }
        }

        Ok(())
    }

    /// Khởi tạo giao dịch bảo hộ ngay trước khi chạy trình cài đặt NSIS:
    /// 1. Từ chối ngay nếu tiến trình của công cụ hoặc sidecar đang chạy / cổng bảo vệ đang mở.
    /// 2. Khóa bất biến mọi tệp trong `immutable_files` (VD: cowriter-core.exe) kèm mã băm SHA-256.
    /// 3. Tạo bản chụp lăn (rolling snapshot) cho DB SQLite & tệp khóa bảo mật.
    pub fn begin(
        tool: &ToolManifest,
        vault_root: &Path,
        max_backup_generations: usize,
    ) -> Result<Self, String> {
        Self::preflight_check(tool)?;

        let stamp = Utc::now().format("%Y%m%d-%H%M%S-%3f").to_string();
        let tool_vault_dir = vault_root.join(&tool.id);
        let txn_dir = tool_vault_dir.join(format!("txn-{stamp}"));
        let imm_dir = txn_dir.join("immutable");
        fs::create_dir_all(&imm_dir).map_err(|e| {
            format!(
                "Không tạo được kho bảo hộ Guardian Vault tại '{}': {e}",
                imm_dir.display()
            )
        })?;

        let mut staged_immutables = Vec::new();
        for (idx, imm_str) in tool.protection.immutable_files.iter().enumerate() {
            let orig = PathBuf::from(imm_str);
            if orig.exists() && orig.is_file() {
                let (sha256_hex, size_bytes) = compute_sha256(&orig)?;
                let fname = orig
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("locked.bin");
                let staged_path = imm_dir.join(format!("{idx}_{fname}.locked"));
                isolated_vault_copy(&orig, &staged_path)?;
                staged_immutables.push(StagedImmutableFile {
                    original_path: orig,
                    staged_path,
                    sha256_hex,
                    size_bytes,
                });
            }
        }

        let mut backed_up_files = Vec::new();
        let existing_backups: Vec<PathBuf> = tool
            .protection
            .backup_files
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists() && p.is_file())
            .collect();

        let snapshot_dir = if !existing_backups.is_empty() {
            let sdir = tool_vault_dir.join(format!("snapshot-{stamp}"));
            fs::create_dir_all(&sdir).map_err(|e| {
                format!(
                    "Không tạo được thư mục sao lưu DB tại '{}': {e}",
                    sdir.display()
                )
            })?;
            for (idx, orig) in existing_backups.into_iter().enumerate() {
                let size_bytes = fs::metadata(&orig).map(|m| m.len()).unwrap_or(0);
                let fname = orig
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("data.bak");
                let bpath = sdir.join(format!("{idx}_{fname}"));
                fs::copy(&orig, &bpath).map_err(|e| {
                    format!(
                        "Không sao lưu được tệp dữ liệu quan trọng '{}': {e}",
                        orig.display()
                    )
                })?;
                backed_up_files.push(BackedUpDataFile {
                    original_path: orig,
                    backup_path: bpath,
                    size_bytes,
                });
            }
            prune_old_snapshots(&tool_vault_dir, max_backup_generations.max(1));
            Some(sdir)
        } else {
            None
        };

        let preexisting_externals: Vec<PathBuf> = tool
            .protection
            .verify_external_paths
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect();

        Ok(Self {
            tool_name: tool.name.clone(),
            txn_dir,
            snapshot_dir,
            staged_immutables,
            backed_up_files,
            preexisting_externals,
        })
    }

    /// Thực thi ngay sau khi trình cài đặt NSIS kết thúc (kể cả thành công hay lỗi)
    /// để khôi phục 100% các tệp bất biến (như cowriter-core.exe) và hậu kiểm toàn vẹn DB.
    pub fn restore_and_verify(self) -> Result<VaultVerificationReport, String> {
        let mut restored_immutable_files = Vec::new();

        for item in &self.staged_immutables {
            if let Some(parent) = item.original_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            // Phục hồi nguyên tử thông qua tệp tạm cùng thư mục rồi đổi tên đè lên bản do NSIS giải nén
            let restore_tmp = item.original_path.with_extension("guardian_restore_tmp");
            fs::copy(&item.staged_path, &restore_tmp).map_err(|e| {
                format!(
                    "Không chép trả tệp bất biến '{}' từ Guardian Vault (bản gốc vẫn an toàn tại '{}'): {e}",
                    item.original_path.display(),
                    item.staged_path.display()
                )
            })?;
            if item.original_path.exists() {
                let _ = fs::remove_file(&item.original_path);
            }
            fs::rename(&restore_tmp, &item.original_path).map_err(|e| {
                format!(
                    "Không hoàn trả được tệp bất biến '{}' (bản gốc vẫn an toàn tại '{}'): {e}",
                    item.original_path.display(),
                    item.staged_path.display()
                )
            })?;

            let (post_sha, post_size) = compute_sha256(&item.original_path)?;
            if post_sha != item.sha256_hex || post_size != item.size_bytes {
                return Err(format!(
                    "CẢNH BÁO BẢO HỘ: SHA-256 sau khôi phục của '{}' không khớp bản gốc ({} != {}). Bản gốc vẫn được giữ tại '{}'.",
                    item.original_path.display(),
                    post_sha,
                    item.sha256_hex,
                    item.staged_path.display()
                ));
            }
            restored_immutable_files.push(item.original_path.to_string_lossy().to_string());
        }

        let mut verified_backup_files = Vec::new();
        for bf in &self.backed_up_files {
            let fname_low = bf
                .original_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            let is_transient_wal = fname_low.ends_with("-wal") || fname_low.ends_with("-shm");

            let intact = match fs::metadata(&bf.original_path) {
                Ok(m) if m.is_file() => bf.size_bytes == 0 || m.len() > 0,
                _ => false,
            };

            if !intact && !is_transient_wal {
                // Nếu trình cài đặt vô tình xóa hoặc làm rỗng DB/khóa -> phục hồi ngay từ bản sao lưu vừa chụp!
                fs::copy(&bf.backup_path, &bf.original_path).map_err(|e| {
                    format!(
                        "Tệp dữ liệu '{}' bị biến đổi khi cài {} và không tự khôi phục được (bản sao lưu tại '{}'): {e}",
                        bf.original_path.display(),
                        self.tool_name,
                        bf.backup_path.display()
                    )
                })?;
            }
            verified_backup_files.push(bf.original_path.to_string_lossy().to_string());
        }

        let mut verified_external_paths = Vec::new();
        for ext in &self.preexisting_externals {
            if !ext.exists() {
                return Err(format!(
                    "Đường dẫn ngoại vi '{}' bị mất sau khi cập nhật {}!",
                    ext.display(),
                    self.tool_name
                ));
            }
            verified_external_paths.push(ext.to_string_lossy().to_string());
        }

        // Dọn thư mục giao dịch tạm sau khi mọi SHA-256 đã khớp 100% (giữ nguyên thư mục snapshot-*)
        let _ = fs::remove_dir_all(&self.txn_dir);

        Ok(VaultVerificationReport {
            restored_immutable_files,
            verified_backup_files,
            verified_external_paths,
            snapshot_dir: self
                .snapshot_dir
                .map(|p| p.to_string_lossy().to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        GitSpec, HealthPortSpec, InstallSpec, ProtectionSpec, UpdaterSpec,
    };
    use std::collections::BTreeMap;
    use std::net::TcpListener;
    use tempfile::tempdir;

    fn mock_cowriter_manifest(app_dir: &Path, port: Option<u16>) -> ToolManifest {
        ToolManifest {
            id: "cowriter".to_string(),
            order: 1,
            name: "Co-Writer".to_string(),
            subtitle: String::new(),
            category: String::new(),
            accent_color: "#F59E0B".to_string(),
            icon: None,
            install: InstallSpec {
                installer_kind: "tauri-nsis".to_string(),
                exe_candidates: vec![app_dir.join("cowriter.exe").to_string_lossy().to_string()],
                registry_names: vec![],
                exe_filename: "cowriter.exe".to_string(),
                launch_args: vec![],
                working_dir: None,
            },
            updater: UpdaterSpec {
                default_channel: "stable".to_string(),
                channels: BTreeMap::new(),
            },
            protection: ProtectionSpec {
                running_processes: vec!["__nonexistent_process_xyz__.exe".to_string()],
                health_ports: port
                    .map(|p| {
                        vec![HealthPortSpec {
                            port: p,
                            label: format!("Test Port (:{p})"),
                            block_update_when_open: true,
                        }]
                    })
                    .unwrap_or_default(),
                immutable_files: vec![
                    app_dir
                        .join("cowriter-core.exe")
                        .to_string_lossy()
                        .to_string(),
                ],
                backup_files: vec![
                    app_dir.join("co_writer.db").to_string_lossy().to_string(),
                    app_dir.join("master.key").to_string_lossy().to_string(),
                ],
                verify_external_paths: vec![],
            },
            git: GitSpec {
                repo_path: app_dir.to_string_lossy().to_string(),
                watch_paths: vec!["app".to_string()],
                tag_prefix: "v".to_string(),
                hot_swap_hint: None,
            },
        }
    }

    #[test]
    fn restores_cowriter_core_sha256_even_when_installer_overwrites_it_and_protects_db() {
        let tmp = tempdir().unwrap();
        let app_dir = tmp.path().join("Co-Writer");
        let vault_root = tmp.path().join("vault");
        fs::create_dir_all(&app_dir).unwrap();

        let original_sidecar = b"SACRED_COWRITER_CORE_BINARY_227MB_AUTHOR_EDITION_DO_NOT_TOUCH";
        let original_db = b"SQLite format 3\0_AKUNALIA_WORLD_BIBLE_CANON_DATA";
        let original_key = b"MASTER_SECRET_KEY_44_BYTES";

        let sidecar_path = app_dir.join("cowriter-core.exe");
        let db_path = app_dir.join("co_writer.db");
        let key_path = app_dir.join("master.key");
        let exe_path = app_dir.join("cowriter.exe");

        fs::write(&sidecar_path, original_sidecar).unwrap();
        fs::write(&db_path, original_db).unwrap();
        fs::write(&key_path, original_key).unwrap();
        fs::write(&exe_path, b"OLD_COWRITER_1_8_0").unwrap();

        let (expected_sha, _) = compute_sha256(&sidecar_path).unwrap();
        let tool = mock_cowriter_manifest(&app_dir, None);

        // Bắt đầu giao dịch bảo hộ
        let guard = GuardianTransaction::begin(&tool, &vault_root, 2)
            .expect("GuardianTransaction::begin phải thành công");

        // Giả lập bộ cài NSIS chạy đè cowriter.exe VÀ vô tình ghi đè cowriter-core.exe bằng bản CI khác!
        fs::write(&exe_path, b"NEW_COWRITER_1_9_0").unwrap();
        fs::write(&sidecar_path, b"CI_OVERWRITTEN_WRONG_SIDECAR_PAYLOAD").unwrap();
        // Thậm chí giả lập sự cố xóa nhầm master.key
        fs::remove_file(&key_path).unwrap();

        let report = guard
            .restore_and_verify()
            .expect("Phải khôi phục nguyên trạng cowriter-core.exe và master.key");

        assert_eq!(report.restored_immutable_files.len(), 1);
        let (post_sha, _) = compute_sha256(&sidecar_path).unwrap();
        assert_eq!(post_sha, expected_sha, "cowriter-core.exe bắt buộc giữ nguyên 100% SHA-256!");
        assert_eq!(fs::read(&exe_path).unwrap(), b"NEW_COWRITER_1_9_0");
        assert_eq!(fs::read(&db_path).unwrap(), original_db);
        assert_eq!(fs::read(&key_path).unwrap(), original_key);
    }

    #[test]
    fn blocks_update_immediately_when_health_port_is_busy() {
        let tmp = tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let tool = mock_cowriter_manifest(tmp.path(), Some(port));
        let res = GuardianTransaction::begin(&tool, &tmp.path().join("vault"), 2);
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.contains(&port.to_string()));
    }
}
