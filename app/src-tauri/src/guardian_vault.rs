use crate::discovery::{capture_running_processes, probe_tcp_port};
use crate::ledger::ToolLedgerEntry;
use crate::manifest::ToolManifest;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

const RESTORE_MAX_ATTEMPTS: usize = 15;
const RESTORE_RETRY_DELAY_MS: u64 = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedImmutableFile {
    pub original_path: PathBuf,
    pub staged_path: PathBuf,
    pub sha256_hex: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub was_readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackedUpDataFile {
    pub original_path: PathBuf,
    pub backup_path: PathBuf,
    pub sha256_hex: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub was_readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxnJournal {
    pub schema_version: u32,
    pub tool_id: String,
    pub tool_name: String,
    pub created_at_iso: String,
    pub staged_immutables: Vec<StagedImmutableFile>,
    pub backed_up_files: Vec<BackedUpDataFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFileEntry {
    pub role: String, // "exe" | "data"
    pub backup_file: String,
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    #[serde(default)]
    pub was_readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub schema_version: u32,
    pub tool_id: String,
    pub tool_name: String,
    pub channel: String,
    pub installed_version: Option<String>,
    pub created_at_iso: String,
    pub active_exe_original_path: Option<String>,
    pub files: Vec<SnapshotFileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultVerificationReport {
    pub restored_immutable_files: Vec<String>,
    pub verified_backup_files: Vec<String>,
    pub verified_external_paths: Vec<String>,
    pub snapshot_dir: Option<String>,
}

pub struct PendingSnapshot {
    staging_dir: Option<PathBuf>,
    final_dir: PathBuf,
    tool_vault_dir: PathBuf,
    max_backup_generations: usize,
    committed: bool,
}

impl PendingSnapshot {
    pub fn commit_and_prune(mut self) -> Option<String> {
        let staging = self.staging_dir.take()?;
        if !staging.exists() {
            return None;
        }
        if self.final_dir.exists() {
            let _ = clear_readonly_recursive(&self.final_dir);
            let _ = fs::remove_dir_all(&self.final_dir);
        }
        if fs::rename(&staging, &self.final_dir).is_ok() {
            self.committed = true;
            prune_old_snapshots(&self.tool_vault_dir, self.max_backup_generations.max(1));
            Some(self.final_dir.to_string_lossy().to_string())
        } else {
            let _ = clear_readonly_recursive(&staging);
            let _ = fs::remove_dir_all(&staging);
            None
        }
    }
}

impl Drop for PendingSnapshot {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(staging) = self.staging_dir.take() {
                let _ = clear_readonly_recursive(&staging);
                let _ = fs::remove_dir_all(&staging);
            }
        }
    }
}

pub struct GuardianTransaction {
    tool_name: String,
    tool_vault_dir: PathBuf,
    txn_dir: PathBuf,
    staging_snapshot_dir: Option<PathBuf>,
    final_snapshot_dir: PathBuf,
    max_backup_generations: usize,
    staged_immutables: Vec<StagedImmutableFile>,
    backed_up_files: Vec<BackedUpDataFile>,
    preexisting_externals: Vec<PathBuf>,
    completed: bool,
}

impl Drop for GuardianTransaction {
    fn drop(&mut self) {
        if !self.completed {
            // Phòng vệ tầng sâu khi tác vụ bị hủy ngang / panic trước khi gọi restore_and_verify():
            // Thử khôi phục ngay lập tức; chỉ xóa txn_dir nếu cả tệp bất biến lẫn DB đều khớp 100% SHA-256
            // (nếu đang bị khóa, giữ nguyên txn-journal.json + snapshot-staging-* để lần khởi động sau phục hồi tiếp!)
            let imm_ok = restore_and_verify_immutables(&self.staged_immutables).is_ok();
            let data_ok =
                verify_and_restore_backed_up_data(&self.tool_name, &self.backed_up_files).is_ok();
            if imm_ok && data_ok {
                clear_readonly_recursive(&self.txn_dir);
                let _ = fs::remove_dir_all(&self.txn_dir);
                if let Some(ref sdir) = self.staging_snapshot_dir {
                    clear_readonly_recursive(sdir);
                    let _ = fs::remove_dir_all(sdir);
                }
            }
        }
    }
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

fn clear_readonly_if_needed(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }
}

fn set_readonly_state(path: &Path, readonly: bool) {
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() != readonly {
            perms.set_readonly(readonly);
            let _ = fs::set_permissions(path, perms);
        }
    }
}

fn clear_readonly_recursive(dir: &Path) {
    clear_readonly_if_needed(dir);
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                clear_readonly_recursive(&p);
            } else {
                clear_readonly_if_needed(&p);
            }
        }
    }
}

fn is_retryable_win_lock_error(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(5) | Some(32))
        || err.kind() == std::io::ErrorKind::PermissionDenied
}

fn remove_file_with_retry(path: &Path) -> Result<(), std::io::Error> {
    if !path.exists() {
        return Ok(());
    }
    let mut last_err = None;
    for attempt in 0..RESTORE_MAX_ATTEMPTS {
        clear_readonly_if_needed(path);
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                let retryable = is_retryable_win_lock_error(&e);
                last_err = Some(e);
                if retryable && attempt + 1 < RESTORE_MAX_ATTEMPTS {
                    std::thread::sleep(Duration::from_millis(RESTORE_RETRY_DELAY_MS));
                    continue;
                }
                break;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("Không xóa được tệp đích")))
}

fn isolated_vault_copy(src: &Path, dst: &Path) -> Result<(), String> {
    if dst.exists() {
        clear_readonly_if_needed(dst);
        let _ = fs::remove_file(dst);
    }
    // BẮT BUỘC dùng fs::copy (tạo luồng dữ liệu độc lập trên NTFS) thay vì hard_link:
    // Nếu NSIS mở tệp đích với cờ CREATE_ALWAYS / TRUNCATE_EXISTING tại chỗ, hard_link dùng chung inode sẽ bị ghi đè theo!
    fs::copy(src, dst).map_err(|e| {
        format!(
            "Không sao lưu cô lập được '{}' sang '{}': {e}",
            src.display(),
            dst.display()
        )
    })?;
    // Gỡ cờ Read-Only trên bản sao trong Vault để việc dọn dẹp txn/snapshot không bao giờ gặp ERROR_ACCESS_DENIED
    clear_readonly_if_needed(dst);
    Ok(())
}

fn write_json_atomic<T: Serialize>(target: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Không tạo được thư mục '{}': {e}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(value)
        .map_err(|e| format!("Lỗi tuần tự hóa JSON cho '{}': {e}", target.display()))?;
    let tmp_name = format!(
        "{}.tmp",
        target
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("meta.json")
    );
    let tmp = target.with_file_name(tmp_name);
    {
        let mut f = File::create(&tmp)
            .map_err(|e| format!("Không tạo được tệp tạm '{}': {e}", tmp.display()))?;
        f.write_all(&json)
            .map_err(|e| format!("Lỗi ghi tệp tạm '{}': {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("Lỗi đồng bộ đĩa tệp tạm '{}': {e}", tmp.display()))?;
    }
    fs::rename(&tmp, target)
        .map_err(|e| format!("Không đổi tên nguyên tử sang '{}': {e}", target.display()))
}

/// Khôi phục nguyên tử `src -> dst` qua tệp tạm cùng thư mục, gỡ cờ Read-Only và retry tối đa 15 × 200ms
/// khi gặp `ERROR_SHARING_VIOLATION (32)` hoặc `ERROR_ACCESS_DENIED (5)` (do Defender/SmartScreen quét PE).
pub fn atomic_restore_file(
    src: &Path,
    dst: &Path,
    tmp_suffix: &str,
    preserve_readonly: Option<bool>,
) -> Result<(), String> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Không tạo được thư mục đích '{}' khi khôi phục: {e}",
                parent.display()
            )
        })?;
    }

    let orig_readonly = preserve_readonly.unwrap_or_else(|| {
        fs::metadata(dst)
            .map(|m| m.permissions().readonly())
            .unwrap_or(false)
    });

    let dst_fname = dst
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("restored.bin");
    let restore_tmp = dst.with_file_name(format!("{dst_fname}.{tmp_suffix}"));

    if restore_tmp.exists() {
        clear_readonly_if_needed(&restore_tmp);
        let _ = fs::remove_file(&restore_tmp);
    }

    fs::copy(src, &restore_tmp).map_err(|e| {
        format!(
            "Không chép trả tệp '{}' từ Guardian Vault (bản gốc vẫn an toàn tại '{}'): {e}",
            dst.display(),
            src.display()
        )
    })?;
    clear_readonly_if_needed(&restore_tmp);

    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..RESTORE_MAX_ATTEMPTS {
        clear_readonly_if_needed(dst);
        match fs::rename(&restore_tmp, dst) {
            Ok(()) => {
                if orig_readonly {
                    set_readonly_state(dst, true);
                }
                return Ok(());
            }
            Err(rename_err) => {
                // Thử xóa tệp đích đang cản trở rồi rename lại ngay
                if dst.exists() {
                    let _ = fs::remove_file(dst);
                    if fs::rename(&restore_tmp, dst).is_ok() {
                        if orig_readonly {
                            set_readonly_state(dst, true);
                        }
                        return Ok(());
                    }
                }
                let retryable = is_retryable_win_lock_error(&rename_err);
                last_err = Some(rename_err);
                if retryable && attempt + 1 < RESTORE_MAX_ATTEMPTS {
                    std::thread::sleep(Duration::from_millis(RESTORE_RETRY_DELAY_MS));
                    continue;
                }
                break;
            }
        }
    }

    let _ = fs::remove_file(&restore_tmp);
    Err(format!(
        "Không hoàn trả được tệp '{}' sau {} lần thử (bản gốc vẫn an toàn tại '{}'): {}",
        dst.display(),
        RESTORE_MAX_ATTEMPTS,
        src.display(),
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "lỗi không xác định".to_string())
    ))
}

fn is_shm_path(p: &Path) -> bool {
    p.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|n| n.to_lowercase().ends_with("-shm"))
}

fn sqlite_wal_base_path(p: &Path) -> Option<PathBuf> {
    let fname = p.file_name()?.to_str()?;
    if fname.to_lowercase().ends_with("-wal") && fname.len() > 4 {
        let base_name = &fname[..fname.len() - 4];
        Some(p.with_file_name(base_name))
    } else {
        None
    }
}

fn is_sqlite_primary_path(p: &Path, all_paths: &[PathBuf]) -> bool {
    let Some(fname) = p.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let low = fname.to_lowercase();
    if low.ends_with("-wal") || low.ends_with("-shm") {
        return false;
    }
    if low.ends_with(".db") || low.ends_with(".sqlite") || low.ends_with(".sqlite3") {
        return true;
    }
    let expected_wal = format!("{fname}-wal").to_lowercase();
    all_paths.iter().any(|other| {
        other
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n.to_lowercase() == expected_wal)
            && other.parent() == p.parent()
    })
}

fn verify_file_matches_hash(path: &Path, expected_sha: &str, expected_size: u64) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.len() != expected_size {
        return false;
    }
    match compute_sha256(path) {
        Ok((sha, size)) => size == expected_size && sha == expected_sha,
        Err(_) => false,
    }
}

fn restore_and_verify_immutables(
    staged_immutables: &[StagedImmutableFile],
) -> Result<Vec<String>, String> {
    let mut restored = Vec::new();
    for item in staged_immutables {
        // Kiểm tra chính bản sao trong Vault còn nguyên vẹn 100% trước khi chép đè
        let (staged_sha, staged_size) = compute_sha256(&item.staged_path)?;
        if staged_sha != item.sha256_hex || staged_size != item.size_bytes {
            return Err(format!(
                "CẢNH BÁO NGHIÊM TRỌNG: Tệp khóa bất biến trong Vault '{}' bị sai lệch SHA-256 ({} != {}). Đã chặn ghi đè!",
                item.staged_path.display(),
                staged_sha,
                item.sha256_hex
            ));
        }

        atomic_restore_file(
            &item.staged_path,
            &item.original_path,
            "guardian_restore_tmp",
            Some(item.was_readonly),
        )?;

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
        restored.push(item.original_path.to_string_lossy().to_string());
    }
    Ok(restored)
}

/// Hậu kiểm và khôi phục nguyên tử toàn bộ tệp dữ liệu sao lưu:
/// - Các cụm SQLite (`.db`/`.sqlite` + `-wal`) được kiểm tra và khôi phục đồng thời để không bao giờ lệch chuỗi WAL.
/// - Mọi tệp bị mất, bị ghi đè rỗng (VD: 4 KB đè lên 60 MB) hoặc đổi SHA-256 đều được hoàn trả qua `.guardian_db_tmp` + `rename`.
fn verify_and_restore_backed_up_data(
    tool_name: &str,
    backed_up_files: &[BackedUpDataFile],
) -> Result<Vec<String>, String> {
    let all_orig_paths: Vec<PathBuf> = backed_up_files
        .iter()
        .map(|b| b.original_path.clone())
        .collect();
    let mut handled_keys: HashSet<String> = HashSet::new();
    let mut verified_paths = Vec::new();

    // 1. Xử lý các cụm nguyên tử SQLite (.db + -wal)
    let mut cluster_bases: Vec<PathBuf> = Vec::new();
    for bf in backed_up_files {
        if is_sqlite_primary_path(&bf.original_path, &all_orig_paths) {
            let key = bf.original_path.to_string_lossy().to_lowercase();
            if !cluster_bases.iter().any(|p| p.to_string_lossy().to_lowercase() == key) {
                cluster_bases.push(bf.original_path.clone());
            }
        } else if let Some(base) = sqlite_wal_base_path(&bf.original_path) {
            let key = base.to_string_lossy().to_lowercase();
            if !cluster_bases.iter().any(|p| p.to_string_lossy().to_lowercase() == key) {
                cluster_bases.push(base);
            }
        }
    }

    for base_path in cluster_bases {
        let base_key = base_path.to_string_lossy().to_lowercase();
        let wal_fname = format!(
            "{}-wal",
            base_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("db")
        );
        let shm_fname = format!(
            "{}-shm",
            base_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("db")
        );
        let wal_path = base_path.with_file_name(&wal_fname);
        let shm_path = base_path.with_file_name(&shm_fname);
        let wal_key = wal_path.to_string_lossy().to_lowercase();

        handled_keys.insert(base_key.clone());
        handled_keys.insert(wal_key.clone());

        let primary_entry = backed_up_files
            .iter()
            .find(|b| b.original_path.to_string_lossy().to_lowercase() == base_key);
        let wal_entry = backed_up_files
            .iter()
            .find(|b| b.original_path.to_string_lossy().to_lowercase() == wal_key);

        let primary_ok = primary_entry.is_none_or(|pe| {
            verify_file_matches_hash(&pe.original_path, &pe.sha256_hex, pe.size_bytes)
        });
        let wal_ok = match wal_entry {
            Some(we) => verify_file_matches_hash(&we.original_path, &we.sha256_hex, we.size_bytes),
            None => !wal_path.exists(),
        };

        if !primary_ok || !wal_ok {
            // Xóa sạch tệp bộ nhớ chia sẻ -shm tàn dư trước khi khôi phục cụm .db + -wal
            let _ = remove_file_with_retry(&shm_path);
            if wal_entry.is_none() && wal_path.exists() {
                let _ = remove_file_with_retry(&wal_path);
            }

            if let Some(pe) = primary_entry {
                atomic_restore_file(
                    &pe.backup_path,
                    &pe.original_path,
                    "guardian_db_tmp",
                    Some(pe.was_readonly),
                )
                .map_err(|e| {
                    format!(
                        "Cơ sở dữ liệu '{}' bị biến đổi khi cài {} và không khôi phục được: {e}",
                        pe.original_path.display(),
                        tool_name
                    )
                })?;
                if !verify_file_matches_hash(&pe.original_path, &pe.sha256_hex, pe.size_bytes) {
                    return Err(format!(
                        "SHA-256 của cơ sở dữ liệu '{}' không khớp sau khi khôi phục nguyên tử!",
                        pe.original_path.display()
                    ));
                }
            }

            if let Some(we) = wal_entry {
                atomic_restore_file(
                    &we.backup_path,
                    &we.original_path,
                    "guardian_db_tmp",
                    Some(we.was_readonly),
                )
                .map_err(|e| {
                    format!(
                        "Nhật ký WAL '{}' bị mất/lệch khi cài {} và không khôi phục được: {e}",
                        we.original_path.display(),
                        tool_name
                    )
                })?;
                if !verify_file_matches_hash(&we.original_path, &we.sha256_hex, we.size_bytes) {
                    return Err(format!(
                        "SHA-256 của tệp WAL '{}' không khớp sau khi khôi phục nguyên tử!",
                        we.original_path.display()
                    ));
                }
            }
        }

        if let Some(pe) = primary_entry {
            verified_paths.push(pe.original_path.to_string_lossy().to_string());
        }
        if let Some(we) = wal_entry {
            verified_paths.push(we.original_path.to_string_lossy().to_string());
        }
    }

    // 2. Xử lý các tệp khóa/cấu hình đơn lẻ còn lại (master.key, secret.key, backend.env, settings.json...)
    for bf in backed_up_files {
        let key = bf.original_path.to_string_lossy().to_lowercase();
        if handled_keys.contains(&key) {
            continue;
        }
        if !verify_file_matches_hash(&bf.original_path, &bf.sha256_hex, bf.size_bytes) {
            atomic_restore_file(
                &bf.backup_path,
                &bf.original_path,
                "guardian_db_tmp",
                Some(bf.was_readonly),
            )
            .map_err(|e| {
                format!(
                    "Tệp dữ liệu '{}' bị biến đổi khi cài {} và không tự khôi phục được (bản sao lưu tại '{}'): {e}",
                    bf.original_path.display(),
                    tool_name,
                    bf.backup_path.display()
                )
            })?;
            if !verify_file_matches_hash(&bf.original_path, &bf.sha256_hex, bf.size_bytes) {
                return Err(format!(
                    "SHA-256 của tệp '{}' không khớp sau khi khôi phục!",
                    bf.original_path.display()
                ));
            }
        }
        verified_paths.push(bf.original_path.to_string_lossy().to_string());
    }

    Ok(verified_paths)
}

/// Quét toàn bộ `vault/*/txn-*` dở dang (do sập nguồn / giết tiến trình giữa lúc NSIS chạy)
/// và khôi phục trả về đúng 100% SHA-256 gốc TRƯỚC KHI cho phép bất kỳ giao dịch mới nào băm tệp!
pub fn recover_incomplete_transactions(vault_root: &Path) -> Result<Vec<String>, String> {
    if !vault_root.exists() {
        return Ok(Vec::new());
    }
    let Ok(tool_dirs) = fs::read_dir(vault_root) else {
        return Ok(Vec::new());
    };

    let mut recovered_notes = Vec::new();

    for tool_entry in tool_dirs.flatten() {
        let tool_dir = tool_entry.path();
        if !tool_dir.is_dir() {
            continue;
        }
        let Ok(sub_entries) = fs::read_dir(&tool_dir) else {
            continue;
        };

        let mut txn_dirs: Vec<PathBuf> = Vec::new();
        let mut orphan_staging_dirs: Vec<PathBuf> = Vec::new();

        for sub in sub_entries_sorted(sub_entries) {
            if !sub.is_dir() {
                continue;
            }
            let Some(name) = sub.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.starts_with("txn-") {
                txn_dirs.push(sub);
            } else if name.starts_with("snapshot-staging-") {
                orphan_staging_dirs.push(sub);
            }
        }

        // Lượt 1 (BẮT BUỘC CHẠY TRƯỚC): Khôi phục toàn bộ `txn-*` khi `snapshot-staging-*` vẫn còn nguyên vẹn trên đĩa!
        // Tuyệt đối không xóa `snapshot-staging-*` trước `txn-*` vì `TxnJournal.backed_up_files` tham chiếu tệp bên trong đó.
        for sub in txn_dirs {
            let journal_path = sub.join("txn-journal.json");
            if journal_path.is_file() {
                let raw = fs::read_to_string(&journal_path).map_err(|e| {
                    format!(
                        "Không đọc được nhật ký giao dịch dở dang '{}': {e}",
                        journal_path.display()
                    )
                })?;
                let journal: TxnJournal = serde_json::from_str(&raw).map_err(|e| {
                    format!(
                        "Nhật ký giao dịch '{}' bị hỏng JSON (giữ nguyên thư mục để bảo vệ bản gốc): {e}",
                        journal_path.display()
                    )
                })?;

                let restored_imm = restore_and_verify_immutables(&journal.staged_immutables)?;
                let restored_data = verify_and_restore_backed_up_data(
                    &journal.tool_name,
                    &journal.backed_up_files,
                )?;

                clear_readonly_recursive(&sub);
                let _ = fs::remove_dir_all(&sub);
                recovered_notes.push(format!(
                    "Đã tự động phục hồi giao dịch dở dang của {} ({} tệp bất biến, {} tệp dữ liệu).",
                    journal.tool_name,
                    restored_imm.len(),
                    restored_data.len()
                ));
            } else {
                // Thư mục txn-* chưa kịp ghi journal nghĩa là begin() dừng trước khi NSIS chạy -> dọn sạch an toàn
                clear_readonly_recursive(&sub);
                let _ = fs::remove_dir_all(&sub);
            }
        }

        // Lượt 2: Chỉ dọn các thư mục `snapshot-staging-*` mồ côi SAU KHI toàn bộ `txn-*` đã phục hồi thành công 100%!
        for staging in orphan_staging_dirs {
            clear_readonly_recursive(&staging);
            let _ = fs::remove_dir_all(&staging);
        }
    }

    Ok(recovered_notes)
}

fn sub_entries_sorted(entries: fs::ReadDir) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    v.sort();
    v
}

fn read_valid_snapshot_meta(snap_dir: &Path) -> Option<SnapshotMetadata> {
    let meta_path = snap_dir.join("snapshot-meta.json");
    let raw = fs::read_to_string(meta_path).ok()?;
    serde_json::from_str::<SnapshotMetadata>(&raw).ok()
}

pub fn prune_old_snapshots(tool_vault_dir: &Path, keep: usize) {
    let Ok(entries) = fs::read_dir(tool_vault_dir) else {
        return;
    };
    let mut valid_snaps: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    n.starts_with("snapshot-") && !n.starts_with("snapshot-staging-")
                })
                && read_valid_snapshot_meta(p).is_some()
        })
        .collect();
    valid_snaps.sort();
    if valid_snaps.len() > keep {
        let remove_cnt = valid_snaps.len() - keep;
        for old in valid_snaps.into_iter().take(remove_cnt) {
            clear_readonly_recursive(&old);
            let _ = fs::remove_dir_all(old);
        }
    }
}

pub fn find_latest_rollback_snapshot(
    vault_root: &Path,
    tool_id: &str,
    preferred_channel: Option<&str>,
) -> Option<(PathBuf, SnapshotMetadata)> {
    let tool_vault_dir = vault_root.join(tool_id);
    let entries = fs::read_dir(&tool_vault_dir).ok()?;
    let mut candidates: Vec<(PathBuf, SnapshotMetadata)> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    n.starts_with("snapshot-") && !n.starts_with("snapshot-staging-")
                })
        })
        .filter_map(|p| {
            let meta = read_valid_snapshot_meta(&p)?;
            // Snapshot có thể rollback khi có bản sao lưu .exe thực sự tồn tại trên đĩa
            let has_exe = meta
                .files
                .iter()
                .any(|f| f.role == "exe" && p.join(&f.backup_file).is_file());
            if has_exe {
                Some((p, meta))
            } else {
                None
            }
        })
        .collect();

    candidates.sort_by(|a, b| a.0.cmp(&b.0));

    if let Some(ch) = preferred_channel {
        if let Some(found) = candidates.iter().rev().find(|(_, m)| m.channel == ch) {
            return Some(found.clone());
        }
        return None;
    }

    candidates.pop()
}

/// Khôi phục nguyên tử bản `.exe` ổn định trước đó kèm dữ liệu DB/khóa từ `snapshot-*` hợp lệ gần nhất.
pub fn execute_rollback(
    tool: &ToolManifest,
    vault_root: &Path,
    selected_channel: &str,
) -> Result<(String, Option<String>, VaultVerificationReport, Option<ToolLedgerEntry>), String> {
    recover_incomplete_transactions(vault_root)?;
    GuardianTransaction::preflight_check(tool, selected_channel)?;

    let (snap_dir, meta) =
        find_latest_rollback_snapshot(vault_root, &tool.id, Some(selected_channel)).ok_or_else(
            || {
                format!(
                    "Chưa có bản sao lưu thực thi nào trong Guardian Vault cho {} (kênh '{}') để khôi phục.",
                    tool.name, selected_channel
                )
            },
        )?;

    // Bước 1: Kiểm khớp 100% SHA-256 của mọi tệp trong snapshot TRƯỚC KHI chạm vào đĩa
    for entry in &meta.files {
        let src = snap_dir.join(&entry.backup_file);
        if !src.is_file() {
            return Err(format!(
                "Tệp sao lưu '{}' trong '{}' bị thiếu. Đã hủy khôi phục an toàn!",
                entry.backup_file,
                snap_dir.display()
            ));
        }
        let (sha, size) = compute_sha256(&src)?;
        if sha != entry.sha256 || size != entry.size {
            return Err(format!(
                "SHA-256 của tệp sao lưu '{}' trong Vault không khớp siêu dữ liệu ({} != {}). Đã hủy khôi phục!",
                src.display(),
                sha,
                entry.sha256
            ));
        }
    }

    // Bước 2: Dọn tệp -shm (và -wal mồ côi nếu bản snapshot lúc chụp không có -wal) cho mọi DB SQLite
    let all_snapshot_origs: Vec<PathBuf> = meta
        .files
        .iter()
        .filter(|f| f.role == "data")
        .map(|f| PathBuf::from(&f.original_path))
        .collect();
    for orig in &all_snapshot_origs {
        if is_sqlite_primary_path(orig, &all_snapshot_origs) {
            let fname = orig.file_name().and_then(|s| s.to_str()).unwrap_or("db");
            let shm_path = orig.with_file_name(format!("{fname}-shm"));
            let wal_path = orig.with_file_name(format!("{fname}-wal"));
            let _ = remove_file_with_retry(&shm_path);
            let has_wal_in_snap = all_snapshot_origs
                .iter()
                .any(|p| p.to_string_lossy().eq_ignore_ascii_case(&wal_path.to_string_lossy()));
            if !has_wal_in_snap && wal_path.exists() {
                let _ = remove_file_with_retry(&wal_path);
            }
        }
    }

    // Bước 3: Khôi phục nguyên tử toàn bộ tệp dữ liệu và tệp thực thi .exe
    let mut verified_backup_files = Vec::new();
    let mut restored_exe_path: Option<String> = None;

    for entry in &meta.files {
        let src = snap_dir.join(&entry.backup_file);
        let dst = PathBuf::from(&entry.original_path);
        let suffix = if entry.role == "exe" {
            "guardian_rollback_exe_tmp"
        } else {
            "guardian_db_tmp"
        };
        atomic_restore_file(&src, &dst, suffix, Some(entry.was_readonly))?;

        let (post_sha, post_size) = compute_sha256(&dst)?;
        if post_sha != entry.sha256 || post_size != entry.size {
            return Err(format!(
                "SHA-256 sau khôi phục của '{}' không khớp bản sao lưu!",
                dst.display()
            ));
        }
        if entry.role == "exe" {
            restored_exe_path = Some(dst.to_string_lossy().to_string());
        } else {
            verified_backup_files.push(dst.to_string_lossy().to_string());
        }
    }

    let mut restored_immutable_files = Vec::new();
    for imm in &tool.protection.immutable_files {
        let p = Path::new(imm);
        if p.is_file() {
            restored_immutable_files.push(imm.clone());
        }
    }

    let mut verified_external_paths = Vec::new();
    for ext in &tool.protection.verify_external_paths {
        let p = Path::new(ext);
        if p.exists() {
            verified_external_paths.push(ext.clone());
        }
    }

    let restored_ver = meta
        .installed_version
        .clone()
        .or_else(|| {
            restored_exe_path
                .as_deref()
                .and_then(|p| crate::discovery::read_pe_version(Path::new(p)))
        })
        .unwrap_or_else(|| "0.0.0".to_string());

    let ledger_entry = if let Some(ref exe_str) = restored_exe_path {
        let p = Path::new(exe_str);
        let fmeta = fs::metadata(p).map_err(|e| {
            format!(
                "Không đọc được metadata tệp thực thi vừa khôi phục '{}': {e}",
                p.display()
            )
        })?;
        let mtime = fmeta
            .modified()
            .map_err(|e| format!("Không đọc được mtime của '{}': {e}", p.display()))?
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Mốc thời gian tệp không hợp lệ: {e}"))?
            .as_secs();
        Some(ToolLedgerEntry {
            exe_path: exe_str.clone(),
            exe_size: fmeta.len(),
            exe_mtime_secs: mtime,
            installed_version: restored_ver.clone(),
            channel: selected_channel.to_string(),
            installed_at_iso: Utc::now().to_rfc3339(),
        })
    } else {
        None
    };

    let report = VaultVerificationReport {
        restored_immutable_files,
        verified_backup_files,
        verified_external_paths,
        snapshot_dir: Some(snap_dir.to_string_lossy().to_string()),
    };

    Ok((restored_ver, restored_exe_path, report, ledger_entry))
}

impl GuardianTransaction {
    /// Kiểm tra nhanh tiến trình sống (bao gồm cả sidecar trong thư mục cài đặt) & cổng dịch vụ (IPv4 + IPv6)
    /// trước khi tải bộ cài dung lượng lớn, tránh tốn băng thông hoặc làm treo bộ cài NSIS.
    pub fn preflight_check(tool: &ToolManifest, selected_channel: &str) -> Result<(), String> {
        let running = capture_running_processes();
        let (active_procs, _) = running.match_tool_processes(tool, selected_channel, &[]);
        if !active_procs.is_empty() {
            return Err(format!(
                "Không thể thao tác khi {} đang có tiến trình hoạt động ({}). Hãy đóng ứng dụng để nhả khóa cơ sở dữ liệu / sidecar trước khi tiếp tục.",
                tool.name,
                active_procs.join(", ")
            ));
        }

        for hp in &tool.protection.health_ports {
            if hp.block_update_when_open && probe_tcp_port(hp.port) {
                return Err(format!(
                    "Cổng dịch vụ {} đang hoạt động. Hãy dừng tác vụ đang chạy trước khi thao tác trên {}.",
                    hp.label, tool.name
                ));
            }
        }

        Ok(())
    }

    /// Khởi tạo giao dịch bảo hộ ngay trước khi chạy trình cài đặt NSIS:
    /// 0. Phục hồi mọi giao dịch `txn-*` sập dở từ trước để bảo đảm tuyệt đối không băm nhầm tệp bị ghi đè!
    /// 1. Từ chối ngay nếu tiến trình của công cụ hoặc sidecar đang chạy / cổng bảo vệ đang mở.
    /// 2. Khóa bất biến mọi tệp trong `immutable_files` (VD: cowriter-core.exe) kèm mã băm SHA-256.
    /// 3. Tạo bản chụp tạm `snapshot-staging-*` cho cả `.exe` đang chạy ổn định + DB SQLite & khóa bảo mật.
    /// 4. Ghi nhật ký nguyên tử `txn-journal.json` trước khi NSIS khởi chạy.
    pub fn begin(
        tool: &ToolManifest,
        vault_root: &Path,
        max_backup_generations: usize,
        selected_channel: &str,
        current_exe_path: Option<&Path>,
        current_installed_version: Option<&str>,
    ) -> Result<Self, String> {
        recover_incomplete_transactions(vault_root)?;
        Self::preflight_check(tool, selected_channel)?;

        let stamp = Utc::now().format("%Y%m%d-%H%M%S-%3f").to_string();
        let tool_vault_dir = vault_root.join(&tool.id);
        let txn_dir = tool_vault_dir.join(format!("txn-{stamp}"));
        let imm_dir = txn_dir.join("immutable");
        let staging_sdir = tool_vault_dir.join(format!("snapshot-staging-{stamp}"));
        let final_sdir = tool_vault_dir.join(format!("snapshot-{stamp}"));

        fs::create_dir_all(&imm_dir).map_err(|e| {
            format!(
                "Không tạo được kho bảo hộ Guardian Vault tại '{}': {e}",
                imm_dir.display()
            )
        })?;

        let build_result: Result<
            (
                Vec<StagedImmutableFile>,
                Vec<BackedUpDataFile>,
                Option<PathBuf>,
            ),
            String,
        > = (|| {
            let mut staged_immutables = Vec::new();
            for (idx, imm_str) in tool.protection.immutable_files.iter().enumerate() {
                let orig = PathBuf::from(imm_str);
                if orig.exists() && orig.is_file() {
                    let was_readonly = fs::metadata(&orig)
                        .map(|m| m.permissions().readonly())
                        .unwrap_or(false);
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
                        was_readonly,
                    });
                }
            }

            let mut backed_up_files = Vec::new();
            let mut snapshot_entries = Vec::new();

            let existing_backups: Vec<PathBuf> = tool
                .protection
                .backup_files
                .iter()
                .map(PathBuf::from)
                .filter(|p| !is_shm_path(p) && p.exists() && p.is_file())
                .collect();

            let existing_exe = current_exe_path.filter(|p| p.exists() && p.is_file());

            let staging_snapshot_dir = if existing_exe.is_some() || !existing_backups.is_empty() {
                fs::create_dir_all(&staging_sdir).map_err(|e| {
                    format!(
                        "Không tạo được thư mục sao lưu tạm tại '{}': {e}",
                        staging_sdir.display()
                    )
                })?;

                let mut active_exe_original_path = None;
                if let Some(exe_orig) = existing_exe {
                    let was_readonly = fs::metadata(exe_orig)
                        .map(|m| m.permissions().readonly())
                        .unwrap_or(false);
                    let (sha, size) = compute_sha256(exe_orig)?;
                    let fname = exe_orig
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("app.exe");
                    let backup_file = format!("exe_{fname}");
                    let dst = staging_sdir.join(&backup_file);
                    isolated_vault_copy(exe_orig, &dst)?;
                    let orig_str = exe_orig.to_string_lossy().to_string();
                    active_exe_original_path = Some(orig_str.clone());
                    snapshot_entries.push(SnapshotFileEntry {
                        role: "exe".to_string(),
                        backup_file,
                        original_path: orig_str,
                        sha256: sha,
                        size,
                        was_readonly,
                    });
                }

                for (idx, orig) in existing_backups.into_iter().enumerate() {
                    let was_readonly = fs::metadata(&orig)
                        .map(|m| m.permissions().readonly())
                        .unwrap_or(false);
                    let (sha256_hex, size_bytes) = compute_sha256(&orig)?;
                    let fname = orig
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("data.bak");
                    let backup_file = format!("data_{idx}_{fname}");
                    let bpath = staging_sdir.join(&backup_file);
                    isolated_vault_copy(&orig, &bpath)?;
                    snapshot_entries.push(SnapshotFileEntry {
                        role: "data".to_string(),
                        backup_file,
                        original_path: orig.to_string_lossy().to_string(),
                        sha256: sha256_hex.clone(),
                        size: size_bytes,
                        was_readonly,
                    });
                    backed_up_files.push(BackedUpDataFile {
                        original_path: orig,
                        backup_path: bpath,
                        sha256_hex,
                        size_bytes,
                        was_readonly,
                    });
                }

                let meta = SnapshotMetadata {
                    schema_version: 1,
                    tool_id: tool.id.clone(),
                    tool_name: tool.name.clone(),
                    channel: selected_channel.to_string(),
                    installed_version: current_installed_version.map(|s| s.to_string()),
                    created_at_iso: Utc::now().to_rfc3339(),
                    active_exe_original_path,
                    files: snapshot_entries,
                };
                write_json_atomic(&staging_sdir.join("snapshot-meta.json"), &meta)?;
                Some(staging_sdir.clone())
            } else {
                None
            };

            let journal = TxnJournal {
                schema_version: 1,
                tool_id: tool.id.clone(),
                tool_name: tool.name.clone(),
                created_at_iso: Utc::now().to_rfc3339(),
                staged_immutables: staged_immutables.clone(),
                backed_up_files: backed_up_files.clone(),
            };
            write_json_atomic(&txn_dir.join("txn-journal.json"), &journal)?;

            Ok((staged_immutables, backed_up_files, staging_snapshot_dir))
        })();

        let (staged_immutables, backed_up_files, staging_snapshot_dir) = match build_result {
            Ok(v) => v,
            Err(e) => {
                clear_readonly_recursive(&txn_dir);
                let _ = fs::remove_dir_all(&txn_dir);
                if staging_sdir.exists() {
                    clear_readonly_recursive(&staging_sdir);
                    let _ = fs::remove_dir_all(&staging_sdir);
                }
                return Err(e);
            }
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
            tool_vault_dir,
            txn_dir,
            staging_snapshot_dir,
            final_snapshot_dir: final_sdir,
            max_backup_generations,
            staged_immutables,
            backed_up_files,
            preexisting_externals,
            completed: false,
        })
    }

    /// Thực thi ngay sau khi trình cài đặt NSIS kết thúc (kể cả thành công hay lỗi)
    /// để khôi phục 100% các tệp bất biến (như cowriter-core.exe) và hậu kiểm toàn vẹn cụm SQLite DB.
    /// Trả về `PendingSnapshot` chỉ được chốt thành `snapshot-*` và `prune_old_snapshots` khi hậu kiểm cài đặt thành công!
    pub fn restore_and_verify(mut self) -> Result<(VaultVerificationReport, PendingSnapshot), String> {
        let restored_immutable_files = restore_and_verify_immutables(&self.staged_immutables)?;
        let verified_backup_files =
            verify_and_restore_backed_up_data(&self.tool_name, &self.backed_up_files)?;

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

        // Dọn thư mục giao dịch tạm CHỈ SAU KHI mọi SHA-256 đã khớp 100%
        self.completed = true;
        clear_readonly_recursive(&self.txn_dir);
        let _ = fs::remove_dir_all(&self.txn_dir);

        let pending = PendingSnapshot {
            staging_dir: self.staging_snapshot_dir.take(),
            final_dir: self.final_snapshot_dir.clone(),
            tool_vault_dir: self.tool_vault_dir.clone(),
            max_backup_generations: self.max_backup_generations,
            committed: false,
        };

        Ok((
            VaultVerificationReport {
                restored_immutable_files,
                verified_backup_files,
                verified_external_paths,
                snapshot_dir: None,
            },
            pending,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{GitSpec, HealthPortSpec, InstallSpec, ProtectionSpec, UpdaterSpec};
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
                    app_dir
                        .join("co_writer.db-wal")
                        .to_string_lossy()
                        .to_string(),
                    app_dir.join("master.key").to_string_lossy().to_string(),
                ],
                verify_external_paths: vec![],
            },
            git: GitSpec {
                repo_path: app_dir.to_string_lossy().to_string(),
                watch_paths: vec!["app".to_string()],
                extra_repos: vec![],
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

        let guard = GuardianTransaction::begin(
            &tool,
            &vault_root,
            2,
            "stable",
            Some(&exe_path),
            Some("1.8.0"),
        )
        .expect("GuardianTransaction::begin phải thành công");

        fs::write(&exe_path, b"NEW_COWRITER_1_9_0").unwrap();
        fs::write(&sidecar_path, b"CI_OVERWRITTEN_WRONG_SIDECAR_PAYLOAD").unwrap();
        fs::remove_file(&key_path).unwrap();

        let (mut report, pending) = guard
            .restore_and_verify()
            .expect("Phải khôi phục nguyên trạng cowriter-core.exe và master.key");
        report.snapshot_dir = pending.commit_and_prune();

        assert_eq!(report.restored_immutable_files.len(), 1);
        assert!(report.snapshot_dir.is_some());
        let (post_sha, _) = compute_sha256(&sidecar_path).unwrap();
        assert_eq!(
            post_sha, expected_sha,
            "cowriter-core.exe bắt buộc giữ nguyên 100% SHA-256!"
        );
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
        let res = GuardianTransaction::begin(
            &tool,
            &tmp.path().join("vault"),
            2,
            "stable",
            None,
            None,
        );
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.contains(&port.to_string()));
    }

    #[test]
    fn blocks_ipv6_loopback_health_port_in_preflight_check() {
        let Ok(listener) = TcpListener::bind("[::1]:0") else {
            return; // Máy không bật loopback IPv6
        };
        let port = listener.local_addr().unwrap().port();
        let tmp = tempdir().unwrap();
        let tool = mock_cowriter_manifest(tmp.path(), Some(port));
        let res = GuardianTransaction::begin(
            &tool,
            &tmp.path().join("vault"),
            2,
            "stable",
            None,
            None,
        );
        assert!(res.is_err(), "Phải chặn ngay cả khi dịch vụ chỉ bind trên IPv6 [::1]");
    }

    #[test]
    fn recovers_crashed_txn_journal_before_next_begin_never_hashes_ci_overwrite() {
        let tmp = tempdir().unwrap();
        let app_dir = tmp.path().join("Co-Writer");
        let vault_root = tmp.path().join("vault");
        fs::create_dir_all(&app_dir).unwrap();

        let sacred_sidecar = b"SACRED_227MB_COWRITER_CORE_AUTHOR_BUILD_V1";
        let sacred_db = b"SQLite format 3\0_CANON_DB_MUST_SURVIVE_CRASH_TOO";
        let sidecar_path = app_dir.join("cowriter-core.exe");
        let db_path = app_dir.join("co_writer.db");
        fs::write(&sidecar_path, sacred_sidecar).unwrap();
        fs::write(&db_path, sacred_db).unwrap();
        let (sacred_sha, _) = compute_sha256(&sidecar_path).unwrap();
        let (sacred_db_sha, _) = compute_sha256(&db_path).unwrap();

        let tool = mock_cowriter_manifest(&app_dir, None);

        // Giao dịch 1 bắt đầu, sau đó NSIS ghi đè CẢ cowriter-core.exe LẪN xóa co_writer.db và Launcher bị giết ngang (forget guard!)
        let crashed_guard = GuardianTransaction::begin(&tool, &vault_root, 2, "stable", None, None)
            .expect("begin giao dịch 1 phải thành công");
        fs::write(&sidecar_path, b"WRONG_CI_STUB_BINARY_DO_NOT_HASH_ME").unwrap();
        fs::remove_file(&db_path).unwrap();
        std::mem::forget(crashed_guard);

        // Giao dịch 2 bắt đầu: BẮT BUỘC tự động phục hồi cả cowriter-core.exe lẫn co_writer.db từ txn-* + snapshot-staging-* trước khi dọn!
        let second_guard = GuardianTransaction::begin(&tool, &vault_root, 2, "stable", None, None)
            .expect("begin giao dịch 2 phải tự phục hồi txn-* cũ trước khi mở giao dịch mới");

        let (mid_sha, _) = compute_sha256(&sidecar_path).unwrap();
        let (mid_db_sha, _) = compute_sha256(&db_path).unwrap();
        assert_eq!(mid_sha, sacred_sha);
        assert_eq!(mid_db_sha, sacred_db_sha);

        // NSIS lần 2 lại ghi đè lần nữa -> restore_and_verify vẫn hoàn trả đúng bản gốc ban đầu!
        fs::write(&sidecar_path, b"WRONG_CI_STUB_SECOND_RUN").unwrap();
        let (report, _pending) = second_guard.restore_and_verify().unwrap();
        assert_eq!(report.restored_immutable_files.len(), 1);
        let (final_sha, _) = compute_sha256(&sidecar_path).unwrap();
        assert_eq!(final_sha, sacred_sha);
    }

    #[cfg(windows)]
    #[test]
    fn retries_restore_when_target_is_readonly_or_temporarily_locked_error_32() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING};

        let tmp = tempdir().unwrap();
        let src = tmp.path().join("staged_core.locked");
        let dst = tmp.path().join("cowriter-core.exe");

        fs::write(&src, b"AUTHOR_IMMUTABLE_PAYLOAD").unwrap();
        fs::write(&dst, b"NSIS_OVERWRITTEN_PAYLOAD").unwrap();

        // Đặt cờ Read-Only trên tệp đích để kiểm chứng gỡ + khôi phục thuộc tính Read-Only
        set_readonly_state(&dst, true);

        // Mở khóa độc quyền (dwShareMode = 0 -> gây ERROR_SHARING_VIOLATION os error 32) trong ~350ms trên luồng phụ
        let wide_dst: Vec<u16> = dst
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle_raw = unsafe {
            let h = CreateFileW(
                wide_dst.as_ptr(),
                GENERIC_READ,
                0, // Không chia sẻ FILE_SHARE_DELETE -> khóa cứng tệp
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            );
            assert!(h != INVALID_HANDLE_VALUE && !h.is_null());
            h as usize
        };

        let unlocker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(350));
            unsafe {
                let _ = CloseHandle(handle_raw as *mut core::ffi::c_void);
            }
        });

        atomic_restore_file(&src, &dst, "guardian_restore_tmp", Some(true))
            .expect("Phải tự động retry vượt qua os error 32 và cờ Read-Only");
        unlocker.join().unwrap();

        assert_eq!(fs::read(&dst).unwrap(), b"AUTHOR_IMMUTABLE_PAYLOAD");
        assert!(
            fs::metadata(&dst).unwrap().permissions().readonly(),
            "Phải khôi phục lại thuộc tính Read-Only ban đầu"
        );
    }

    #[test]
    fn restores_sqlite_db_and_wal_cluster_atomically_and_detects_blank_db_overwrite() {
        let tmp = tempdir().unwrap();
        let app_dir = tmp.path().join("Co-Writer");
        let vault_root = tmp.path().join("vault");
        fs::create_dir_all(&app_dir).unwrap();

        let db_path = app_dir.join("co_writer.db");
        let wal_path = app_dir.join("co_writer.db-wal");
        let shm_path = app_dir.join("co_writer.db-shm");

        let real_db = vec![0xABu8; 64 * 1024]; // 64 KB DB
        let real_wal = vec![0xCDu8; 16 * 1024]; // 16 KB WAL chưa checkpoint
        fs::write(&db_path, &real_db).unwrap();
        fs::write(&wal_path, &real_wal).unwrap();
        fs::write(&shm_path, vec![0xEEu8; 4096]).unwrap();

        let (expected_db_sha, _) = compute_sha256(&db_path).unwrap();
        let (expected_wal_sha, _) = compute_sha256(&wal_path).unwrap();
        let tool = mock_cowriter_manifest(&app_dir, None);

        // Ca A: Bộ cài giải nén tệp DB trống 4 KB (> 0 byte!) đè lên DB thật 64 KB
        let guard_a = GuardianTransaction::begin(&tool, &vault_root, 2, "stable", None, None).unwrap();
        fs::write(&db_path, vec![0x00u8; 4096]).unwrap();
        let (_rep_a, pend_a) = guard_a.restore_and_verify().unwrap();
        drop(pend_a);

        assert!(!shm_path.exists(), "Phải xóa sạch tệp -shm tàn dư khi khôi phục cụm SQLite");
        assert_eq!(compute_sha256(&db_path).unwrap().0, expected_db_sha);
        assert_eq!(compute_sha256(&wal_path).unwrap().0, expected_wal_sha);

        // Ca B: Bộ cài xóa mất tệp .db-wal trong khi giữ nguyên .db -> bắt buộc khôi phục lại .db-wal!
        let guard_b = GuardianTransaction::begin(&tool, &vault_root, 2, "stable", None, None).unwrap();
        fs::remove_file(&wal_path).unwrap();
        let (_rep_b, _pend_b) = guard_b.restore_and_verify().unwrap();

        assert!(wal_path.is_file(), "Phải hoàn trả .db-wal để không mất giao dịch chưa checkpoint");
        assert_eq!(compute_sha256(&wal_path).unwrap().0, expected_wal_sha);
    }

    #[test]
    fn executes_rollback_and_prune_only_counts_snapshots_with_valid_snapshot_meta() {
        let tmp = tempdir().unwrap();
        let app_dir = tmp.path().join("Co-Writer");
        let vault_root = tmp.path().join("vault");
        fs::create_dir_all(&app_dir).unwrap();

        let exe_path = app_dir.join("cowriter.exe");
        let db_path = app_dir.join("co_writer.db");
        let tool = mock_cowriter_manifest(&app_dir, None);

        // Thế hệ 1: Đang ở v1.0.0 -> nâng cấp lên v1.1.0 thành công
        fs::write(&exe_path, b"MZ_COWRITER_BIN_1_0_0").unwrap();
        fs::write(&db_path, b"DB_STATE_1_0_0").unwrap();
        let g1 = GuardianTransaction::begin(
            &tool,
            &vault_root,
            2,
            "stable",
            Some(&exe_path),
            Some("1.0.0"),
        )
        .unwrap();
        fs::write(&exe_path, b"MZ_COWRITER_BIN_1_1_0").unwrap();
        let (_, p1) = g1.restore_and_verify().unwrap();
        assert!(p1.commit_and_prune().is_some());
        std::thread::sleep(Duration::from_millis(10));

        // Thế hệ 2: Đang ở v1.1.0 -> nâng cấp lên v1.2.0 thành công
        fs::write(&db_path, b"DB_STATE_1_1_0").unwrap();
        let g2 = GuardianTransaction::begin(
            &tool,
            &vault_root,
            2,
            "stable",
            Some(&exe_path),
            Some("1.1.0"),
        )
        .unwrap();
        fs::write(&exe_path, b"MZ_COWRITER_BIN_1_2_0_CRASHING").unwrap();
        let (_, p2) = g2.restore_and_verify().unwrap();
        assert!(p2.commit_and_prune().is_some());

        // Chèn thêm 2 thư mục snapshot hỏng (thiếu snapshot-meta.json) + mô phỏng 2 lần cài lỗi liên tiếp
        let tool_vault = vault_root.join("cowriter");
        fs::create_dir_all(tool_vault.join("snapshot-99990101-000000-001")).unwrap();
        fs::create_dir_all(tool_vault.join("snapshot-99990101-000000-002")).unwrap();

        for _ in 0..2 {
            let g_fail = GuardianTransaction::begin(
                &tool,
                &vault_root,
                2,
                "stable",
                Some(&exe_path),
                Some("1.2.0"),
            )
            .unwrap();
            let (_, pending_fail) = g_fail.restore_and_verify().unwrap();
            // Không gọi commit_and_prune vì giả lập NSIS lỗi!
            drop(pending_fail);
        }
        prune_old_snapshots(&tool_vault, 2);

        // Kiểm chứng: Bản sao lưu lành gần nhất (v1.1.0) VẪN CÒN NGUYÊN VẸN và khôi phục thành công!
        let (restored_ver, restored_exe, _rep, ledger) =
            execute_rollback(&tool, &vault_root, "stable")
                .expect("Phải khôi phục thành công từ snapshot lành v1.1.0");

        assert_eq!(restored_ver, "1.1.0");
        assert!(restored_exe.is_some());
        assert_eq!(fs::read(&exe_path).unwrap(), b"MZ_COWRITER_BIN_1_1_0");
        assert_eq!(fs::read(&db_path).unwrap(), b"DB_STATE_1_1_0");
        assert_eq!(ledger.unwrap().installed_version, "1.1.0");
    }
}
