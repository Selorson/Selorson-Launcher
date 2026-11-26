use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LauncherStateFile {
    #[serde(default)]
    pub settings: LauncherSettings,
    #[serde(default)]
    pub installed_ledger: BTreeMap<String, ToolLedgerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LauncherSettings {
    /// Mặc định false: Đóng cửa sổ = Thoát sạch 100% (0 MB RAM nền).
    /// Khi bật true: Đóng cửa sổ sẽ hủy nhân WebView2 (~0 MB UI RAM) và giữ khay hệ thống + phím tắt Alt+Shift+S.
    #[serde(default)]
    pub close_to_tray: bool,
    #[serde(default)]
    pub global_hotkey_enabled: bool,
    /// Kênh phát hành đang chọn cho từng công cụ (ví dụ neuroforge -> "rtx" hoặc "standard")
    #[serde(default)]
    pub selected_channels: BTreeMap<String, String>,
}

impl Default for LauncherSettings {
    fn default() -> Self {
        Self {
            close_to_tray: false,
            global_hotkey_enabled: false,
            selected_channels: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolLedgerEntry {
    pub exe_path: String,
    pub exe_size: u64,
    pub exe_mtime_secs: u64,
    pub installed_version: String,
    pub channel: String,
    pub installed_at_iso: String,
}

impl LauncherStateFile {
    pub fn ledger_key(tool_id: &str, channel: &str) -> String {
        format!("{tool_id}:{channel}")
    }

    /// Đọc bản ghi sổ cái theo khóa ghép `{tool_id}:{channel}`, hỗ trợ tương thích ngược khóa cũ `{tool_id}`
    /// khi cùng kênh phát hành (không để bản ghi kênh RTX tràn sang kênh Standard).
    pub fn get_ledger_entry(&self, tool_id: &str, channel: &str) -> Option<&ToolLedgerEntry> {
        let composite = Self::ledger_key(tool_id, channel);
        if let Some(entry) = self.installed_ledger.get(&composite) {
            return Some(entry);
        }
        self.installed_ledger
            .get(tool_id)
            .filter(|legacy| legacy.channel.eq_ignore_ascii_case(channel))
    }

    pub fn upsert_ledger_entry(&mut self, tool_id: &str, channel: &str, entry: ToolLedgerEntry) {
        let composite = Self::ledger_key(tool_id, channel);
        self.installed_ledger.insert(composite, entry);
        if self
            .installed_ledger
            .get(tool_id)
            .is_some_and(|legacy| legacy.channel.eq_ignore_ascii_case(channel))
        {
            self.installed_ledger.remove(tool_id);
        }
    }
}

pub fn default_state_file_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    base.join("Selorson Launcher").join("state.json")
}

pub fn load_state_file(path: &Path) -> LauncherStateFile {
    if !path.is_file() {
        return LauncherStateFile::default();
    }
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<LauncherStateFile>(&raw) {
            Ok(parsed) => parsed,
            Err(err) => {
                // Sao lưu bản hỏng sang `.corrupt` để không bao giờ mất dấu sổ cái cũ
                let corrupt_name = format!(
                    "{}.corrupt",
                    path.file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("state.json")
                );
                let corrupt_path = path.with_file_name(corrupt_name);
                let _ = fs::copy(path, &corrupt_path);
                eprintln!(
                    "[Ledger] Tệp '{}' lỗi cú pháp JSON ({err}); đã sao lưu sang '{}'.",
                    path.display(),
                    corrupt_path.display()
                );
                LauncherStateFile::default()
            }
        },
        Err(_) => LauncherStateFile::default(),
    }
}

pub fn save_state_file(path: &Path, state: &LauncherStateFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Không tạo được thư mục lưu trạng thái '{}': {e}",
                parent.display()
            )
        })?;
    }
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| format!("Lỗi tuần tự hóa state.json: {e}"))?;
    let tmp_name = format!(
        "{}.tmp",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("state.json")
    );
    let tmp = path.with_file_name(tmp_name);
    {
        let mut f = File::create(&tmp)
            .map_err(|e| format!("Không tạo được tệp tạm '{}': {e}", tmp.display()))?;
        f.write_all(&json)
            .map_err(|e| format!("Không ghi được tệp tạm '{}': {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("Không đồng bộ đĩa cho tệp tạm '{}': {e}", tmp.display()))?;
    }

    let mut last_err = None;
    for attempt in 0..10 {
        match fs::rename(&tmp, path) {
            Ok(()) => return Ok(()),
            Err(e) => {
                let retryable = matches!(e.raw_os_error(), Some(5) | Some(32))
                    || e.kind() == std::io::ErrorKind::PermissionDenied;
                last_err = Some(e);
                if retryable && attempt + 1 < 10 {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                break;
            }
        }
    }
    let _ = fs::remove_file(&tmp);
    Err(format!(
        "Không đổi tên nguyên tử sang '{}': {}",
        path.display(),
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "lỗi không xác định".to_string())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn supports_channel_composite_keys_with_legacy_compat_and_backs_up_corrupt_state() {
        let tmp = tempdir().unwrap();
        let state_path = tmp.path().join("state.json");

        // 1. Giả lập tệp state.json cũ từ v0.1.1 lưu theo khóa đơn "neuroforge" cho kênh "rtx"
        let legacy_json = r#"{
          "settings": { "close_to_tray": true, "global_hotkey_enabled": false, "selected_channels": {} },
          "installed_ledger": {
            "neuroforge": {
              "exe_path": "C:\\Fake\\NeuroForge RTX\\neuroforge.exe",
              "exe_size": 12345,
              "exe_mtime_secs": 1700000000,
              "installed_version": "3.0.88",
              "channel": "rtx",
              "installed_at_iso": "2026-11-26T00:00:00Z"
            }
          }
        }"#;
        fs::write(&state_path, legacy_json).unwrap();

        let mut loaded = load_state_file(&state_path);
        assert!(loaded.get_ledger_entry("neuroforge", "rtx").is_some());
        assert!(
            loaded.get_ledger_entry("neuroforge", "standard").is_none(),
            "Bản ghi legacy của kênh rtx không được rò sang kênh standard"
        );

        // Nâng cấp ghi khóa ghép mới -> tự dọn khóa cũ cùng kênh
        let new_entry = loaded.get_ledger_entry("neuroforge", "rtx").unwrap().clone();
        loaded.upsert_ledger_entry("neuroforge", "rtx", new_entry);
        save_state_file(&state_path, &loaded).unwrap();

        let reloaded = load_state_file(&state_path);
        assert!(reloaded.installed_ledger.contains_key("neuroforge:rtx"));
        assert!(!reloaded.installed_ledger.contains_key("neuroforge"));

        // 2. Giả lập tệp state.json bị hỏng cú pháp JSON -> phải sao lưu ra state.json.corrupt!
        fs::write(&state_path, "{ broken json !!!").unwrap();
        let fallback = load_state_file(&state_path);
        assert!(fallback.installed_ledger.is_empty());
        let corrupt_backup = tmp.path().join("state.json.corrupt");
        assert!(
            corrupt_backup.is_file(),
            "Phải sao lưu state.json hỏng sang state.json.corrupt trước khi trả Default"
        );
    }
}
