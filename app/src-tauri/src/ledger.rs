use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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

pub fn default_state_file_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    base.join("Selorson Launcher").join("state.json")
}

pub fn load_state_file(path: &Path) -> LauncherStateFile {
    if let Ok(raw) = std::fs::read_to_string(path) {
        if let Ok(parsed) = serde_json::from_str::<LauncherStateFile>(&raw) {
            return parsed;
        }
    }
    LauncherStateFile::default()
}

pub fn save_state_file(path: &Path, state: &LauncherStateFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Không tạo được thư mục lưu trạng thái '{}': {e}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| format!("Lỗi tuần tự hóa state.json: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)
        .map_err(|e| format!("Không ghi được tệp tạm '{}': {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("Không đổi tên nguyên tử sang '{}': {e}", path.display()))?;
    Ok(())
}
