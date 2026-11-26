use base64::{Engine as _, engine::general_purpose::STANDARD};
use minisign_verify::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemManifest {
    pub schema_version: u32,
    pub ecosystem_name: String,
    pub globals: ManifestGlobals,
    pub tools: Vec<ToolManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestGlobals {
    pub ecosystem_root: String,
    pub vault_root: String,
    #[serde(default = "default_backup_gens")]
    pub max_backup_generations: usize,
    #[serde(default)]
    pub shared_gpu_busy_ports: Vec<SharedPortSpec>,
}

fn default_backup_gens() -> usize {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedPortSpec {
    pub port: u16,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifest {
    pub id: String,
    pub order: u32,
    pub name: String,
    pub subtitle: String,
    pub category: String,
    pub accent_color: String,
    #[serde(default)]
    pub icon: Option<String>,
    pub install: InstallSpec,
    pub updater: UpdaterSpec,
    #[serde(default)]
    pub protection: ProtectionSpec,
    pub git: GitSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSpec {
    pub installer_kind: String,
    pub exe_candidates: Vec<String>,
    #[serde(default)]
    pub registry_names: Vec<String>,
    pub exe_filename: String,
    #[serde(default)]
    pub launch_args: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdaterSpec {
    pub default_channel: String,
    pub channels: BTreeMap<String, ReleaseChannelSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseChannelSpec {
    pub label: String,
    pub endpoint: String,
    pub pubkey: String,
    #[serde(default)]
    pub exe_candidates: Vec<String>,
    #[serde(default)]
    pub registry_names: Vec<String>,
}

impl ToolManifest {
    pub fn effective_exe_candidates(&self, channel: &str) -> &[String] {
        if let Some(ch) = self.updater.channels.get(channel) {
            if !ch.exe_candidates.is_empty() {
                return &ch.exe_candidates;
            }
        }
        &self.install.exe_candidates
    }

    pub fn effective_registry_names(&self, channel: &str) -> &[String] {
        if let Some(ch) = self.updater.channels.get(channel) {
            if !ch.registry_names.is_empty() {
                return &ch.registry_names;
            }
        }
        &self.install.registry_names
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtectionSpec {
    #[serde(default)]
    pub running_processes: Vec<String>,
    #[serde(default)]
    pub health_ports: Vec<HealthPortSpec>,
    #[serde(default)]
    pub immutable_files: Vec<String>,
    #[serde(default)]
    pub backup_files: Vec<String>,
    #[serde(default)]
    pub verify_external_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthPortSpec {
    pub port: u16,
    pub label: String,
    #[serde(default = "default_true")]
    pub block_update_when_open: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtraGitRepoSpec {
    pub repo_path: String,
    pub watch_paths: Vec<String>,
    #[serde(default)]
    pub tag_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitSpec {
    pub repo_path: String,
    pub watch_paths: Vec<String>,
    #[serde(default)]
    pub extra_repos: Vec<ExtraGitRepoSpec>,
    #[serde(default = "default_tag_prefix")]
    pub tag_prefix: String,
    #[serde(default)]
    pub hot_swap_hint: Option<String>,
}

fn default_tag_prefix() -> String {
    "v".to_string()
}

fn replace_ascii_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() || replacement.is_empty() {
        return haystack.to_string();
    }
    let h_low = haystack.to_ascii_lowercase();
    let n_low = needle.to_ascii_lowercase();
    if !h_low.contains(&n_low) {
        return haystack.to_string();
    }

    let mut out = String::with_capacity(haystack.len() + replacement.len());
    let mut cursor = 0usize;
    while let Some(rel) = h_low[cursor..].find(&n_low) {
        let match_start = cursor + rel;
        let match_end = match_start + needle.len();
        out.push_str(&haystack[cursor..match_start]);
        out.push_str(replacement);
        cursor = match_end;
    }
    out.push_str(&haystack[cursor..]);
    out
}

pub fn expand_vars(input: &str, ecosystem_root: &str) -> String {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let app_data = std::env::var("APPDATA").unwrap_or_default();
    let user_profile = std::env::var("USERPROFILE").unwrap_or_default();
    let temp = std::env::var("TEMP").unwrap_or_default();

    let mut out = input.to_string();
    let replacements = [
        ("%ECOSYSTEM_ROOT%", ecosystem_root),
        ("%LOCALAPPDATA%", local_app_data.as_str()),
        ("%APPDATA%", app_data.as_str()),
        ("%USERPROFILE%", user_profile.as_str()),
        ("%TEMP%", temp.as_str()),
    ];
    for (token, val) in replacements {
        if !val.is_empty() {
            out = replace_ascii_case_insensitive(&out, token, val);
        }
    }
    out
}

pub fn default_override_manifest_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    base.join("Selorson Launcher")
        .join("ecosystem-manifest.override.json")
}

fn file_mtime(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

fn find_bundled_manifest_near_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    // Không coi thư mục build phát triển (`target\debug`, `target\release`) là gói cài đặt NSIS
    let dir_low = dir.to_string_lossy().to_lowercase();
    if dir_low.contains("\\target\\") {
        return None;
    }
    for cand in [
        dir.join("ecosystem-manifest.json"),
        dir.join("resources").join("ecosystem-manifest.json"),
        dir.join("_up_")
            .join("_up_")
            .join("ecosystem-manifest.json"),
    ] {
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

pub fn resolve_manifest_path() -> PathBuf {
    if let Ok(custom) = std::env::var("SELORSON_MANIFEST_PATH") {
        let p = PathBuf::from(custom);
        if p.exists() {
            return p;
        }
    }

    let primary_candidates = [
        PathBuf::from(r"E:\Selorson-Launcher\ecosystem-manifest.json"),
        PathBuf::from(r"E:\Selorson-Ecosystem\Launcher\ecosystem-manifest.json"),
    ];
    let existing_primary = primary_candidates.iter().find(|p| p.is_file()).cloned();
    let bundled = find_bundled_manifest_near_exe();

    match (existing_primary, bundled) {
        (Some(repo_p), Some(bun_p)) => {
            // Nếu bản đóng gói NSIS mới hơn kho nguồn chưa git pull -> dùng bản mới hơn để không bị che khuất
            return match (file_mtime(&repo_p), file_mtime(&bun_p)) {
                (Some(rm), Some(bm)) if bm > rm => bun_p,
                _ => repo_p,
            };
        }
        (Some(repo_p), None) => return repo_p,
        (None, Some(bun_p)) => return bun_p,
        (None, None) => {}
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let mut cursor = Some(dir);
            for _ in 0..6 {
                if let Some(c) = cursor {
                    let candidate = c.join("ecosystem-manifest.json");
                    if candidate.exists() {
                        return candidate;
                    }
                    cursor = c.parent();
                }
            }
        }
    }

    primary_candidates[0].clone()
}

/// Trộn tệp mở rộng `ecosystem-manifest.override.json` (chứa các công cụ thứ 8+ hoặc ghi đè theo `id`)
/// lên trên manifest gốc để tự cập nhật NSIS không bao giờ làm mất công cụ người dùng thêm vào.
pub fn merge_manifest_override(base_json: &str, override_json: &str) -> Result<String, String> {
    let mut base_val: serde_json::Value = serde_json::from_str(base_json)
        .map_err(|e| format!("Lỗi cú pháp JSON trong ecosystem-manifest.json: {e}"))?;
    let over_val: serde_json::Value = serde_json::from_str(override_json)
        .map_err(|e| format!("Lỗi cú pháp JSON trong ecosystem-manifest.override.json: {e}"))?;

    if let Some(over_globals) = over_val.get("globals").and_then(|g| g.as_object()) {
        if let Some(base_globals) = base_val.get_mut("globals").and_then(|g| g.as_object_mut()) {
            for (k, v) in over_globals {
                base_globals.insert(k.clone(), v.clone());
            }
        }
    }

    if let Some(over_tools) = over_val.get("tools").and_then(|t| t.as_array()) {
        let base_tools = base_val
            .get_mut("tools")
            .and_then(|t| t.as_array_mut())
            .ok_or_else(|| "Trường 'tools' trong manifest gốc không phải mảng.".to_string())?;

        for ot in over_tools {
            let Some(oid) = ot.get("id").and_then(|v| v.as_str()) else {
                return Err(
                    "Một phần tử trong ecosystem-manifest.override.json thiếu trường 'id'."
                        .to_string(),
                );
            };
            if let Some(existing_slot) = base_tools
                .iter_mut()
                .find(|bt| bt.get("id").and_then(|v| v.as_str()) == Some(oid))
            {
                *existing_slot = ot.clone();
            } else {
                base_tools.push(ot.clone());
            }
        }
    }

    serde_json::to_string(&base_val)
        .map_err(|e| format!("Lỗi hợp nhất ecosystem-manifest.override.json: {e}"))
}

pub fn decode_tauri_pubkey(pubkey_b64: &str) -> Result<PublicKey, String> {
    let raw_bytes = STANDARD
        .decode(pubkey_b64.trim())
        .map_err(|e| format!("Khóa công khai Base64 không hợp lệ: {e}"))?;
    let raw_str = String::from_utf8(raw_bytes)
        .map_err(|e| format!("Khóa công khai không phải chuỗi UTF-8 Minisign: {e}"))?;
    PublicKey::decode(&raw_str)
        .map_err(|e| format!("Không giải mã được khóa Ed25519 Minisign: {e}"))
}

fn is_valid_tool_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn is_valid_hex_color(color: &str) -> bool {
    color.len() == 7
        && color.starts_with('#')
        && color[1..].chars().all(|c| c.is_ascii_hexdigit())
}

fn is_safe_exe_filename(fname: &str) -> bool {
    let trimmed = fname.trim();
    !trimmed.is_empty()
        && trimmed == fname
        && !fname.contains('/')
        && !fname.contains('\\')
        && !fname.contains("..")
        && !fname.contains(':')
}

fn validate_watch_paths(tool_id: &str, watch_paths: &[String]) -> Result<(), String> {
    if watch_paths.is_empty() {
        return Err(format!(
            "Công cụ '{}' thiếu danh sách git.watch_paths.",
            tool_id
        ));
    }
    for wp in watch_paths {
        if wp.trim().is_empty() {
            return Err(format!(
                "Công cụ '{}' có phần tử rỗng trong git.watch_paths.",
                tool_id
            ));
        }
        if Path::new(wp)
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_) | Component::RootDir))
        {
            return Err(format!(
                "Công cụ '{}' khai báo git.watch_paths='{}' không hợp lệ (chỉ chấp nhận đường dẫn tương đối bên trong kho Git).",
                tool_id, wp
            ));
        }
    }
    Ok(())
}

pub fn parse_and_validate_manifest(raw_json: &str) -> Result<EcosystemManifest, String> {
    let mut manifest: EcosystemManifest = serde_json::from_str(raw_json)
        .map_err(|e| format!("Lỗi cú pháp JSON trong ecosystem-manifest.json: {e}"))?;

    if manifest.schema_version != 1 {
        return Err(format!(
            "Phiên bản schema_version={} không được hỗ trợ (yêu cầu schema_version=1).",
            manifest.schema_version
        ));
    }

    if manifest.ecosystem_name.trim().is_empty() {
        return Err("Trường ecosystem_name trong manifest không được để trống.".to_string());
    }

    if manifest.globals.ecosystem_root.trim().is_empty()
        || manifest.globals.vault_root.trim().is_empty()
    {
        return Err(
            "globals.ecosystem_root và globals.vault_root không được để trống.".to_string(),
        );
    }

    if manifest.globals.max_backup_generations < 1 {
        return Err("globals.max_backup_generations bắt buộc >= 1.".to_string());
    }

    for sp in &manifest.globals.shared_gpu_busy_ports {
        if sp.port == 0 {
            return Err(format!(
                "Cổng dùng chung '{}' có số cổng 0 không hợp lệ.",
                sp.label
            ));
        }
    }

    if manifest.tools.is_empty() {
        return Err("Danh sách tools trong manifest đang trống.".to_string());
    }

    let eco_root = expand_vars(&manifest.globals.ecosystem_root, "");
    manifest.globals.ecosystem_root = eco_root.clone();
    manifest.globals.vault_root = expand_vars(&manifest.globals.vault_root, &eco_root);

    let mut seen_ids = HashSet::new();
    for tool in &mut manifest.tools {
        if !is_valid_tool_id(&tool.id) {
            return Err(format!(
                "Công cụ '{}' có id='{}' không hợp lệ (chỉ cho phép ký tự thường a-z, chữ số 0-9 và dấu gạch ngang '-' để chống Path Traversal).",
                tool.name, tool.id
            ));
        }
        if !seen_ids.insert(tool.id.clone()) {
            return Err(format!(
                "Trùng lặp id công cụ '{}' trong manifest.",
                tool.id
            ));
        }
        if tool.order == 0 {
            return Err(format!("Công cụ '{}' có order=0 (yêu cầu >= 1).", tool.id));
        }
        if tool.name.trim().is_empty() {
            return Err(format!("Công cụ '{}' có name rỗng.", tool.id));
        }
        if !is_valid_hex_color(&tool.accent_color) {
            return Err(format!(
                "Công cụ '{}' có mã màu accent_color='{}' sai định dạng #RRGGBB.",
                tool.id, tool.accent_color
            ));
        }
        if tool.install.installer_kind != "tauri-nsis" {
            return Err(format!(
                "Công cụ '{}' khai báo installer_kind='{}' chưa hỗ trợ (chỉ chấp nhận 'tauri-nsis').",
                tool.id, tool.install.installer_kind
            ));
        }
        if !is_safe_exe_filename(&tool.install.exe_filename) {
            return Err(format!(
                "Công cụ '{}' có install.exe_filename='{}' không hợp lệ (chỉ được phép là tên tệp đơn, không chứa dấu phân cách đường dẫn).",
                tool.id, tool.install.exe_filename
            ));
        }
        if tool.install.exe_candidates.is_empty()
            || tool
                .install
                .exe_candidates
                .iter()
                .any(|c| c.trim().is_empty())
        {
            return Err(format!(
                "Công cụ '{}' thiếu hoặc có phần tử rỗng trong install.exe_candidates.",
                tool.id
            ));
        }
        if tool.updater.channels.is_empty() {
            return Err(format!(
                "Công cụ '{}' chưa khai báo kênh nào trong updater.channels.",
                tool.id
            ));
        }
        if !tool
            .updater
            .channels
            .contains_key(&tool.updater.default_channel)
        {
            return Err(format!(
                "Công cụ '{}' khai báo default_channel='{}' không tồn tại trong updater.channels.",
                tool.id, tool.updater.default_channel
            ));
        }
        for (ch_key, ch_spec) in &mut tool.updater.channels {
            if !ch_spec.endpoint.trim().starts_with("https://") {
                return Err(format!(
                    "Công cụ '{}' kênh '{}': endpoint bắt buộc dùng giao thức https:// ('{}').",
                    tool.id, ch_key, ch_spec.endpoint
                ));
            }
            if ch_spec.pubkey.trim().len() < 40 {
                return Err(format!(
                    "Công cụ '{}' kênh '{}': khóa pubkey quá ngắn.",
                    tool.id, ch_key
                ));
            }
            decode_tauri_pubkey(&ch_spec.pubkey)
                .map_err(|e| format!("Công cụ '{}' kênh '{}': {e}", tool.id, ch_key))?;
            if ch_spec.exe_candidates.iter().any(|c| c.trim().is_empty()) {
                return Err(format!(
                    "Công cụ '{}' kênh '{}' có exe_candidates rỗng.",
                    tool.id, ch_key
                ));
            }
            ch_spec.exe_candidates = ch_spec
                .exe_candidates
                .iter()
                .map(|s| expand_vars(s, &eco_root))
                .collect();
        }

        for hp in &tool.protection.health_ports {
            if hp.port == 0 {
                return Err(format!(
                    "Công cụ '{}' có health_ports chứa cổng 0 không hợp lệ.",
                    tool.id
                ));
            }
        }

        if tool.git.repo_path.trim().is_empty() {
            return Err(format!("Công cụ '{}' có git.repo_path rỗng.", tool.id));
        }
        validate_watch_paths(&tool.id, &tool.git.watch_paths)?;
        for extra in &mut tool.git.extra_repos {
            if extra.repo_path.trim().is_empty() {
                return Err(format!(
                    "Công cụ '{}' có phần tử extra_repos thiếu repo_path.",
                    tool.id
                ));
            }
            validate_watch_paths(&tool.id, &extra.watch_paths)?;
            extra.repo_path = expand_vars(&extra.repo_path, &eco_root);
        }

        if let Some(icon) = &tool.icon {
            tool.icon = Some(expand_vars(icon, &eco_root));
        }
        tool.install.exe_candidates = tool
            .install
            .exe_candidates
            .iter()
            .map(|s| expand_vars(s, &eco_root))
            .collect();
        if let Some(wd) = &tool.install.working_dir {
            tool.install.working_dir = Some(expand_vars(wd, &eco_root));
        }
        tool.protection.immutable_files = tool
            .protection
            .immutable_files
            .iter()
            .map(|s| expand_vars(s, &eco_root))
            .collect();
        tool.protection.backup_files = tool
            .protection
            .backup_files
            .iter()
            .map(|s| expand_vars(s, &eco_root))
            .collect();
        tool.protection.verify_external_paths = tool
            .protection
            .verify_external_paths
            .iter()
            .map(|s| expand_vars(s, &eco_root))
            .collect();
        tool.git.repo_path = expand_vars(&tool.git.repo_path, &eco_root);
    }

    manifest
        .tools
        .sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.name.cmp(&b.name)));

    Ok(manifest)
}

pub fn load_manifest_from_disk_with_override(
    path: &Path,
    override_path: Option<&Path>,
) -> Result<EcosystemManifest, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "Không đọc được tệp manifest tại '{}': {e}",
            path.display()
        )
    })?;

    let merged = if let Some(ov_p) = override_path.filter(|p| p.is_file()) {
        let ov_raw = std::fs::read_to_string(ov_p).map_err(|e| {
            format!(
                "Không đọc được tệp mở rộng manifest tại '{}': {e}",
                ov_p.display()
            )
        })?;
        merge_manifest_override(&raw, &ov_raw)?
    } else {
        raw
    };

    parse_and_validate_manifest(&merged)
}

pub fn load_manifest_from_disk(path: &Path) -> Result<EcosystemManifest, String> {
    // Chỉ tự động nạp tệp override người dùng khi đang đọc manifest hệ thống (không ảnh hưởng các unit test cô lập)
    let ov = default_override_manifest_path();
    let use_ov = if ov.is_file() && path == resolve_manifest_path() {
        Some(ov.as_path())
    } else {
        None
    };
    load_manifest_from_disk_with_override(path, use_ov)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_real_ecosystem_manifest_with_all_7_tools_and_valid_pubkeys() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("ecosystem-manifest.json");
        let manifest = load_manifest_from_disk_with_override(&manifest_path, None)
            .expect("Phải nạp và xác thực thành công ecosystem-manifest.json thật");
        assert_eq!(manifest.tools.len(), 7);
        let ids: Vec<&str> = manifest.tools.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "cowriter",
                "toneforge",
                "akunarch",
                "selorson-admin",
                "neuroforge",
                "filmforge",
                "castcam"
            ]
        );
        let cw = manifest.tools.iter().find(|t| t.id == "cowriter").unwrap();
        assert!(
            cw.protection
                .immutable_files
                .iter()
                .any(|p| p.to_lowercase().ends_with("cowriter-core.exe"))
        );
    }

    #[test]
    fn supports_adding_eighth_tool_purely_via_manifest_json() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("ecosystem-manifest.json");
        let raw = std::fs::read_to_string(&manifest_path).unwrap();
        let mut val: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let eighth = serde_json::json!({
            "id": "loreweaver-studio",
            "order": 8,
            "name": "LoreWeaver Studio",
            "subtitle": "Công cụ thứ 8 thử nghiệm mở rộng động không sửa code",
            "category": "Thử nghiệm",
            "accent_color": "#06B6D4",
            "install": {
                "installer_kind": "tauri-nsis",
                "exe_candidates": ["%LOCALAPPDATA%\\LoreWeaver\\loreweaver.exe"],
                "registry_names": ["LoreWeaver"],
                "exe_filename": "loreweaver.exe"
            },
            "updater": {
                "default_channel": "stable",
                "channels": {
                    "stable": {
                        "label": "Bản chính thức",
                        "endpoint": "https://github.com/Selorson/LoreWeaver-Release/releases/latest/download/latest.json",
                        "pubkey": "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDkyN0Q2MUM0NEFFOTlGMDMKUldRRG4rbEt4R0Y5a20yTUJtM1RZQlAvSkFjUGo0V3FMdW9sY20wSlU0U09LNGllY3pwZlNtZ28K"
                    }
                }
            },
            "protection": {
                "running_processes": ["loreweaver.exe"],
                "immutable_files": []
            },
            "git": {
                "repo_path": "%ECOSYSTEM_ROOT%\\LoreWeaver",
                "watch_paths": ["app"]
            }
        });
        val["tools"].as_array_mut().unwrap().push(eighth);

        let parsed = parse_and_validate_manifest(&serde_json::to_string(&val).unwrap())
            .expect("Công cụ thứ 8 phải được nạp tự động không cần sửa code");
        assert_eq!(parsed.tools.len(), 8);
        assert_eq!(parsed.tools[7].id, "loreweaver-studio");
    }

    #[test]
    fn rejects_path_traversal_css_injection_http_endpoints_and_expands_case_insensitive_vars() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("ecosystem-manifest.json");
        let base_raw = std::fs::read_to_string(&manifest_path).unwrap();

        // 1. Chặn Path Traversal trong tool.id
        let mut bad_id: serde_json::Value = serde_json::from_str(&base_raw).unwrap();
        bad_id["tools"][0]["id"] = serde_json::json!("../escape");
        assert!(parse_and_validate_manifest(&bad_id.to_string()).is_err());

        // 2. Chặn dấu phân cách trong install.exe_filename
        let mut bad_exe: serde_json::Value = serde_json::from_str(&base_raw).unwrap();
        bad_exe["tools"][0]["install"]["exe_filename"] = serde_json::json!("..\\evil.exe");
        assert!(parse_and_validate_manifest(&bad_exe.to_string()).is_err());

        // 3. Chặn CSS injection qua accent_color
        let mut bad_color: serde_json::Value = serde_json::from_str(&base_raw).unwrap();
        bad_color["tools"][0]["accent_color"] = serde_json::json!("#F59E0B; background:red");
        assert!(parse_and_validate_manifest(&bad_color.to_string()).is_err());

        // 4. Chặn endpoint không dùng https://
        let mut bad_http: serde_json::Value = serde_json::from_str(&base_raw).unwrap();
        bad_http["tools"][0]["updater"]["channels"]["stable"]["endpoint"] =
            serde_json::json!("http://insecure.example.com/latest.json");
        assert!(parse_and_validate_manifest(&bad_http.to_string()).is_err());

        // 5. Mở rộng biến môi trường không phân biệt chữ hoa - thường & merge override công cụ thứ 8
        let expanded = expand_vars("%ecosystem_root%\\TestTool", "E:\\EcoRoot");
        assert_eq!(expanded, "E:\\EcoRoot\\TestTool");

        let override_json = serde_json::json!({
            "tools": [{
                "id": "eighth-override-tool",
                "order": 8,
                "name": "Override Tool",
                "subtitle": "Bền vững qua NSIS update",
                "category": "Mở rộng",
                "accent_color": "#22C55E",
                "install": {
                    "installer_kind": "tauri-nsis",
                    "exe_candidates": ["%localappdata%\\Override\\override.exe"],
                    "exe_filename": "override.exe"
                },
                "updater": {
                    "default_channel": "stable",
                    "channels": {
                        "stable": {
                            "label": "Stable",
                            "endpoint": "https://github.com/Selorson/Test/releases/latest/download/latest.json",
                            "pubkey": "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDkyN0Q2MUM0NEFFOTlGMDMKUldRRG4rbEt4R0Y5a20yTUJtM1RZQlAvSkFjUGo0V3FMdW9sY20wSlU0U09LNGllY3pwZlNtZ28K"
                        }
                    }
                },
                "git": {
                    "repo_path": "%ecosystem_root%\\Override",
                    "watch_paths": ["src"]
                }
            }]
        })
        .to_string();
        let merged = merge_manifest_override(&base_raw, &override_json).unwrap();
        let parsed = parse_and_validate_manifest(&merged).unwrap();
        assert_eq!(parsed.tools.len(), 8);
        assert_eq!(parsed.tools[7].id, "eighth-override-tool");
    }
}
