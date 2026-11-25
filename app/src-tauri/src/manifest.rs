use base64::{Engine as _, engine::general_purpose::STANDARD};
use minisign_verify::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

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
pub struct GitSpec {
    pub repo_path: String,
    pub watch_paths: Vec<String>,
    #[serde(default = "default_tag_prefix")]
    pub tag_prefix: String,
    #[serde(default)]
    pub hot_swap_hint: Option<String>,
}

fn default_tag_prefix() -> String {
    "v".to_string()
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
        if !val.is_empty() && out.contains(token) {
            out = out.replace(token, val);
        }
    }
    out
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
    for p in &primary_candidates {
        if p.exists() {
            return p.clone();
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let beside = dir.join("ecosystem-manifest.json");
            if beside.exists() {
                return beside;
            }
            let resources = dir.join("resources").join("ecosystem-manifest.json");
            if resources.exists() {
                return resources;
            }
            let bundled_up = dir
                .join("_up_")
                .join("_up_")
                .join("ecosystem-manifest.json");
            if bundled_up.exists() {
                return bundled_up;
            }
            // Dev / cargo test fallback walking up to repo root
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

pub fn decode_tauri_pubkey(pubkey_b64: &str) -> Result<PublicKey, String> {
    let raw_bytes = STANDARD
        .decode(pubkey_b64.trim())
        .map_err(|e| format!("Khóa công khai Base64 không hợp lệ: {e}"))?;
    let raw_str = String::from_utf8(raw_bytes)
        .map_err(|e| format!("Khóa công khai không phải chuỗi UTF-8 Minisign: {e}"))?;
    PublicKey::decode(&raw_str).map_err(|e| format!("Không giải mã được khóa Ed25519 Minisign: {e}"))
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

    if manifest.tools.is_empty() {
        return Err("Danh sách tools trong manifest đang trống.".to_string());
    }

    let eco_root = expand_vars(&manifest.globals.ecosystem_root, "");
    manifest.globals.ecosystem_root = eco_root.clone();
    manifest.globals.vault_root = expand_vars(&manifest.globals.vault_root, &eco_root);

    let mut seen_ids = HashSet::new();
    for tool in &mut manifest.tools {
        if tool.id.trim().is_empty() {
            return Err(format!("Công cụ '{}' có id rỗng.", tool.name));
        }
        if !seen_ids.insert(tool.id.clone()) {
            return Err(format!("Trùng lặp id công cụ '{}' trong manifest.", tool.id));
        }
        if tool.install.exe_candidates.is_empty() {
            return Err(format!(
                "Công cụ '{}' thiếu danh sách install.exe_candidates.",
                tool.id
            ));
        }
        if !tool.updater.channels.contains_key(&tool.updater.default_channel) {
            return Err(format!(
                "Công cụ '{}' khai báo default_channel='{}' không tồn tại trong updater.channels.",
                tool.id, tool.updater.default_channel
            ));
        }
        for (ch_key, ch_spec) in &tool.updater.channels {
            decode_tauri_pubkey(&ch_spec.pubkey).map_err(|e| {
                format!("Công cụ '{}' kênh '{}': {e}", tool.id, ch_key)
            })?;
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

pub fn load_manifest_from_disk(path: &Path) -> Result<EcosystemManifest, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "Không đọc được tệp manifest tại '{}': {e}",
            path.display()
        )
    })?;
    parse_and_validate_manifest(&raw)
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
        let manifest = load_manifest_from_disk(&manifest_path)
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
        // Co-Writer bắt buộc khai báo khóa bất biến cho cowriter-core.exe
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
}
