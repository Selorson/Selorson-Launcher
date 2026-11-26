pub mod discovery;
pub mod git_drift;
pub mod guardian_vault;
pub mod installer;
pub mod ledger;
pub mod manifest;
pub mod release_probe;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use discovery::{
    DiscoveredToolLocal, OpenPortStatus, capture_running_processes, discover_tool_local,
    focus_existing_process_window, normalize_semver, path_is_within_dir, probe_tcp_port,
    scan_uninstall_registry,
};
use git_drift::{GitRepoReport, inspect_git_drift};
use guardian_vault::{
    execute_rollback, find_latest_rollback_snapshot, recover_incomplete_transactions,
};
use installer::{
    InstallProgressEvent, InstallResultDto, execute_protected_install, launch_tool_detached,
};
use ledger::{
    LauncherSettings, LauncherStateFile, default_state_file_path, load_state_file, save_state_file,
};
use manifest::{
    EcosystemManifest, ReleaseChannelSpec, default_override_manifest_path, load_manifest_from_disk,
    resolve_manifest_path,
};
use release_probe::{
    ReleaseComparisonState, RemoteReleaseInfo, build_http_client, compare_installed_vs_remote,
    fetch_remote_release,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, UNIX_EPOCH};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{
    AppHandle, Emitter, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent,
};
use tokio::sync::{Mutex, RwLock};

const MAX_ICON_BYTES: u64 = 2 * 1024 * 1024; // 2 MB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelOptionDto {
    pub key: String,
    pub label: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolFullStatusDto {
    pub id: String,
    pub order: u32,
    pub name: String,
    pub subtitle: String,
    pub category: String,
    pub accent_color: String,
    pub icon_path: Option<String>,
    pub icon_data_url: Option<String>,
    pub selected_channel: String,
    pub available_channels: Vec<ChannelOptionDto>,
    pub repo_path: String,
    pub watch_paths: Vec<String>,
    pub extra_repo_paths: Vec<String>,
    pub tag_prefix: String,
    pub hot_swap_hint: Option<String>,
    pub local: DiscoveredToolLocal,
    pub git: GitRepoReport,
    pub remote: Option<RemoteReleaseInfo>,
    pub remote_error: Option<String>,
    pub release_state: ReleaseComparisonState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemSnapshotDto {
    pub ecosystem_name: String,
    pub manifest_path: String,
    pub ecosystem_root: String,
    pub vault_root: String,
    pub shared_ports: Vec<OpenPortStatus>,
    pub settings: LauncherSettings,
    pub tools: Vec<ToolFullStatusDto>,
    pub checked_at_iso: String,
    pub active_install_tool_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestValidationDto {
    pub valid: bool,
    pub manifest_path: String,
    pub tool_count: usize,
    pub message: String,
}

pub struct AppSharedState {
    pub manifest_path: PathBuf,
    pub state_file_path: PathBuf,
    pub state_file: RwLock<LauncherStateFile>,
    pub cached_remotes: RwLock<HashMap<(String, String), Result<RemoteReleaseInfo, String>>>,
    pub icon_cache: std::sync::Mutex<HashMap<String, (u64, u64, String)>>,
    pub install_mutex: Mutex<()>,
    pub active_install_tool_id: std::sync::Mutex<Option<String>>,
    pub http_client: reqwest::Client,
    pub explicit_quit: AtomicBool,
    pub close_to_tray_active: AtomicBool,
    pub hotkey_active: AtomicBool,
}

struct ActiveInstallScope<'a> {
    shared: &'a AppSharedState,
}

impl<'a> ActiveInstallScope<'a> {
    fn enter(shared: &'a AppSharedState, tool_id: String) -> Self {
        if let Ok(mut guard) = shared.active_install_tool_id.lock() {
            *guard = Some(tool_id);
        }
        Self { shared }
    }
}

impl Drop for ActiveInstallScope<'_> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.shared.active_install_tool_id.lock() {
            *guard = None;
        }
    }
}

/// Đọc icon đã khai báo trong Manifest thành Data URL (`data:image/png;base64,...`) có bộ nhớ đệm `(mtime, size)`,
/// hoạt động ổn định 100% xuyên qua NTFS Junction (`D:\`, `E:\`, `F:\`) mà không cần mở rộng `assetProtocol.scope`.
fn load_safe_icon_data_url(
    icon_path_str: &str,
    cache: &std::sync::Mutex<HashMap<String, (u64, u64, String)>>,
) -> Option<String> {
    let p = Path::new(icon_path_str);
    let ext = p.extension()?.to_str()?.to_ascii_lowercase();
    let mime = match ext.as_str() {
        "png" => "image/png",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        _ => return None,
    };

    let meta = std::fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_ICON_BYTES {
        return None;
    }
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    let size = meta.len();

    if let Ok(guard) = cache.lock() {
        if let Some((cached_mtime, cached_size, data_url)) = guard.get(icon_path_str) {
            if *cached_mtime == mtime && *cached_size == size {
                return Some(data_url.clone());
            }
        }
    }

    let bytes = std::fs::read(p).ok()?;
    let data_url = format!("data:{mime};base64,{}", STANDARD.encode(&bytes));
    if let Ok(mut guard) = cache.lock() {
        guard.insert(icon_path_str.to_string(), (mtime, size, data_url.clone()));
    }
    Some(data_url)
}

pub fn show_or_recreate_main_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.unminimize();
        let _ = win.show();
        let _ = win.set_focus();
        return;
    }

    // Dựng lại cửa sổ sau khi đã giải phóng ~100 MB RAM WebView2, đồng bộ nền tối #0E1B1D không chớp trắng
    if let Ok(win) = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("/".into()))
        .title("Selorson Launcher — Trung Tâm Điều Phối Hệ Sinh Thái")
        .inner_size(1440.0, 920.0)
        .min_inner_size(1040.0, 680.0)
        .center()
        .resizable(true)
        .theme(Some(tauri::Theme::Dark))
        .background_color(tauri::window::Color(14, 27, 29, 255))
        .build()
    {
        let _ = win.set_focus();
    }
}

async fn build_snapshot(
    shared: Arc<AppSharedState>,
    force_remote: bool,
) -> Result<EcosystemSnapshotDto, String> {
    let manifest_path = shared.manifest_path.clone();
    let manifest: EcosystemManifest =
        tokio::task::spawn_blocking(move || load_manifest_from_disk(&manifest_path))
            .await
            .map_err(|e| format!("Lỗi luồng đọc manifest: {e}"))??;
    let state_guard = shared.state_file.read().await.clone();

    // 1. Quét tiến trình, Registry & toàn bộ cổng TCP trên spawn_blocking (dò mỗi cổng đúng 1 lần duy nhất)
    let mut unique_ports: Vec<u16> = manifest
        .globals
        .shared_gpu_busy_ports
        .iter()
        .map(|sp| sp.port)
        .collect();
    for t in &manifest.tools {
        for hp in &t.protection.health_ports {
            if !unique_ports.contains(&hp.port) {
                unique_ports.push(hp.port);
            }
        }
    }

    let shared_port_specs = manifest.globals.shared_gpu_busy_ports.clone();
    let (running_procs, registry_apps, port_map, shared_ports) =
        tokio::task::spawn_blocking(move || {
            let procs = Arc::new(capture_running_processes());
            let regs = Arc::new(scan_uninstall_registry());
            let mut pmap = HashMap::new();
            for p in unique_ports {
                pmap.insert(p, probe_tcp_port(p));
            }
            let mut sports = Vec::new();
            for sp in &shared_port_specs {
                sports.push(OpenPortStatus {
                    port: sp.port,
                    label: sp.label.clone(),
                    is_open: pmap.get(&sp.port).copied().unwrap_or(false),
                    blocks_update: false,
                });
            }
            (procs, regs, Arc::new(pmap), sports)
        })
        .await
        .map_err(|e| format!("Lỗi luồng quét trạng thái hệ thống: {e}"))?;

    // 2. Nạp thông tin kênh phát hành từ GitHub song song (nếu force_remote hoặc chưa có trong bộ đệm)
    {
        let mut to_fetch: Vec<(String, String, String, String)> = Vec::new();
        {
            let cache = shared.cached_remotes.read().await;
            for tool in &manifest.tools {
                let ch_key = state_guard
                    .settings
                    .selected_channels
                    .get(&tool.id)
                    .filter(|k| tool.updater.channels.contains_key(*k))
                    .cloned()
                    .unwrap_or_else(|| tool.updater.default_channel.clone());
                if force_remote || !cache.contains_key(&(tool.id.clone(), ch_key.clone())) {
                    if let Some(ch_spec) = tool.updater.channels.get(&ch_key) {
                        to_fetch.push((
                            tool.id.clone(),
                            ch_key,
                            ch_spec.endpoint.clone(),
                            tool.git.tag_prefix.clone(),
                        ));
                    }
                }
            }
        }

        if !to_fetch.is_empty() {
            let mut join_set = tokio::task::JoinSet::new();
            for (tid, ch_key, endpoint, tag_pref) in to_fetch {
                let client = shared.http_client.clone();
                join_set.spawn(async move {
                    let res = fetch_remote_release(&client, &ch_key, &endpoint, &tag_pref).await;
                    ((tid, ch_key), res)
                });
            }
            let mut cache = shared.cached_remotes.write().await;
            while let Some(Ok((key, res))) = join_set.join_next().await {
                cache.insert(key, res);
            }
        }
    }

    let remote_cache = shared.cached_remotes.read().await.clone();

    // 3. Quét song song trạng thái cục bộ + Git Drift cho toàn bộ N công cụ
    let vault_root_path = Arc::new(PathBuf::from(&manifest.globals.vault_root));
    let mut tool_tasks = tokio::task::JoinSet::new();
    for tool in manifest.tools {
        let procs = Arc::clone(&running_procs);
        let regs = Arc::clone(&registry_apps);
        let pmap = Arc::clone(&port_map);
        let vroot = Arc::clone(&vault_root_path);
        let shared_for_icon = Arc::clone(&shared);
        let selected_ch = state_guard
            .settings
            .selected_channels
            .get(&tool.id)
            .filter(|k| tool.updater.channels.contains_key(*k))
            .cloned()
            .unwrap_or_else(|| tool.updater.default_channel.clone());
        let ledger_entry = state_guard
            .get_ledger_entry(&tool.id, &selected_ch)
            .cloned();
        let rem_res = remote_cache
            .get(&(tool.id.clone(), selected_ch.clone()))
            .cloned()
            .unwrap_or_else(|| Err("Chưa kiểm tra kênh phát hành.".to_string()));

        tool_tasks.spawn(async move {
            let tool_for_local = tool.clone();
            let sel_ch_for_local = selected_ch.clone();
            let (local, icon_path, icon_data_url) = tokio::task::spawn_blocking(move || {
                let mut loc = discover_tool_local(
                    &tool_for_local,
                    &sel_ch_for_local,
                    &procs,
                    &regs,
                    ledger_entry.as_ref(),
                    Some(&pmap),
                );
                if let Some((_, snap_meta)) = find_latest_rollback_snapshot(
                    &vroot,
                    &tool_for_local.id,
                    Some(&sel_ch_for_local),
                ) {
                    loc.can_rollback = true;
                    loc.rollback_target_version = snap_meta.installed_version;
                }
                let ipath = tool_for_local
                    .icon
                    .as_ref()
                    .filter(|p| Path::new(p).is_file())
                    .cloned();
                let idata = ipath
                    .as_deref()
                    .and_then(|p| load_safe_icon_data_url(p, &shared_for_icon.icon_cache));
                (loc, ipath, idata)
            })
            .await
            .unwrap_or_else(|_| {
                (
                    DiscoveredToolLocal {
                        is_installed: false,
                        active_exe_path: None,
                        all_detected_exes: Vec::new(),
                        installed_version: None,
                        version_source: None,
                        exe_mtime_secs: None,
                        is_running: false,
                        active_processes: Vec::new(),
                        open_ports: Vec::new(),
                        immutable_guards: Vec::new(),
                        can_rollback: false,
                        rollback_target_version: None,
                        is_verified_ledger_install: false,
                        matched_pids: Vec::new(),
                    },
                    None,
                    None,
                )
            });

            let git = inspect_git_drift(
                &tool.git,
                local.installed_version.as_deref(),
                local.exe_mtime_secs,
                local.is_verified_ledger_install,
            )
            .await;

            let release_state = compare_installed_vs_remote(
                local.is_installed,
                local.installed_version.as_deref(),
                &tool.git.tag_prefix,
                &rem_res,
                &git.drift_status,
            );

            let available_channels: Vec<ChannelOptionDto> = tool
                .updater
                .channels
                .iter()
                .map(|(k, v): (&String, &ReleaseChannelSpec)| ChannelOptionDto {
                    key: k.clone(),
                    label: v.label.clone(),
                    endpoint: v.endpoint.clone(),
                })
                .collect();

            let extra_repo_paths: Vec<String> = tool
                .git
                .extra_repos
                .iter()
                .map(|er| er.repo_path.clone())
                .collect();

            let (remote, remote_error) = match rem_res {
                Ok(r) => (Some(r), None),
                Err(e) => (None, Some(e)),
            };

            ToolFullStatusDto {
                id: tool.id,
                order: tool.order,
                name: tool.name,
                subtitle: tool.subtitle,
                category: tool.category,
                accent_color: tool.accent_color,
                icon_path,
                icon_data_url,
                selected_channel: selected_ch,
                available_channels,
                repo_path: tool.git.repo_path,
                watch_paths: tool.git.watch_paths,
                extra_repo_paths,
                tag_prefix: tool.git.tag_prefix,
                hot_swap_hint: tool.git.hot_swap_hint,
                local,
                git,
                remote,
                remote_error,
                release_state,
            }
        });
    }

    let mut tools = Vec::new();
    while let Some(Ok(dto)) = tool_tasks.join_next().await {
        tools.push(dto);
    }
    tools.sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.name.cmp(&b.name)));

    let active_install_tool_id = shared
        .active_install_tool_id
        .lock()
        .ok()
        .and_then(|g| g.clone());

    Ok(EcosystemSnapshotDto {
        ecosystem_name: manifest.ecosystem_name,
        manifest_path: shared.manifest_path.to_string_lossy().to_string(),
        ecosystem_root: manifest.globals.ecosystem_root,
        vault_root: manifest.globals.vault_root,
        shared_ports,
        settings: state_guard.settings,
        tools,
        checked_at_iso: chrono::Local::now()
            .format("%H:%M:%S · %d/%m/%Y")
            .to_string(),
        active_install_tool_id,
    })
}

#[tauri::command]
async fn get_ecosystem_snapshot(
    state: tauri::State<'_, Arc<AppSharedState>>,
    force_remote: bool,
) -> Result<EcosystemSnapshotDto, String> {
    build_snapshot(Arc::clone(&state), force_remote).await
}

#[tauri::command]
async fn launch_tool(
    state: tauri::State<'_, Arc<AppSharedState>>,
    tool_id: String,
) -> Result<String, String> {
    if state
        .active_install_tool_id
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .is_some()
        || state.install_mutex.try_lock().is_err()
    {
        return Err(
            "Đang thực thi giao dịch cài đặt / khôi phục Guardian Vault — vui lòng chờ hoàn tất trước khi khởi chạy công cụ!"
                .to_string(),
        );
    }

    let manifest_path = state.manifest_path.clone();
    let st_snapshot = state.state_file.read().await.clone();

    tokio::task::spawn_blocking(move || -> Result<String, String> {
        let manifest = load_manifest_from_disk(&manifest_path)?;
        let tool = manifest
            .tools
            .iter()
            .find(|t| t.id == tool_id)
            .ok_or_else(|| format!("Không tìm thấy công cụ '{}' trong manifest.", tool_id))?;

        let selected_ch = st_snapshot
            .settings
            .selected_channels
            .get(&tool.id)
            .filter(|k| tool.updater.channels.contains_key(*k))
            .cloned()
            .unwrap_or_else(|| tool.updater.default_channel.clone());
        let ledger_entry = st_snapshot.get_ledger_entry(&tool.id, &selected_ch);

        let procs = capture_running_processes();
        let regs = scan_uninstall_registry();
        let local = discover_tool_local(tool, &selected_ch, &procs, &regs, ledger_entry, None);

        let exe_str = local.active_exe_path.ok_or_else(|| {
            format!(
                "{} (kênh '{}') chưa được cài đặt trên máy. Hãy bấm 'Cài đặt' để tải bản chính thức!",
                tool.name, selected_ch
            )
        })?;

        if local.is_running {
            if focus_existing_process_window(&local.matched_pids) {
                return Ok(exe_str);
            }
            if !local.active_processes.is_empty() {
                return Err(format!(
                    "{} đang hoạt động ở chế độ nền ({}). Không mở chồng bản sao thứ 2 để bảo vệ cơ sở dữ liệu!",
                    tool.name,
                    local.active_processes.join(", ")
                ));
            }
            let busy_ports: Vec<String> = local
                .open_ports
                .iter()
                .filter(|p| p.is_open && p.blocks_update)
                .map(|p| p.label.clone())
                .collect();
            if !busy_ports.is_empty() {
                return Err(format!(
                    "Cổng dịch vụ của {} đang bận ({}). Hãy kiểm tra tiến trình đang chiếm cổng trước khi mở mới.",
                    tool.name,
                    busy_ports.join(", ")
                ));
            }
        }

        launch_tool_detached(tool, Path::new(&exe_str))?;
        Ok(exe_str)
    })
    .await
    .map_err(|e| format!("Lỗi luồng khởi chạy công cụ: {e}"))?
}

fn verify_not_downgrade(
    tool_name: &str,
    channel: &str,
    tag_prefix: &str,
    installed_ver: Option<&str>,
    remote_ver: &str,
) -> Result<(), String> {
    let Some(inst_raw) = installed_ver else {
        return Ok(());
    };
    let (Some(inst_sv), Some(rem_sv)) = (
        normalize_semver(inst_raw, Some(tag_prefix)),
        normalize_semver(remote_ver, Some(tag_prefix)),
    ) else {
        return Ok(());
    };
    if rem_sv < inst_sv {
        return Err(format!(
            "CHẶN HẠ CẤP AN TOÀN: Phiên bản từ xa trên kênh '{}' (v{}) thấp hơn phiên bản đang cài của {} (v{}). Nếu muốn lùi phiên bản an toàn, hãy dùng nút Khôi phục (⏪) từ Guardian Vault.",
            channel, rem_sv, tool_name, inst_sv
        ));
    }
    Ok(())
}

#[tauri::command]
async fn install_or_update_tool(
    app: AppHandle,
    state: tauri::State<'_, Arc<AppSharedState>>,
    tool_id: String,
) -> Result<InstallResultDto, String> {
    let _install_guard = state.install_mutex.lock().await;
    let _active_scope = ActiveInstallScope::enter(&state, tool_id.clone());

    let manifest_path = state.manifest_path.clone();
    let manifest = tokio::task::spawn_blocking(move || load_manifest_from_disk(&manifest_path))
        .await
        .map_err(|e| format!("Lỗi luồng đọc manifest: {e}"))??;
    let tool = manifest
        .tools
        .iter()
        .find(|t| t.id == tool_id)
        .cloned()
        .ok_or_else(|| format!("Không tìm thấy công cụ '{}' trong manifest.", tool_id))?;

    let (selected_ch, prev_ledger) = {
        let st = state.state_file.read().await;
        let ch = st
            .settings
            .selected_channels
            .get(&tool.id)
            .filter(|k| tool.updater.channels.contains_key(*k))
            .cloned()
            .unwrap_or_else(|| tool.updater.default_channel.clone());
        let prev = st.get_ledger_entry(&tool.id, &ch).cloned();
        (ch, prev)
    };

    let ch_spec = tool
        .updater
        .channels
        .get(&selected_ch)
        .cloned()
        .ok_or_else(|| format!("Kênh '{}' không tồn tại.", selected_ch))?;

    let outcome: Result<InstallResultDto, String> = async {
        // Luôn lấy lại latest.json mới nhất ngay trước khi tải bộ cài
        let remote = fetch_remote_release(
            &state.http_client,
            &selected_ch,
            &ch_spec.endpoint,
            &tool.git.tag_prefix,
        )
        .await?;

        {
            let mut cache = state.cached_remotes.write().await;
            cache.insert((tool.id.clone(), selected_ch.clone()), Ok(remote.clone()));
        }

        // Kiểm tra chống hạ cấp phiên bản trên cùng kênh phát hành trước khi tải bộ cài lớn
        {
            let tool_for_chk = tool.clone();
            let ch_for_chk = selected_ch.clone();
            let prev_for_chk = prev_ledger.clone();
            let rem_norm = remote.normalized_version.clone();
            tokio::task::spawn_blocking(move || -> Result<(), String> {
                let procs = capture_running_processes();
                let regs = scan_uninstall_registry();
                let local = discover_tool_local(
                    &tool_for_chk,
                    &ch_for_chk,
                    &procs,
                    &regs,
                    prev_for_chk.as_ref(),
                    None,
                );
                if local.is_installed {
                    verify_not_downgrade(
                        &tool_for_chk.name,
                        &ch_for_chk,
                        &tool_for_chk.git.tag_prefix,
                        local.installed_version.as_deref(),
                        &rem_norm,
                    )?;
                }
                Ok(())
            })
            .await
            .map_err(|e| format!("Lỗi luồng kiểm tra chống hạ cấp: {e}"))??;
        }

        let (result_dto, ledger_entry) = execute_protected_install(
            &app,
            &state.http_client,
            &tool,
            &selected_ch,
            &ch_spec.pubkey,
            &remote,
            Path::new(&manifest.globals.vault_root),
            manifest.globals.max_backup_generations,
            prev_ledger.as_ref(),
        )
        .await?;

        {
            let mut st = state.state_file.write().await;
            let mut draft = st.clone();
            draft.upsert_ledger_entry(&tool.id, &selected_ch, ledger_entry);
            let sf_path = state.state_file_path.clone();
            let draft_for_save = draft.clone();
            tokio::task::spawn_blocking(move || save_state_file(&sf_path, &draft_for_save))
                .await
                .map_err(|e| format!("Lỗi luồng lưu state.json: {e}"))??;
            *st = draft;
        }

        Ok(result_dto)
    }
    .await;

    if let Err(ref err) = outcome {
        let _ = app.emit(
            "launcher://install-progress",
            InstallProgressEvent {
                tool_id: tool.id,
                tool_name: tool.name,
                phase: "failed".to_string(),
                percent: Some(100),
                downloaded_bytes: 0,
                total_bytes: None,
                message: err.clone(),
            },
        );
    }

    outcome
}

#[tauri::command]
async fn rollback_tool(
    app: AppHandle,
    state: tauri::State<'_, Arc<AppSharedState>>,
    tool_id: String,
) -> Result<InstallResultDto, String> {
    let _install_guard = state.install_mutex.lock().await;
    let _active_scope = ActiveInstallScope::enter(&state, tool_id.clone());

    let manifest_path = state.manifest_path.clone();
    let manifest = tokio::task::spawn_blocking(move || load_manifest_from_disk(&manifest_path))
        .await
        .map_err(|e| format!("Lỗi luồng đọc manifest: {e}"))??;
    let tool = manifest
        .tools
        .iter()
        .find(|t| t.id == tool_id)
        .cloned()
        .ok_or_else(|| format!("Không tìm thấy công cụ '{}' trong manifest.", tool_id))?;

    let selected_ch = {
        let st = state.state_file.read().await;
        st.settings
            .selected_channels
            .get(&tool.id)
            .filter(|k| tool.updater.channels.contains_key(*k))
            .cloned()
            .unwrap_or_else(|| tool.updater.default_channel.clone())
    };

    let _ = app.emit(
        "launcher://install-progress",
        InstallProgressEvent {
            tool_id: tool.id.clone(),
            tool_name: tool.name.clone(),
            phase: "rolling_back".to_string(),
            percent: Some(35),
            downloaded_bytes: 0,
            total_bytes: None,
            message: format!(
                "Đang khôi phục phiên bản ổn định trước đó của {} từ Guardian Vault...",
                tool.name
            ),
        },
    );

    let tool_for_rb = tool.clone();
    let vroot_for_rb = PathBuf::from(&manifest.globals.vault_root);
    let ch_for_rb = selected_ch.clone();
    let rb_res = tokio::task::spawn_blocking(move || {
        execute_rollback(&tool_for_rb, &vroot_for_rb, &ch_for_rb)
    })
    .await
    .map_err(|e| format!("Lỗi luồng khôi phục Guardian Vault: {e}"))
    .and_then(|r| r);

    let (restored_ver, restored_exe_path, vault_report, maybe_ledger) = match rb_res {
        Ok(v) => v,
        Err(err) => {
            let _ = app.emit(
                "launcher://install-progress",
                InstallProgressEvent {
                    tool_id: tool.id,
                    tool_name: tool.name,
                    phase: "failed".to_string(),
                    percent: Some(100),
                    downloaded_bytes: 0,
                    total_bytes: None,
                    message: err.clone(),
                },
            );
            return Err(err);
        }
    };

    if let Some(entry) = maybe_ledger {
        let mut st = state.state_file.write().await;
        let mut draft = st.clone();
        draft.upsert_ledger_entry(&tool.id, &selected_ch, entry);
        let sf_path = state.state_file_path.clone();
        let draft_for_save = draft.clone();
        tokio::task::spawn_blocking(move || save_state_file(&sf_path, &draft_for_save))
            .await
            .map_err(|e| format!("Lỗi luồng lưu state.json: {e}"))??;
        *st = draft;
    }

    let _ = app.emit(
        "launcher://install-progress",
        InstallProgressEvent {
            tool_id: tool.id.clone(),
            tool_name: tool.name.clone(),
            phase: "completed".to_string(),
            percent: Some(100),
            downloaded_bytes: 0,
            total_bytes: None,
            message: format!(
                "Đã khôi phục {} về v{} nguyên vẹn 100% từ Guardian Vault!",
                tool.name, restored_ver
            ),
        },
    );

    Ok(InstallResultDto {
        tool_id: tool.id,
        installed_version: restored_ver,
        active_exe_path: restored_exe_path,
        vault_report,
    })
}

#[tauri::command]
async fn set_tool_channel(
    state: tauri::State<'_, Arc<AppSharedState>>,
    tool_id: String,
    channel: String,
) -> Result<(), String> {
    let manifest_path = state.manifest_path.clone();
    let manifest = tokio::task::spawn_blocking(move || load_manifest_from_disk(&manifest_path))
        .await
        .map_err(|e| format!("Lỗi luồng đọc manifest: {e}"))??;
    let tool = manifest
        .tools
        .iter()
        .find(|t| t.id == tool_id)
        .ok_or_else(|| format!("Không tìm thấy công cụ '{}'.", tool_id))?;
    if !tool.updater.channels.contains_key(&channel) {
        return Err(format!("Kênh '{}' không hợp lệ cho {}.", channel, tool.name));
    }

    let mut st = state.state_file.write().await;
    let mut draft = st.clone();
    draft.settings.selected_channels.insert(tool_id, channel);
    let sf_path = state.state_file_path.clone();
    let draft_for_save = draft.clone();
    tokio::task::spawn_blocking(move || save_state_file(&sf_path, &draft_for_save))
        .await
        .map_err(|e| format!("Lỗi luồng lưu state.json: {e}"))??;
    *st = draft;
    Ok(())
}

#[tauri::command]
async fn update_launcher_settings(
    state: tauri::State<'_, Arc<AppSharedState>>,
    close_to_tray: bool,
    global_hotkey_enabled: bool,
) -> Result<LauncherSettings, String> {
    let mut st = state.state_file.write().await;
    let mut draft = st.clone();
    draft.settings.close_to_tray = close_to_tray;
    draft.settings.global_hotkey_enabled = global_hotkey_enabled;
    let sf_path = state.state_file_path.clone();
    let draft_for_save = draft.clone();
    tokio::task::spawn_blocking(move || save_state_file(&sf_path, &draft_for_save))
        .await
        .map_err(|e| format!("Lỗi luồng lưu state.json: {e}"))??;
    *st = draft;
    state
        .close_to_tray_active
        .store(close_to_tray, Ordering::Relaxed);
    state
        .hotkey_active
        .store(global_hotkey_enabled, Ordering::Relaxed);
    Ok(st.settings.clone())
}

fn is_allowed_ecosystem_open_path(
    target: &Path,
    manifest_path: &Path,
    manifest: &EcosystemManifest,
    ledger_paths: &[String],
) -> bool {
    let override_path = default_override_manifest_path();
    let exact_files = [manifest_path, override_path.as_path()];
    for ef in exact_files {
        if target.to_string_lossy().eq_ignore_ascii_case(&ef.to_string_lossy()) {
            return true;
        }
        if let Some(parent) = ef.parent() {
            if path_is_within_dir(target, parent) {
                return true;
            }
        }
    }

    let mut allowed_dirs: Vec<PathBuf> = vec![
        PathBuf::from(&manifest.globals.ecosystem_root),
        PathBuf::from(&manifest.globals.vault_root),
    ];

    for lp in ledger_paths {
        if let Some(parent) = Path::new(lp).parent() {
            allowed_dirs.push(parent.to_path_buf());
        }
    }

    for tool in &manifest.tools {
        allowed_dirs.push(PathBuf::from(&tool.git.repo_path));
        for er in &tool.git.extra_repos {
            allowed_dirs.push(PathBuf::from(&er.repo_path));
        }
        for cand in &tool.install.exe_candidates {
            if let Some(parent) = Path::new(cand).parent() {
                allowed_dirs.push(parent.to_path_buf());
            }
        }
        for ch in tool.updater.channels.values() {
            for cand in &ch.exe_candidates {
                if let Some(parent) = Path::new(cand).parent() {
                    allowed_dirs.push(parent.to_path_buf());
                }
            }
        }
        for imm in &tool.protection.immutable_files {
            if let Some(parent) = Path::new(imm).parent() {
                allowed_dirs.push(parent.to_path_buf());
            }
        }
        for bf in &tool.protection.backup_files {
            if let Some(parent) = Path::new(bf).parent() {
                allowed_dirs.push(parent.to_path_buf());
            }
        }
        for ext in &tool.protection.verify_external_paths {
            let ep = Path::new(ext);
            allowed_dirs.push(ep.to_path_buf());
            if let Some(parent) = ep.parent() {
                allowed_dirs.push(parent.to_path_buf());
            }
        }
    }

    allowed_dirs.iter().any(|dir| path_is_within_dir(target, dir))
}

#[tauri::command]
async fn open_filesystem_path(
    state: tauri::State<'_, Arc<AppSharedState>>,
    path: String,
) -> Result<(), String> {
    let manifest_path = state.manifest_path.clone();
    let ledger_paths: Vec<String> = state
        .state_file
        .read()
        .await
        .installed_ledger
        .values()
        .map(|e| e.exe_path.clone())
        .collect();

    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let manifest = load_manifest_from_disk(&manifest_path)?;
        let p = PathBuf::from(path.trim());
        if p.as_os_str().is_empty() {
            return Err("Đường dẫn trống.".to_string());
        }

        if !is_allowed_ecosystem_open_path(&p, &manifest_path, &manifest, &ledger_paths) {
            return Err(format!(
                "Từ chối mở đường dẫn '{}' vì nằm ngoài phạm vi cho phép của Hệ sinh thái Selorson.",
                p.display()
            ));
        }

        // Nếu bấm "Mở Kho Vault" trên máy mới chưa có thư mục vault -> tự tạo sẵn thay vì báo lỗi
        let vault_root_path = Path::new(&manifest.globals.vault_root);
        if path_is_within_dir(&p, vault_root_path)
            && p.to_string_lossy()
                .trim_end_matches(['\\', '/'])
                .eq_ignore_ascii_case(
                    vault_root_path
                        .to_string_lossy()
                        .trim_end_matches(['\\', '/']),
                )
            && !p.exists()
        {
            std::fs::create_dir_all(&p)
                .map_err(|e| format!("Không tạo được thư mục Guardian Vault '{}': {e}", p.display()))?;
        }

        if !p.exists() {
            return Err(format!("Đường dẫn '{}' hiện chưa tồn tại trên đĩa.", p.display()));
        }

        if p.is_file() {
            // Dùng Win32 SHOpenFolderAndSelectItems chuẩn qua tauri-plugin-opener:
            // xử lý hoàn hảo khoảng trắng & dấu phẩy ("Selorson Admin", "F:\FL studio\toneforge") và KHÔNG BAO GIỜ chạy nhầm .exe!
            tauri_plugin_opener::reveal_item_in_dir(&p)
                .map_err(|e| format!("Không mở được vị trí tệp trong File Explorer: {e}"))?;
        } else if p.is_dir() {
            tauri_plugin_opener::open_path(p.to_string_lossy().as_ref(), None::<&str>)
                .map_err(|e| format!("Không mở được thư mục trong File Explorer: {e}"))?;
        }

        Ok(())
    })
    .await
    .map_err(|e| format!("Lỗi luồng mở File Explorer: {e}"))?
}

#[tauri::command]
async fn validate_manifest_now(
    state: tauri::State<'_, Arc<AppSharedState>>,
) -> Result<ManifestValidationDto, String> {
    let manifest_path = state.manifest_path.clone();
    let path_str = manifest_path.to_string_lossy().to_string();
    let res = tokio::task::spawn_blocking(move || load_manifest_from_disk(&manifest_path))
        .await
        .map_err(|e| format!("Lỗi luồng kiểm tra manifest: {e}"))?;

    match res {
        Ok(m) => Ok(ManifestValidationDto {
            valid: true,
            manifest_path: path_str,
            tool_count: m.tools.len(),
            message: format!(
                "Manifest hợp lệ 100% ({} công cụ đã khai báo, tất cả Schema, giao thức HTTPS và khóa Ed25519 đều chuẩn xác).",
                m.tools.len()
            ),
        }),
        Err(err) => Ok(ManifestValidationDto {
            valid: false,
            manifest_path: path_str,
            tool_count: 0,
            message: err,
        }),
    }
}

#[tauri::command]
async fn prepare_self_update_exit(
    state: tauri::State<'_, Arc<AppSharedState>>,
    quit: Option<bool>,
) -> Result<(), String> {
    state
        .explicit_quit
        .store(quit.unwrap_or(true), Ordering::Relaxed);
    Ok(())
}

fn read_manifest_pair_stamp(
    primary: &Path,
    override_p: &Path,
) -> (
    Option<(std::time::SystemTime, u64)>,
    Option<(std::time::SystemTime, u64)>,
) {
    let s1 = std::fs::metadata(primary)
        .ok()
        .and_then(|m| Some((m.modified().ok()?, m.len())));
    let s2 = std::fs::metadata(override_p)
        .ok()
        .and_then(|m| Some((m.modified().ok()?, m.len())));
    (s1, s2)
}

fn spawn_manifest_hot_reload_watcher(app: AppHandle, shared: Arc<AppSharedState>) {
    tauri::async_runtime::spawn(async move {
        let override_path = default_override_manifest_path();
        let mut last_stamp = read_manifest_pair_stamp(&shared.manifest_path, &override_path);

        loop {
            tokio::time::sleep(Duration::from_millis(700)).await;
            let current = read_manifest_pair_stamp(&shared.manifest_path, &override_path);
            if current.0.is_some() && current != last_stamp {
                last_stamp = current;
                // Xóa sạch bộ đệm thông tin phát hành từ xa để nạp lại endpoint mới nếu có thay đổi
                shared.cached_remotes.write().await.clear();
                if app.get_webview_window("main").is_some() {
                    let _ = app.emit(
                        "launcher://manifest-reloaded",
                        BTreeMap::<String, String>::new(),
                    );
                }
            }
        }
    });
}

#[cfg(windows)]
fn spawn_win32_hotkey_and_singleton_listener(
    app: AppHandle,
    shared: Arc<AppSharedState>,
    wakeup_event_handle: usize,
) {
    // Luồng 1: Nhận tín hiệu gọi cửa sổ khi người dùng bấm mở Selorson Launcher lần thứ 2
    if wakeup_event_handle != 0 {
        let app_for_wake = app.clone();
        std::thread::spawn(move || unsafe {
            use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
            use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};
            let h = wakeup_event_handle as *mut core::ffi::c_void;
            loop {
                if WaitForSingleObject(h, INFINITE) == WAIT_OBJECT_0 {
                    show_or_recreate_main_window(&app_for_wake);
                } else {
                    // Thoát ngay nếu WAIT_FAILED hoặc handle đóng để không bao giờ quay 100% CPU
                    break;
                }
            }
        });
    }

    // Luồng 2: Phím tắt toàn cục Alt + Shift + S (chỉ đăng ký khi công tắc global_hotkey_enabled đang bật)
    std::thread::spawn(move || unsafe {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
            MOD_ALT, MOD_NOREPEAT, MOD_SHIFT, RegisterHotKey, UnregisterHotKey,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            MSG, PM_REMOVE, PeekMessageW, WM_HOTKEY,
        };

        let mut registered = false;
        let hotkey_id: i32 = 0x534C; // 'SL'

        loop {
            let want_active = shared.hotkey_active.load(Ordering::Relaxed);
            if want_active && !registered {
                if RegisterHotKey(
                    std::ptr::null_mut(),
                    hotkey_id,
                    MOD_ALT | MOD_SHIFT | MOD_NOREPEAT,
                    0x53, // Phím 'S'
                ) != 0
                {
                    registered = true;
                }
            } else if !want_active && registered {
                let _ = UnregisterHotKey(std::ptr::null_mut(), hotkey_id);
                registered = false;
            }

            if registered {
                let mut msg: MSG = std::mem::zeroed();
                while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                    if msg.message == WM_HOTKEY && msg.wParam as i32 == hotkey_id {
                        show_or_recreate_main_window(&app);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(80));
        }
    });
}

#[cfg(windows)]
pub fn acquire_single_instance_or_signal_existing() -> Option<usize> {
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError};
        use windows_sys::Win32::System::Threading::{CreateEventW, CreateMutexW, SetEvent};

        let mutex_name: Vec<u16> = "Local\\SelorsonLauncherSingleton_v1\0"
            .encode_utf16()
            .collect();
        let event_name: Vec<u16> = "Local\\SelorsonLauncherWakeupEvent_v1\0"
            .encode_utf16()
            .collect();

        // Khởi tạo Event TRƯỚC Mutex để triệt tiêu hoàn toàn khoảng hở đua giữa 2 tiến trình khởi chạy đồng thời
        let evt = CreateEventW(std::ptr::null(), 0, 0, event_name.as_ptr());
        let mutex = CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr());
        if mutex.is_null() {
            return Some(evt as usize);
        }
        if GetLastError() == ERROR_ALREADY_EXISTS {
            if !evt.is_null() {
                let _ = SetEvent(evt);
                let _ = CloseHandle(evt);
            }
            let _ = CloseHandle(mutex);
            return None;
        }

        // Giữ nguyên handle `mutex` sống suốt vòng đời tiến trình chính (Windows tự nhả khi tiến trình thoát)
        Some(evt as usize)
    }
}

#[cfg(windows)]
mod win_aumid {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    pub const LAUNCHER_AUMID: &str = "vn.selorson.launcher";
    const APP_ICON_ICO: &[u8] = include_bytes!("../icons/icon.ico");

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PropertyKey {
        fmtid: Guid,
        pid: u32,
    }

    #[repr(C)]
    struct PropVariant {
        vt: u16,
        w_reserved1: u16,
        w_reserved2: u16,
        w_reserved3: u16,
        data1: usize,
        data2: usize,
    }

    #[repr(C)]
    struct IPersistFileVtbl {
        query_interface:
            unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
        add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
        release: unsafe extern "system" fn(*mut c_void) -> u32,
        get_class_id: unsafe extern "system" fn(*mut c_void, *mut Guid) -> i32,
        is_dirty: unsafe extern "system" fn(*mut c_void) -> i32,
        load: unsafe extern "system" fn(*mut c_void, *const u16, u32) -> i32,
        save: unsafe extern "system" fn(*mut c_void, *const u16, i32) -> i32,
        save_completed: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
        get_cur_file: unsafe extern "system" fn(*mut c_void, *mut *mut u16) -> i32,
    }

    #[repr(C)]
    struct IPersistFile {
        lp_vtbl: *const IPersistFileVtbl,
    }

    #[repr(C)]
    struct IPropertyStoreVtbl {
        query_interface:
            unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
        add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
        release: unsafe extern "system" fn(*mut c_void) -> u32,
        get_count: unsafe extern "system" fn(*mut c_void, *mut u32) -> i32,
        get_at: unsafe extern "system" fn(*mut c_void, u32, *mut PropertyKey) -> i32,
        get_value:
            unsafe extern "system" fn(*mut c_void, *const PropertyKey, *mut PropVariant) -> i32,
        set_value:
            unsafe extern "system" fn(*mut c_void, *const PropertyKey, *const PropVariant) -> i32,
        commit: unsafe extern "system" fn(*mut c_void) -> i32,
    }

    #[repr(C)]
    struct IPropertyStore {
        lp_vtbl: *const IPropertyStoreVtbl,
    }

    const CLSID_SHELL_LINK: Guid = Guid {
        data1: 0x00021401,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };
    const IID_IPERSIST_FILE: Guid = Guid {
        data1: 0x0000010B,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };
    const IID_IPROPERTY_STORE: Guid = Guid {
        data1: 0x886D8EEB,
        data2: 0x8CF2,
        data3: 0x4446,
        data4: [0x8D, 0x02, 0xCD, 0xBA, 0x1D, 0xBD, 0xCF, 0x99],
    };
    const PKEY_APP_USER_MODEL_ID: PropertyKey = PropertyKey {
        fmtid: Guid {
            data1: 0x9F4C2855,
            data2: 0x9F79,
            data3: 0x4B39,
            data4: [0xA8, 0xD0, 0xE1, 0xD4, 0x2D, 0xE1, 0xD5, 0xF3],
        },
        pid: 5,
    };

    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoInitializeEx(pv_reserved: *const c_void, dw_co_init: u32) -> i32;
        fn CoUninitialize();
        fn CoCreateInstance(
            rclsid: *const Guid,
            p_unk_outer: *mut c_void,
            dw_cls_context: u32,
            riid: *const Guid,
            ppv: *mut *mut c_void,
        ) -> i32;
        fn PropVariantClear(pvar: *mut PropVariant) -> i32;
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHChangeNotify(
            w_event_id: i32,
            u_flags: u32,
            dw_item1: *const c_void,
            dw_item2: *const c_void,
        );
    }

    fn wide_null(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn set_process_aumid_and_heal_shell() {
        unsafe {
            use windows_sys::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
            let aumid: Vec<u16> = format!("{LAUNCHER_AUMID}\0").encode_utf16().collect();
            let _ = SetCurrentProcessExplicitAppUserModelID(aumid.as_ptr());
        }

        std::thread::spawn(|| {
            register_aumid_registry();
            if let Ok(appdata) = std::env::var("APPDATA") {
                let base = PathBuf::from(appdata);
                let candidates = [
                    base.join(r"Microsoft\Windows\Start Menu\Programs\Selorson Launcher.lnk"),
                    base.join(r"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Selorson Launcher.lnk"),
                ];
                for lnk in &candidates {
                    if lnk.is_file() {
                        let _ = ensure_shortcut_aumid(lnk, LAUNCHER_AUMID);
                    }
                }
            }
        });
    }

    fn register_aumid_registry() {
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let subkey = format!(r"Software\Classes\AppUserModelId\{LAUNCHER_AUMID}");
        if let Ok((key, _)) = hkcu.create_subkey(&subkey) {
            let _ = key.set_value("DisplayName", &"Selorson Launcher");
            if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
                let dir = PathBuf::from(local_appdata).join("Selorson Launcher");
                let ico_path = dir.join("icon.ico");
                if !ico_path.exists() {
                    let _ = std::fs::create_dir_all(&dir);
                    let _ = std::fs::write(&ico_path, APP_ICON_ICO);
                }
                if ico_path.exists() {
                    let _ = key.set_value("IconUri", &ico_path.to_string_lossy().to_string());
                }
            }
        }
    }

    pub fn ensure_shortcut_aumid(lnk_path: &Path, expected_aumid: &str) -> Result<bool, String> {
        unsafe {
            let hr_init = CoInitializeEx(std::ptr::null(), 0x2); // COINIT_APARTMENTTHREADED
            let should_uninit = hr_init >= 0;

            let result = (|| -> Result<bool, String> {
                let mut raw_pf: *mut c_void = std::ptr::null_mut();
                let hr = CoCreateInstance(
                    &CLSID_SHELL_LINK,
                    std::ptr::null_mut(),
                    1,
                    &IID_IPERSIST_FILE,
                    &mut raw_pf,
                );
                if hr < 0 || raw_pf.is_null() {
                    return Err(format!("CoCreateInstance(ShellLink) thất bại: 0x{hr:08x}"));
                }

                let pf = raw_pf as *mut IPersistFile;
                let wpath = wide_null(lnk_path.as_os_str());
                let hr_load = ((*(*pf).lp_vtbl).load)(raw_pf, wpath.as_ptr(), 2);
                if hr_load < 0 {
                    ((*(*pf).lp_vtbl).release)(raw_pf);
                    return Err(format!("IPersistFile::Load thất bại: 0x{hr_load:08x}"));
                }

                let mut raw_ps: *mut c_void = std::ptr::null_mut();
                let hr_qi =
                    ((*(*pf).lp_vtbl).query_interface)(raw_pf, &IID_IPROPERTY_STORE, &mut raw_ps);
                if hr_qi < 0 || raw_ps.is_null() {
                    ((*(*pf).lp_vtbl).release)(raw_pf);
                    return Err(format!(
                        "QueryInterface(IPropertyStore) thất bại: 0x{hr_qi:08x}"
                    ));
                }

                let ps = raw_ps as *mut IPropertyStore;
                let mut cur_pv: PropVariant = std::mem::zeroed();
                let mut already_matches = false;
                if ((*(*ps).lp_vtbl).get_value)(raw_ps, &PKEY_APP_USER_MODEL_ID, &mut cur_pv) >= 0 {
                    if cur_pv.vt == 31 && cur_pv.data1 != 0 {
                        let ptr = cur_pv.data1 as *const u16;
                        let mut len = 0usize;
                        while *ptr.add(len) != 0 && len < 260 {
                            len += 1;
                        }
                        let cur_str =
                            String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
                        if cur_str == expected_aumid {
                            already_matches = true;
                        }
                    }
                    let _ = PropVariantClear(&mut cur_pv);
                }

                if already_matches {
                    ((*(*ps).lp_vtbl).release)(raw_ps);
                    ((*(*pf).lp_vtbl).release)(raw_pf);
                    return Ok(false);
                }

                let waumid = wide_null(std::ffi::OsStr::new(expected_aumid));
                let set_pv = PropVariant {
                    vt: 31,
                    w_reserved1: 0,
                    w_reserved2: 0,
                    w_reserved3: 0,
                    data1: waumid.as_ptr() as usize,
                    data2: 0,
                };
                let hr_set =
                    ((*(*ps).lp_vtbl).set_value)(raw_ps, &PKEY_APP_USER_MODEL_ID, &set_pv);
                let hr_commit = ((*(*ps).lp_vtbl).commit)(raw_ps);
                let hr_save = if hr_set >= 0 && hr_commit >= 0 {
                    ((*(*pf).lp_vtbl).save)(raw_pf, wpath.as_ptr(), 1)
                } else {
                    -1
                };

                ((*(*ps).lp_vtbl).release)(raw_ps);
                ((*(*pf).lp_vtbl).release)(raw_pf);

                if hr_set < 0 || hr_commit < 0 || hr_save < 0 {
                    return Err("Không ghi được AppUserModelID vào tệp .lnk".to_string());
                }

                SHChangeNotify(
                    0x0000_2000,
                    0x0005,
                    wpath.as_ptr() as *const c_void,
                    std::ptr::null(),
                );
                Ok(true)
            })();

            if should_uninit {
                CoUninitialize();
            }
            result
        }
    }
}

pub fn run() {
    #[cfg(windows)]
    let wakeup_handle = match acquire_single_instance_or_signal_existing() {
        Some(h) => h,
        None => return,
    };

    #[cfg(windows)]
    win_aumid::set_process_aumid_and_heal_shell();

    let manifest_path = resolve_manifest_path();
    let startup_vault_root = load_manifest_from_disk(&manifest_path)
        .map(|m| PathBuf::from(m.globals.vault_root))
        .unwrap_or_else(|_| {
            let base = std::env::var("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|_| std::env::temp_dir());
            base.join("Selorson Launcher").join("vault")
        });
    if let Err(err) = recover_incomplete_transactions(&startup_vault_root) {
        eprintln!("[GuardianVault] Cảnh báo phục hồi giao dịch dở dang lúc khởi động: {err}");
    }

    let state_file_path = default_state_file_path();
    let initial_state = load_state_file(&state_file_path);
    let initial_close_to_tray = initial_state.settings.close_to_tray;
    let initial_hotkey = initial_state.settings.global_hotkey_enabled;

    let http_client = build_http_client().expect("Không khởi tạo được HTTP client");

    let shared = Arc::new(AppSharedState {
        manifest_path,
        state_file_path,
        state_file: RwLock::new(initial_state),
        cached_remotes: RwLock::new(HashMap::new()),
        icon_cache: std::sync::Mutex::new(HashMap::new()),
        install_mutex: Mutex::new(()),
        active_install_tool_id: std::sync::Mutex::new(None),
        http_client,
        explicit_quit: AtomicBool::new(false),
        close_to_tray_active: AtomicBool::new(initial_close_to_tray),
        hotkey_active: AtomicBool::new(initial_hotkey),
    });

    let shared_for_setup = Arc::clone(&shared);
    let shared_for_run = Arc::clone(&shared);

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(shared)
        .setup(move |app| {
            let handle = app.handle().clone();

            let open_item =
                MenuItem::with_id(app, "open_hub", "Mở Selorson Launcher", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(
                app,
                "quit_hub",
                "Thoát hoàn toàn (0 MB RAM)",
                true,
                None::<&str>,
            )?;
            let tray_menu = Menu::with_items(app, &[&open_item, &quit_item])?;

            let mut tray_builder = TrayIconBuilder::new()
                .menu(&tray_menu)
                .tooltip("Selorson Launcher — Trung Tâm Hệ Sinh Thái")
                .on_menu_event({
                    let shared_menu = Arc::clone(&shared_for_setup);
                    move |app_h, event| match event.id.as_ref() {
                        "open_hub" => show_or_recreate_main_window(app_h),
                        "quit_hub" => {
                            if shared_menu.install_mutex.try_lock().is_err() {
                                show_or_recreate_main_window(app_h);
                                let _ = app_h.emit(
                                    "launcher://close-blocked",
                                    "Đang chạy giao dịch bảo hộ Guardian Vault — không thể thoát ngang để bảo vệ dữ liệu & tệp bất biến!",
                                );
                                return;
                            }
                            shared_menu.explicit_quit.store(true, Ordering::Relaxed);
                            app_h.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_or_recreate_main_window(tray.app_handle());
                    }
                });

            if let Some(default_icon) = app.default_window_icon().cloned() {
                tray_builder = tray_builder.icon(default_icon);
            }
            let _ = tray_builder.build(app)?;

            spawn_manifest_hot_reload_watcher(handle.clone(), Arc::clone(&shared_for_setup));

            #[cfg(windows)]
            spawn_win32_hotkey_and_singleton_listener(
                handle,
                Arc::clone(&shared_for_setup),
                wakeup_handle,
            );

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_ecosystem_snapshot,
            launch_tool,
            install_or_update_tool,
            rollback_tool,
            set_tool_channel,
            update_launcher_settings,
            open_filesystem_path,
            validate_manifest_now,
            prepare_self_update_exit,
        ])
        .build(tauri::generate_context!())
        .expect("Lỗi khởi tạo ứng dụng Tauri Selorson Launcher");

    app.run(move |app_handle, event| match event {
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::CloseRequested { api, .. },
            ..
        } if label == "main" => {
            if shared_for_run.explicit_quit.load(Ordering::Relaxed) {
                return;
            }
            if shared_for_run.install_mutex.try_lock().is_err() {
                api.prevent_close();
                let _ = app_handle.emit(
                    "launcher://close-blocked",
                    "Giao dịch bảo hộ Guardian Vault đang thực thi — vui lòng chờ hoàn tất trước khi đóng cửa sổ!",
                );
                return;
            }
            let close_to_tray = shared_for_run.close_to_tray_active.load(Ordering::Relaxed);

            if close_to_tray {
                api.prevent_close();
                if let Some(win) = app_handle.get_webview_window("main") {
                    let _ = win.destroy();
                }
            } else {
                shared_for_run.explicit_quit.store(true, Ordering::Relaxed);
                app_handle.exit(0);
            }
        }
        RunEvent::ExitRequested { api, .. } => {
            if shared_for_run.install_mutex.try_lock().is_err() {
                api.prevent_exit();
                return;
            }
            if !shared_for_run.explicit_quit.load(Ordering::Relaxed)
                && shared_for_run.close_to_tray_active.load(Ordering::Relaxed)
            {
                api.prevent_exit();
            }
        }
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn builds_live_snapshot_for_all_7_tools() {
        let tmp = tempdir().unwrap();
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("ecosystem-manifest.json");

        let shared = Arc::new(AppSharedState {
            manifest_path,
            state_file_path: tmp.path().join("state.json"),
            state_file: RwLock::new(LauncherStateFile::default()),
            cached_remotes: RwLock::new(HashMap::new()),
            icon_cache: std::sync::Mutex::new(HashMap::new()),
            install_mutex: Mutex::new(()),
            active_install_tool_id: std::sync::Mutex::new(None),
            http_client: build_http_client().unwrap(),
            explicit_quit: AtomicBool::new(false),
            close_to_tray_active: AtomicBool::new(false),
            hotkey_active: AtomicBool::new(false),
        });

        let snap = build_snapshot(shared, true)
            .await
            .expect("Phải dựng thành công bức tranh toàn cảnh 7 công cụ thực tế");
        assert_eq!(snap.tools.len(), 7);
        for t in &snap.tools {
            println!(
                "[LIVE] #{} {} -> installed={:?} (src={:?}) | icon_data={} | remote={:?} | state={:?} | git={:?} (dirty={})",
                t.order,
                t.name,
                t.local.installed_version,
                t.local.version_source,
                t.icon_data_url.is_some(),
                t.remote.as_ref().map(|r| r.normalized_version.as_str()),
                t.release_state,
                t.git.drift_status,
                t.git.dirty_files_count
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn shortcut_aumid_healer_stamps_and_is_idempotent() {
        let tmp = tempdir().unwrap();
        let lnk = tmp.path().join("TestLauncher.lnk");
        let status = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath='C:\\Windows\\notepad.exe'; $s.Save()",
                    lnk.display()
                ),
            ])
            .status()
            .unwrap();
        assert!(status.success());

        let first = win_aumid::ensure_shortcut_aumid(&lnk, win_aumid::LAUNCHER_AUMID)
            .expect("Phải ghi được System.AppUserModel.ID vào .lnk");
        assert!(first, "Lần đầu phải cập nhật .lnk");

        let second = win_aumid::ensure_shortcut_aumid(&lnk, win_aumid::LAUNCHER_AUMID)
            .expect("Phải đọc lại được System.AppUserModel.ID từ .lnk");
        assert!(!second, "Lần hai phải nhận diện đã khớp và bỏ qua ghi đĩa");
    }

    #[test]
    fn enforces_anti_downgrade_and_filesystem_open_allowlist() {
        // 1. Chặn hạ cấp SemVer trên cùng kênh
        assert!(verify_not_downgrade("Co-Writer", "stable", "v", Some("1.9.1"), "1.8.0").is_err());
        assert!(verify_not_downgrade("Co-Writer", "stable", "v", Some("1.9.1"), "1.9.1").is_ok());
        assert!(verify_not_downgrade("Co-Writer", "stable", "v", Some("1.9.1-beta.1"), "1.9.1").is_ok());

        // 2. Allowlist mở File Explorer: cho phép đường dẫn hệ sinh thái (kể cả có dấu cách), chặn đường dẫn nhạy cảm bên ngoài
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("ecosystem-manifest.json");
        let manifest = manifest::load_manifest_from_disk_with_override(&manifest_path, None).unwrap();

        assert!(is_allowed_ecosystem_open_path(
            Path::new(&manifest.globals.vault_root),
            &manifest_path,
            &manifest,
            &[]
        ));
        assert!(is_allowed_ecosystem_open_path(
            Path::new(r"F:\FL studio\toneforge\ToneForge_Studio.exe"),
            &manifest_path,
            &manifest,
            &[]
        ));
        assert!(!is_allowed_ecosystem_open_path(
            Path::new(r"E:\Selorson-Launcher-Keys\launcher.key"),
            &manifest_path,
            &manifest,
            &[]
        ));
        assert!(!is_allowed_ecosystem_open_path(
            Path::new(r"C:\Windows\System32\cmd.exe"),
            &manifest_path,
            &manifest,
            &[]
        ));
    }
}
