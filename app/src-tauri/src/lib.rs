pub mod discovery;
pub mod git_drift;
pub mod guardian_vault;
pub mod installer;
pub mod ledger;
pub mod manifest;
pub mod release_probe;

use discovery::{
    DiscoveredToolLocal, OpenPortStatus, capture_running_processes, discover_tool_local,
    probe_tcp_port, scan_uninstall_registry,
};
use git_drift::{GitRepoReport, inspect_git_drift};
use installer::{InstallResultDto, execute_protected_install, launch_tool_detached};
use ledger::{
    LauncherSettings, LauncherStateFile, default_state_file_path, load_state_file, save_state_file,
};
use manifest::{
    EcosystemManifest, ReleaseChannelSpec, load_manifest_from_disk, resolve_manifest_path,
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
use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tokio::sync::{Mutex, RwLock};

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
    pub selected_channel: String,
    pub available_channels: Vec<ChannelOptionDto>,
    pub repo_path: String,
    pub watch_paths: Vec<String>,
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
    pub install_mutex: Mutex<()>,
    pub http_client: reqwest::Client,
    pub explicit_quit: AtomicBool,
    pub hotkey_active: AtomicBool,
}

pub fn show_or_recreate_main_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.unminimize();
        let _ = win.show();
        let _ = win.set_focus();
        return;
    }

    // Nếu trước đó cửa sổ đã hủy nhân WebView2 để giải phóng ~100 MB RAM khi thu xuống khay hệ thống -> dựng lại tức thì!
    if let Ok(win) = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("/".into()))
        .title("Selorson Launcher — Trung Tâm Điều Phối Hệ Sinh Thái")
        .inner_size(1440.0, 920.0)
        .min_inner_size(1040.0, 680.0)
        .center()
        .resizable(true)
        .build()
    {
        let _ = win.set_focus();
    }
}

async fn build_snapshot(
    shared: &AppSharedState,
    force_remote: bool,
) -> Result<EcosystemSnapshotDto, String> {
    let manifest: EcosystemManifest = load_manifest_from_disk(&shared.manifest_path)?;
    let state_guard = shared.state_file.read().await.clone();

    let running_procs = Arc::new(capture_running_processes());
    let registry_apps = Arc::new(scan_uninstall_registry());

    // 1. Dò cổng dùng chung của toàn hệ sinh thái (ComfyUI :8189, :8188)
    let mut shared_ports = Vec::new();
    for sp in &manifest.globals.shared_gpu_busy_ports {
        shared_ports.push(OpenPortStatus {
            port: sp.port,
            label: sp.label.clone(),
            is_open: probe_tcp_port(sp.port),
            blocks_update: false,
        });
    }

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
    let mut tool_tasks = tokio::task::JoinSet::new();
    for tool in manifest.tools {
        let procs = Arc::clone(&running_procs);
        let regs = Arc::clone(&registry_apps);
        let ledger_entry = state_guard.installed_ledger.get(&tool.id).cloned();
        let selected_ch = state_guard
            .settings
            .selected_channels
            .get(&tool.id)
            .filter(|k| tool.updater.channels.contains_key(*k))
            .cloned()
            .unwrap_or_else(|| tool.updater.default_channel.clone());
        let rem_res = remote_cache
            .get(&(tool.id.clone(), selected_ch.clone()))
            .cloned()
            .unwrap_or_else(|| Err("Chưa kiểm tra kênh phát hành.".to_string()));

        tool_tasks.spawn(async move {
            let local = discover_tool_local(&tool, &procs, &regs, ledger_entry.as_ref());
            let rem_ver = rem_res.as_ref().ok().map(|r| r.normalized_version.as_str());
            let git = inspect_git_drift(
                &tool.git,
                local.installed_version.as_deref(),
                local.exe_mtime_secs,
                rem_ver,
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

            let icon_path = tool.icon.filter(|p| Path::new(p).exists());

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
                selected_channel: selected_ch,
                available_channels,
                repo_path: tool.git.repo_path,
                watch_paths: tool.git.watch_paths,
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

    Ok(EcosystemSnapshotDto {
        ecosystem_name: manifest.ecosystem_name,
        manifest_path: shared.manifest_path.to_string_lossy().to_string(),
        ecosystem_root: manifest.globals.ecosystem_root,
        vault_root: manifest.globals.vault_root,
        shared_ports,
        settings: state_guard.settings,
        tools,
        checked_at_iso: chrono::Local::now().format("%H:%M:%S · %d/%m/%Y").to_string(),
    })
}

#[tauri::command]
async fn get_ecosystem_snapshot(
    state: tauri::State<'_, Arc<AppSharedState>>,
    force_remote: bool,
) -> Result<EcosystemSnapshotDto, String> {
    build_snapshot(&state, force_remote).await
}

#[tauri::command]
async fn launch_tool(
    state: tauri::State<'_, Arc<AppSharedState>>,
    tool_id: String,
) -> Result<String, String> {
    let manifest = load_manifest_from_disk(&state.manifest_path)?;
    let tool = manifest
        .tools
        .iter()
        .find(|t| t.id == tool_id)
        .ok_or_else(|| format!("Không tìm thấy công cụ '{}' trong manifest.", tool_id))?;

    let st = state.state_file.read().await;
    let procs = capture_running_processes();
    let regs = scan_uninstall_registry();
    let local = discover_tool_local(tool, &procs, &regs, st.installed_ledger.get(&tool_id));

    let exe_str = local.active_exe_path.ok_or_else(|| {
        format!(
            "{} chưa được cài đặt trên máy. Hãy bấm 'Cài đặt' để tải bản chính thức!",
            tool.name
        )
    })?;

    launch_tool_detached(tool, Path::new(&exe_str))?;
    Ok(exe_str)
}

#[tauri::command]
async fn install_or_update_tool(
    app: AppHandle,
    state: tauri::State<'_, Arc<AppSharedState>>,
    tool_id: String,
) -> Result<InstallResultDto, String> {
    // Khóa tuần tự 1 luồng cài đặt tại một thời điểm
    let _install_guard = state.install_mutex.lock().await;

    let manifest = load_manifest_from_disk(&state.manifest_path)?;
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

    let ch_spec = tool
        .updater
        .channels
        .get(&selected_ch)
        .cloned()
        .ok_or_else(|| format!("Kênh '{}' không tồn tại.", selected_ch))?;

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

    let (result_dto, maybe_ledger) = execute_protected_install(
        &app,
        &state.http_client,
        &tool,
        &selected_ch,
        &ch_spec.pubkey,
        &remote,
        Path::new(&manifest.globals.vault_root),
        manifest.globals.max_backup_generations,
    )
    .await?;

    if let Some(entry) = maybe_ledger {
        let mut st = state.state_file.write().await;
        st.installed_ledger.insert(tool.id.clone(), entry);
        let _ = save_state_file(&state.state_file_path, &st);
    }

    Ok(result_dto)
}

#[tauri::command]
async fn set_tool_channel(
    state: tauri::State<'_, Arc<AppSharedState>>,
    tool_id: String,
    channel: String,
) -> Result<(), String> {
    let manifest = load_manifest_from_disk(&state.manifest_path)?;
    let tool = manifest
        .tools
        .iter()
        .find(|t| t.id == tool_id)
        .ok_or_else(|| format!("Không tìm thấy công cụ '{}'.", tool_id))?;
    if !tool.updater.channels.contains_key(&channel) {
        return Err(format!("Kênh '{}' không hợp lệ cho {}.", channel, tool.name));
    }

    let mut st = state.state_file.write().await;
    st.settings
        .selected_channels
        .insert(tool_id, channel);
    save_state_file(&state.state_file_path, &st)
}

#[tauri::command]
async fn update_launcher_settings(
    state: tauri::State<'_, Arc<AppSharedState>>,
    close_to_tray: bool,
    global_hotkey_enabled: bool,
) -> Result<LauncherSettings, String> {
    let mut st = state.state_file.write().await;
    st.settings.close_to_tray = close_to_tray;
    st.settings.global_hotkey_enabled = global_hotkey_enabled;
    state
        .hotkey_active
        .store(global_hotkey_enabled, Ordering::Relaxed);
    save_state_file(&state.state_file_path, &st)?;
    Ok(st.settings.clone())
}

#[tauri::command]
async fn open_filesystem_path(path: String) -> Result<(), String> {
    let p = PathBuf::from(&path);
    if !p.exists() {
        return Err(format!("Đường dẫn '{}' hiện chưa tồn tại trên đĩa.", path));
    }
    #[cfg(windows)]
    {
        let mut cmd = std::process::Command::new("explorer.exe");
        if p.is_file() {
            cmd.arg(format!("/select,{}", p.display()));
        } else {
            cmd.arg(&p);
        }
        cmd.spawn()
            .map_err(|e| format!("Không mở được File Explorer: {e}"))?;
    }
    Ok(())
}

#[tauri::command]
async fn validate_manifest_now(
    state: tauri::State<'_, Arc<AppSharedState>>,
) -> Result<ManifestValidationDto, String> {
    let path_str = state.manifest_path.to_string_lossy().to_string();
    match load_manifest_from_disk(&state.manifest_path) {
        Ok(m) => Ok(ManifestValidationDto {
            valid: true,
            manifest_path: path_str,
            tool_count: m.tools.len(),
            message: format!(
                "Manifest hợp lệ 100% ({} công cụ đã khai báo, tất cả khóa Ed25519 đều chuẩn xác).",
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
) -> Result<(), String> {
    state.explicit_quit.store(true, Ordering::Relaxed);
    Ok(())
}

fn spawn_manifest_hot_reload_watcher(app: AppHandle, shared: Arc<AppSharedState>) {
    tauri::async_runtime::spawn(async move {
        let mut last_stamp: Option<(std::time::SystemTime, u64)> = std::fs::metadata(&shared.manifest_path)
            .ok()
            .and_then(|m| Some((m.modified().ok()?, m.len())));

        loop {
            tokio::time::sleep(Duration::from_millis(700)).await;
            // Khi cửa sổ đã đóng xuống khay hệ thống -> nghỉ nhẹ không phát sự kiện thừa
            if app.get_webview_window("main").is_none() {
                continue;
            }
            let current = std::fs::metadata(&shared.manifest_path)
                .ok()
                .and_then(|m| Some((m.modified().ok()?, m.len())));
            if current.is_some() && current != last_stamp {
                last_stamp = current;
                // Xóa đệm kênh mới nếu có thêm công cụ thứ 8
                let _ = app.emit("launcher://manifest-reloaded", BTreeMap::<String, String>::new());
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
        use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
        use windows_sys::Win32::System::Threading::{
            CreateEventW, CreateMutexW, EVENT_MODIFY_STATE, OpenEventW, SetEvent,
        };

        let mutex_name: Vec<u16> = "Local\\SelorsonLauncherSingleton_v1\0"
            .encode_utf16()
            .collect();
        let event_name: Vec<u16> = "Local\\SelorsonLauncherWakeupEvent_v1\0"
            .encode_utf16()
            .collect();

        let _mutex = CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr());
        if GetLastError() == ERROR_ALREADY_EXISTS {
            let evt = OpenEventW(EVENT_MODIFY_STATE, 0, event_name.as_ptr());
            if !evt.is_null() {
                let _ = SetEvent(evt);
            }
            return None;
        }

        let evt = CreateEventW(std::ptr::null(), 0, 0, event_name.as_ptr());
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
        query_interface: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
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
        query_interface: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
        add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
        release: unsafe extern "system" fn(*mut c_void) -> u32,
        get_count: unsafe extern "system" fn(*mut c_void, *mut u32) -> i32,
        get_at: unsafe extern "system" fn(*mut c_void, u32, *mut PropertyKey) -> i32,
        get_value: unsafe extern "system" fn(*mut c_void, *const PropertyKey, *mut PropVariant) -> i32,
        set_value: unsafe extern "system" fn(*mut c_void, *const PropertyKey, *const PropVariant) -> i32,
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

        // Chạy ngầm đăng ký AppUserModelId & tự sửa Shortcut nếu thiếu để không cản trở 1ms khởi động nào
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

    /// Đảm bảo tệp `.lnk` mang đúng `System.AppUserModel.ID` để Windows 11 gộp chung 1 icon trên Taskbar.
    /// Trả về `Ok(true)` nếu vừa cập nhật mới, `Ok(false)` nếu đã khớp sẵn (0 ghi đĩa thừa).
    pub fn ensure_shortcut_aumid(lnk_path: &Path, expected_aumid: &str) -> Result<bool, String> {
        unsafe {
            let hr_init = CoInitializeEx(std::ptr::null(), 0x2); // COINIT_APARTMENTTHREADED
            let should_uninit = hr_init >= 0;

            let result = (|| -> Result<bool, String> {
                let mut raw_pf: *mut c_void = std::ptr::null_mut();
                let hr = CoCreateInstance(
                    &CLSID_SHELL_LINK,
                    std::ptr::null_mut(),
                    1, // CLSCTX_INPROC_SERVER
                    &IID_IPERSIST_FILE,
                    &mut raw_pf,
                );
                if hr < 0 || raw_pf.is_null() {
                    return Err(format!("CoCreateInstance(ShellLink) thất bại: 0x{hr:08x}"));
                }

                let pf = raw_pf as *mut IPersistFile;
                let wpath = wide_null(lnk_path.as_os_str());
                // STGM_READWRITE = 2
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
                    return Err(format!("QueryInterface(IPropertyStore) thất bại: 0x{hr_qi:08x}"));
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
                    vt: 31, // VT_LPWSTR
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

                // Báo cho Windows Explorer cập nhật ngay bộ đệm Taskband
                SHChangeNotify(
                    0x0000_2000, // SHCNE_UPDATEITEM
                    0x0005,      // SHCNF_PATHW
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
        None => return, // Đã đánh thức cửa sổ đang chạy -> thoát ngay trong 1ms
    };

    #[cfg(windows)]
    win_aumid::set_process_aumid_and_heal_shell();

    let manifest_path = resolve_manifest_path();
    let state_file_path = default_state_file_path();
    let initial_state = load_state_file(&state_file_path);
    let initial_hotkey = initial_state.settings.global_hotkey_enabled;

    let http_client = build_http_client().expect("Không khởi tạo được HTTP client");

    let shared = Arc::new(AppSharedState {
        manifest_path,
        state_file_path,
        state_file: RwLock::new(initial_state),
        cached_remotes: RwLock::new(HashMap::new()),
        install_mutex: Mutex::new(()),
        http_client,
        explicit_quit: AtomicBool::new(false),
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

            // Khởi tạo biểu tượng Khay hệ thống (System Tray) gọn nhẹ
            let open_item = MenuItem::with_id(app, "open_hub", "Mở Selorson Launcher", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit_hub", "Thoát hoàn toàn (0 MB RAM)", true, None::<&str>)?;
            let tray_menu = Menu::with_items(app, &[&open_item, &quit_item])?;

            let mut tray_builder = TrayIconBuilder::new()
                .menu(&tray_menu)
                .tooltip("Selorson Launcher — Trung Tâm Hệ Sinh Thái")
                .on_menu_event({
                    let shared_menu = Arc::clone(&shared_for_setup);
                    move |app_h, event| match event.id.as_ref() {
                        "open_hub" => show_or_recreate_main_window(app_h),
                        "quit_hub" => {
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
            let close_to_tray = tauri::async_runtime::block_on(async {
                shared_for_run.state_file.read().await.settings.close_to_tray
            });

            if close_to_tray {
                // Hủy hẳn cửa sổ WebView2 (~100 MB RAM) và chỉ giữ hạt nhân Rust ~4 MB ở khay hệ thống!
                api.prevent_close();
                if let Some(win) = app_handle.get_webview_window("main") {
                    let _ = win.destroy();
                }
            } else {
                // Mặc định: Đóng cửa sổ = Thoát sạch 100% tiến trình (0 MB RAM nền)
                shared_for_run.explicit_quit.store(true, Ordering::Relaxed);
                app_handle.exit(0);
            }
        }
        RunEvent::ExitRequested { api, .. } => {
            if !shared_for_run.explicit_quit.load(Ordering::Relaxed) {
                let close_to_tray = tauri::async_runtime::block_on(async {
                    shared_for_run.state_file.read().await.settings.close_to_tray
                });
                if close_to_tray {
                    api.prevent_exit();
                }
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

        let shared = AppSharedState {
            manifest_path,
            state_file_path: tmp.path().join("state.json"),
            state_file: RwLock::new(LauncherStateFile::default()),
            cached_remotes: RwLock::new(HashMap::new()),
            install_mutex: Mutex::new(()),
            http_client: build_http_client().unwrap(),
            explicit_quit: AtomicBool::new(false),
            hotkey_active: AtomicBool::new(false),
        };

        let snap = build_snapshot(&shared, true)
            .await
            .expect("Phải dựng thành công bức tranh toàn cảnh 7 công cụ thực tế");
        assert_eq!(snap.tools.len(), 7);
        for t in &snap.tools {
            println!(
                "[LIVE] #{} {} -> installed={:?} (src={:?}) | remote={:?} | state={:?} | git={:?} (dirty={})",
                t.order,
                t.name,
                t.local.installed_version,
                t.local.version_source,
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
        // Tạo 1 shortcut trống bằng WScript.Shell (mô phỏng shortcut thiếu AUMID gây tách 2 icon)
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

        // Lần 1: Thiếu AUMID -> phải đóng dấu và trả về Ok(true)
        let first = win_aumid::ensure_shortcut_aumid(&lnk, win_aumid::LAUNCHER_AUMID)
            .expect("Phải ghi được System.AppUserModel.ID vào .lnk");
        assert!(first, "Lần đầu phải cập nhật .lnk");

        // Lần 2: Đã khớp AUMID -> không ghi đĩa thừa, trả về Ok(false)
        let second = win_aumid::ensure_shortcut_aumid(&lnk, win_aumid::LAUNCHER_AUMID)
            .expect("Phải đọc lại được System.AppUserModel.ID từ .lnk");
        assert!(!second, "Lần hai phải nhận diện đã khớp và bỏ qua ghi đĩa");
    }
}
