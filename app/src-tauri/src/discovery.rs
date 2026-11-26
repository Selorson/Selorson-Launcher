use crate::ledger::ToolLedgerEntry;
use crate::manifest::ToolManifest;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredToolLocal {
    pub is_installed: bool,
    pub active_exe_path: Option<String>,
    pub all_detected_exes: Vec<String>,
    pub installed_version: Option<String>,
    pub version_source: Option<String>,
    pub exe_mtime_secs: Option<u64>,
    pub is_running: bool,
    pub active_processes: Vec<String>,
    pub open_ports: Vec<OpenPortStatus>,
    pub immutable_guards: Vec<ImmutableFileStatus>,
    pub can_rollback: bool,
    pub rollback_target_version: Option<String>,
    #[serde(skip)]
    pub is_verified_ledger_install: bool,
    #[serde(skip)]
    pub matched_pids: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPortStatus {
    pub port: u16,
    pub label: String,
    pub is_open: bool,
    pub blocks_update: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableFileStatus {
    pub path: String,
    pub exists: bool,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct RegistryAppInfo {
    pub display_name: String,
    pub display_version: Option<String>,
    pub install_location: Option<String>,
    pub display_icon: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RunningProcessInfo {
    pub pid: u32,
    pub exe_name_lower: String,
    pub full_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessSnapshot {
    pub entries: Vec<RunningProcessInfo>,
}

fn normalize_path_key(p: &Path) -> String {
    if let Ok(canon) = std::fs::canonicalize(p) {
        let s = canon.to_string_lossy().to_lowercase();
        return s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
    }
    let mut normalized = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    let s = normalized.to_string_lossy().replace('/', "\\").to_lowercase();
    s.strip_prefix(r"\\?\")
        .unwrap_or(&s)
        .trim_end_matches('\\')
        .to_string()
}

pub fn path_is_within_dir(child: &Path, dir: &Path) -> bool {
    let c_key = normalize_path_key(child);
    let d_key = normalize_path_key(dir);
    if d_key.is_empty() || d_key.len() <= 3 {
        // Không bao giờ coi gốc ổ đĩa (VD: "C:" / "E:") là thư mục cài đặt ứng dụng
        return false;
    }
    c_key == d_key || c_key.starts_with(&format!("{d_key}\\"))
}

fn is_generic_process_name(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "app.exe"
            | "main.exe"
            | "launcher.exe"
            | "python.exe"
            | "pythonw.exe"
            | "node.exe"
            | "ffmpeg.exe"
            | "ffprobe.exe"
            | "msedgewebview2.exe"
    )
}

impl ProcessSnapshot {
    /// Trả về `(active_process_labels, matched_pids)` của công cụ:
    /// - Với tên chung như `app.exe`, bắt buộc `full_path` phải nằm trong thư mục ứng dụng/repo của công cụ đó.
    /// - Quét thêm mọi tiến trình phụ/sidecar đang chạy trực tiếp từ thư mục cài đặt ứng dụng (`install_dirs`).
    pub fn match_tool_processes(
        &self,
        tool: &ToolManifest,
        selected_channel: &str,
        extra_install_dirs: &[PathBuf],
    ) -> (Vec<String>, Vec<u32>) {
        let mut tool_install_dirs: Vec<PathBuf> = Vec::new();
        for cand in tool.effective_exe_candidates(selected_channel) {
            if let Some(parent) = Path::new(cand).parent() {
                tool_install_dirs.push(parent.to_path_buf());
            }
        }
        for imm in &tool.protection.immutable_files {
            if let Some(parent) = Path::new(imm).parent() {
                tool_install_dirs.push(parent.to_path_buf());
            }
        }
        for d in extra_install_dirs {
            tool_install_dirs.push(d.clone());
        }

        let repo_dir = PathBuf::from(&tool.git.repo_path);
        // Các thư mục cài đặt thực tế (loại trừ cây mã nguồn Git để tránh bắt nhầm rust-analyzer / git.exe khi dev)
        let strict_install_dirs: Vec<PathBuf> = tool_install_dirs
            .iter()
            .filter(|d| !path_is_within_dir(d, &repo_dir))
            .cloned()
            .collect();

        let mut all_valid_tool_dirs = tool_install_dirs;
        if !tool.git.repo_path.is_empty() {
            all_valid_tool_dirs.push(repo_dir);
        }

        let self_pid = std::process::id();
        let mut active_names: Vec<String> = Vec::new();
        let mut pids: Vec<u32> = Vec::new();

        // 1. Đối chiếu danh sách `running_processes` khai báo trong Manifest
        for declared in &tool.protection.running_processes {
            let dec_low = declared.to_lowercase();
            let generic = is_generic_process_name(&dec_low);

            for proc_info in &self.entries {
                if proc_info.pid == self_pid || proc_info.exe_name_lower != dec_low {
                    continue;
                }
                let matches = if generic {
                    proc_info.full_path.as_ref().is_some_and(|fp| {
                        all_valid_tool_dirs
                            .iter()
                            .any(|dir| path_is_within_dir(fp, dir))
                    })
                } else {
                    // Với tên thực thi đặc thù của hệ sinh thái (cowriter-core.exe, neuroforge.exe...),
                    // luôn nhận diện để bảo vệ chung cơ sở dữ liệu trong %APPDATA% / %LOCALAPPDATA%
                    true
                };

                if matches {
                    if !active_names.iter().any(|x| x.eq_ignore_ascii_case(declared)) {
                        active_names.push(declared.clone());
                    }
                    if !pids.contains(&proc_info.pid) {
                        pids.push(proc_info.pid);
                    }
                }
            }
        }

        // 2. Quét mọi tiến trình con / sidecar có ảnh thực thi nằm bên trong thư mục cài đặt đích
        for proc_info in &self.entries {
            if proc_info.pid == self_pid {
                continue;
            }
            if let Some(fp) = &proc_info.full_path {
                if strict_install_dirs
                    .iter()
                    .any(|dir| path_is_within_dir(fp, dir))
                {
                    let label = fp
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| proc_info.exe_name_lower.clone());
                    if !active_names.iter().any(|x| x.eq_ignore_ascii_case(&label)) {
                        active_names.push(label);
                    }
                    if !pids.contains(&proc_info.pid) {
                        pids.push(proc_info.pid);
                    }
                }
            }
        }

        (active_names, pids)
    }
}

pub fn normalize_semver(raw: &str, custom_prefix: Option<&str>) -> Option<Version> {
    let mut s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(pref) = custom_prefix {
        if !pref.is_empty() && s.starts_with(pref) {
            s = &s[pref.len()..];
        }
    }
    if let Some(stripped) = s.strip_prefix("desktop-admin-v") {
        s = stripped;
    } else if let Some(stripped) = s.strip_prefix('v').or_else(|| s.strip_prefix('V')) {
        s = stripped;
    }
    s = s.trim();

    if let Ok(v) = Version::parse(s) {
        return Some(v);
    }
    // Hỗ trợ định dạng 4 phần của Windows PE FileVersion / Registry (1.8.0.0 -> 1.8.0; 1.8.0.1 -> 1.8.0+build.1)
    let (core_part, suffix_part) = match s.find(['-', '+']) {
        Some(idx) => (&s[..idx], &s[idx..]),
        None => (s, ""),
    };
    let parts: Vec<&str> = core_part.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())) {
        let rebuilt = if parts[3] == "0" || suffix_part.contains('+') {
            format!("{}.{}.{}{}", parts[0], parts[1], parts[2], suffix_part)
        } else {
            format!(
                "{}.{}.{}{}+build.{}",
                parts[0], parts[1], parts[2], suffix_part, parts[3]
            )
        };
        if let Ok(v) = Version::parse(&rebuilt) {
            return Some(v);
        }
    } else if parts.len() == 2 {
        let rebuilt = format!("{}.{}.0{}", parts[0], parts[1], suffix_part);
        if let Ok(v) = Version::parse(&rebuilt) {
            return Some(v);
        }
    }
    None
}

pub fn probe_tcp_port(port: u16) -> bool {
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    if TcpStream::connect_timeout(&v4, Duration::from_millis(35)).is_ok() {
        return true;
    }
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
    TcpStream::connect_timeout(&v6, Duration::from_millis(35)).is_ok()
}

pub fn capture_running_processes() -> ProcessSnapshot {
    let mut entries = Vec::new();
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        };

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot != INVALID_HANDLE_VALUE && !snapshot.is_null() {
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    let len = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let exe_name_lower =
                        String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase();
                    let pid = entry.th32ProcessID;

                    if !exe_name_lower.is_empty() && pid != 0 && pid != 4 {
                        let mut full_path: Option<PathBuf> = None;
                        let h_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                        if !h_proc.is_null() {
                            let mut path_buf = [0u16; 1024];
                            let mut cap = path_buf.len() as u32;
                            if QueryFullProcessImageNameW(h_proc, 0, path_buf.as_mut_ptr(), &mut cap)
                                != 0
                                && cap > 0
                            {
                                let s = String::from_utf16_lossy(&path_buf[..cap as usize]);
                                full_path = Some(PathBuf::from(s));
                            }
                            let _ = CloseHandle(h_proc);
                        }
                        entries.push(RunningProcessInfo {
                            pid,
                            exe_name_lower,
                            full_path,
                        });
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
    }
    ProcessSnapshot { entries }
}

/// Kích hoạt cửa sổ đang mở của một trong các `pids` lên tiền cảnh thay vì phóng bản sao thứ 2.
/// Trả về `true` nếu tìm thấy và kích hoạt được cửa sổ hiển thị thuộc `pids`.
#[cfg(windows)]
pub fn focus_existing_process_window(pids: &[u32]) -> bool {
    if pids.is_empty() {
        return false;
    }
    unsafe {
        use windows_sys::Win32::Foundation::HWND;
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetWindow, GetWindowThreadProcessId, GW_OWNER, IsIconic, IsWindowVisible,
            SW_RESTORE, SetForegroundWindow, ShowWindow,
        };

        struct EnumCtx<'a> {
            pids: &'a [u32],
            found_hwnd: HWND,
        }

        unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: isize) -> i32 {
            unsafe {
                let ctx = &mut *(lparam as *mut EnumCtx<'_>);
                if IsWindowVisible(hwnd) == 0 {
                    return 1;
                }
                if !GetWindow(hwnd, GW_OWNER).is_null() {
                    return 1;
                }
                let mut win_pid: u32 = 0;
                GetWindowThreadProcessId(hwnd, &mut win_pid);
                if ctx.pids.contains(&win_pid) {
                    ctx.found_hwnd = hwnd;
                    return 0; // Dừng quét ngay khi tìm thấy cửa sổ chính
                }
                1
            }
        }

        let mut ctx = EnumCtx {
            pids,
            found_hwnd: std::ptr::null_mut(),
        };
        let _ = EnumWindows(Some(enum_cb), (&mut ctx as *mut EnumCtx<'_>) as isize);
        if !ctx.found_hwnd.is_null() {
            if IsIconic(ctx.found_hwnd) != 0 {
                let _ = ShowWindow(ctx.found_hwnd, SW_RESTORE);
            }
            let _ = SetForegroundWindow(ctx.found_hwnd);
            return true;
        }
    }
    false
}

#[cfg(not(windows))]
pub fn focus_existing_process_window(_pids: &[u32]) -> bool {
    false
}

pub fn read_pe_version(path: &Path) -> Option<String> {
    #[cfg(windows)]
    unsafe {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
        };

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut handle: u32 = 0;
        let size = GetFileVersionInfoSizeW(wide.as_ptr(), &mut handle);
        if size == 0 {
            return None;
        }
        let mut buffer = vec![0u8; size as usize];
        if GetFileVersionInfoW(wide.as_ptr(), 0, size, buffer.as_mut_ptr() as *mut _) == 0 {
            return None;
        }

        // Ưu tiên đọc chuỗi `StringFileInfo\...\ProductVersion` để giữ nguyên hậu tố pre-release (-beta.1, -rc.2...)
        let trans_query: Vec<u16> = "\\VarFileInfo\\Translation\0".encode_utf16().collect();
        let mut trans_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut trans_len: u32 = 0;
        let mut lang_codepages: Vec<(u16, u16)> = Vec::new();
        if VerQueryValueW(
            buffer.as_ptr() as *const _,
            trans_query.as_ptr(),
            &mut trans_ptr,
            &mut trans_len,
        ) != 0
            && !trans_ptr.is_null()
            && trans_len >= 4
        {
            let words = std::slice::from_raw_parts(trans_ptr as *const u16, (trans_len / 2) as usize);
            for chunk in words.chunks_exact(2) {
                lang_codepages.push((chunk[0], chunk[1]));
            }
        }
        // Dự phòng các bảng mã phổ biến của Tauri / MSVC RC
        for fallback in [(0x0409, 0x04B0), (0x0000, 0x04B0), (0x0409, 0x04E4)] {
            if !lang_codepages.contains(&fallback) {
                lang_codepages.push(fallback);
            }
        }

        let mut string_prod_ver: Option<Version> = None;
        for (lang, cp) in lang_codepages {
            for field in ["ProductVersion", "FileVersion"] {
                let query = format!("\\StringFileInfo\\{lang:04x}{cp:04x}\\{field}\0");
                let wquery: Vec<u16> = query.encode_utf16().collect();
                let mut str_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
                let mut str_len: u32 = 0;
                if VerQueryValueW(
                    buffer.as_ptr() as *const _,
                    wquery.as_ptr(),
                    &mut str_ptr,
                    &mut str_len,
                ) != 0
                    && !str_ptr.is_null()
                    && str_len > 0
                {
                    let slice = std::slice::from_raw_parts(str_ptr as *const u16, str_len as usize);
                    let nul_pos = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                    let val = String::from_utf16_lossy(&slice[..nul_pos]).trim().to_string();
                    if let Some(v) = normalize_semver(&val, None) {
                        if !(v.major == 0 && v.minor == 0 && v.patch == 0) {
                            // Nếu chuỗi có hậu tố pre-release thì ưu tiên ngay lập tức
                            if !v.pre.is_empty() {
                                return Some(v.to_string());
                            }
                            if string_prod_ver.as_ref().is_none_or(|cur| v > *cur) {
                                string_prod_ver = Some(v);
                            }
                        }
                    }
                }
            }
        }

        let sub_block: [u16; 2] = [b'\\' as u16, 0];
        let mut lp_buffer: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        if VerQueryValueW(
            buffer.as_ptr() as *const _,
            sub_block.as_ptr(),
            &mut lp_buffer,
            &mut len,
        ) == 0
            || lp_buffer.is_null()
            || (len as usize) < std::mem::size_of::<VS_FIXEDFILEINFO>()
        {
            return string_prod_ver.map(|v| v.to_string());
        }
        let info = &*(lp_buffer as *const VS_FIXEDFILEINFO);
        if info.dwSignature != 0xFEEF04BD {
            return string_prod_ver.map(|v| v.to_string());
        }
        let prod_major = (info.dwProductVersionMS >> 16) & 0xFFFF;
        let prod_minor = info.dwProductVersionMS & 0xFFFF;
        let prod_patch = (info.dwProductVersionLS >> 16) & 0xFFFF;

        let file_major = (info.dwFileVersionMS >> 16) & 0xFFFF;
        let file_minor = info.dwFileVersionMS & 0xFFFF;
        let file_patch = (info.dwFileVersionLS >> 16) & 0xFFFF;

        let prod_ver = Version::new(prod_major as u64, prod_minor as u64, prod_patch as u64);
        let file_ver = Version::new(file_major as u64, file_minor as u64, file_patch as u64);
        let mut best = std::cmp::max(prod_ver, file_ver);
        if let Some(sv) = string_prod_ver {
            if sv > best {
                best = sv;
            }
        }
        if best.major == 0 && best.minor == 0 && best.patch == 0 {
            return None;
        }
        return Some(best.to_string());
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

pub fn scan_uninstall_registry() -> Vec<RegistryAppInfo> {
    let mut apps = Vec::new();
    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};

        let roots = [
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
        ];

        for (hive, subkey_path) in roots {
            let root = RegKey::predef(hive);
            if let Ok(uninstall) = root.open_subkey_with_flags(subkey_path, KEY_READ) {
                for key_name in uninstall.enum_keys().flatten() {
                    if let Ok(sub) = uninstall.open_subkey_with_flags(&key_name, KEY_READ) {
                        let display_name: Result<String, _> = sub.get_value("DisplayName");
                        if let Ok(name) = display_name {
                            if !name.trim().is_empty() {
                                let display_version: Option<String> =
                                    sub.get_value("DisplayVersion").ok();
                                let install_location: Option<String> = sub
                                    .get_value::<String, _>("InstallLocation")
                                    .ok()
                                    .map(|s| s.trim_matches('"').to_string())
                                    .filter(|s| !s.is_empty());
                                let display_icon: Option<String> = sub
                                    .get_value::<String, _>("DisplayIcon")
                                    .ok()
                                    .map(|s| {
                                        s.split(',')
                                            .next()
                                            .unwrap_or("")
                                            .trim()
                                            .trim_matches('"')
                                            .to_string()
                                    })
                                    .filter(|s| !s.is_empty());
                                apps.push(RegistryAppInfo {
                                    display_name: name,
                                    display_version,
                                    install_location,
                                    display_icon,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    apps
}

fn file_mtime_and_size(path: &Path) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((mtime, meta.len()))
}

/// Khớp chính xác tên khóa Uninstall Registry (hoặc chỉ cho phép hậu tố số phiên bản như `"Co-Writer 1.8.0"`),
/// tuyệt đối không để `"NeuroForge"` khớp tràn sang `"NeuroForge RTX"`.
pub fn registry_name_matches_pattern(display_name: &str, pattern: &str) -> bool {
    let r_low = display_name.trim().to_lowercase();
    let p_low = pattern.trim().to_lowercase();
    if p_low.is_empty() {
        return false;
    }
    if r_low == p_low {
        return true;
    }
    if let Some(rest) = r_low.strip_prefix(&format!("{p_low} ")) {
        let rest = rest.trim();
        let ver_tail = rest.strip_prefix('v').unwrap_or(rest);
        return ver_tail
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit());
    }
    false
}

pub fn discover_tool_local(
    tool: &ToolManifest,
    selected_channel: &str,
    running_procs: &ProcessSnapshot,
    registry_apps: &[RegistryAppInfo],
    ledger_entry: Option<&ToolLedgerEntry>,
    precomputed_ports: Option<&std::collections::HashMap<u16, bool>>,
) -> DiscoveredToolLocal {
    let channel_exe_candidates = tool.effective_exe_candidates(selected_channel);
    let channel_reg_names = tool.effective_registry_names(selected_channel);

    // 1. Khớp khóa Registry Uninstall riêng theo kênh đang chọn
    let matched_regs: Vec<&RegistryAppInfo> = registry_apps
        .iter()
        .filter(|r| {
            channel_reg_names
                .iter()
                .any(|pat| registry_name_matches_pattern(&r.display_name, pat))
        })
        .collect();

    let best_reg_version: Option<Version> = matched_regs
        .iter()
        .filter_map(|r| r.display_version.as_deref())
        .filter_map(|v| normalize_semver(v, Some(&tool.git.tag_prefix)))
        .max();

    // 2. Gom các ứng viên .exe thuộc đúng kênh đang chọn
    let mut raw_candidates: Vec<PathBuf> = Vec::new();
    if let Some(le) = ledger_entry {
        if le.channel.eq_ignore_ascii_case(selected_channel) {
            raw_candidates.push(PathBuf::from(&le.exe_path));
        }
    }
    for r in &matched_regs {
        if let Some(loc) = &r.install_location {
            raw_candidates.push(PathBuf::from(loc).join(&tool.install.exe_filename));
        }
        if let Some(icon) = &r.display_icon {
            if icon.to_lowercase().ends_with(".exe") {
                raw_candidates.push(PathBuf::from(icon));
            }
        }
    }
    for cand in channel_exe_candidates {
        raw_candidates.push(PathBuf::from(cand));
    }

    let channel_candidate_dirs: Vec<PathBuf> = channel_exe_candidates
        .iter()
        .filter_map(|c| Path::new(c).parent().map(|p| p.to_path_buf()))
        .filter(|d| !path_is_within_dir(d, Path::new(&tool.git.repo_path)))
        .collect();

    let mut seen_keys = HashSet::new();
    // (path, chosen_ver, chosen_src, mtime, size, is_verified_ledger)
    let mut scored_exes: Vec<(PathBuf, Option<Version>, String, u64, u64, bool)> = Vec::new();

    for cand in raw_candidates {
        if let Some((mtime, size)) = file_mtime_and_size(&cand) {
            let canon_key = normalize_path_key(&cand);
            if !seen_keys.insert(canon_key.clone()) {
                continue;
            }

            let ledger_ver = ledger_entry.and_then(|le| {
                if le.channel.eq_ignore_ascii_case(selected_channel)
                    && normalize_path_key(Path::new(&le.exe_path)) == canon_key
                    && le.exe_size == size
                    && le.exe_mtime_secs == mtime
                {
                    normalize_semver(&le.installed_version, Some(&tool.git.tag_prefix))
                } else {
                    None
                }
            });

            if let Some(lv) = ledger_ver {
                // Dấu vân tay (path, size, mtime) khớp tuyệt đối với sổ cái Launcher Ledger -> ưu tiên duy nhất (không để Registry cũ đè ngược khi Rollback/Hot-Swap!)
                scored_exes.push((
                    cand,
                    Some(lv),
                    "Launcher Ledger".to_string(),
                    mtime,
                    size,
                    true,
                ));
                continue;
            }

            let pe_ver = read_pe_version(&cand)
                .and_then(|s| normalize_semver(&s, Some(&tool.git.tag_prefix)));

            // Chỉ áp dụng Registry version khi ứng viên thực sự thuộc thư mục InstallLocation / DisplayIcon của khóa Registry khớp kênh (hoặc thư mục cài đặt chuẩn ngoài cây repo)
            let applies_reg = matched_regs.iter().any(|r| {
                if let Some(loc) = &r.install_location {
                    if path_is_within_dir(&cand, Path::new(loc)) {
                        return true;
                    }
                }
                if let Some(icon) = &r.display_icon {
                    if let Some(icon_dir) = Path::new(icon).parent() {
                        if path_is_within_dir(&cand, icon_dir) {
                            return true;
                        }
                    }
                }
                r.install_location.is_none()
                    && r.display_icon.is_none()
                    && channel_candidate_dirs
                        .iter()
                        .any(|d| path_is_within_dir(&cand, d))
            });

            let reg_ver = if applies_reg {
                best_reg_version.clone()
            } else {
                None
            };

            let mut chosen_ver: Option<Version> = None;
            let mut chosen_src = String::from("PE Header");

            for (v_opt, label) in [
                (pe_ver, "PE FileVersion"),
                (reg_ver, "Windows Registry"),
            ] {
                if let Some(v) = v_opt {
                    if chosen_ver.as_ref().is_none_or(|cur| v > *cur) {
                        chosen_ver = Some(v);
                        chosen_src = label.to_string();
                    }
                }
            }

            scored_exes.push((cand, chosen_ver, chosen_src, mtime, size, false));
        }
    }

    // Ưu tiên: Tệp đã xác thực trong Ledger -> Phiên bản SemVer cao nhất -> Thời gian cập nhật tệp mới nhất
    scored_exes.sort_by(|a, b| {
        b.5.cmp(&a.5)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| b.3.cmp(&a.3))
    });

    let all_detected_exes: Vec<String> = scored_exes
        .iter()
        .map(|x| x.0.to_string_lossy().to_string())
        .collect();

    let (
        is_installed,
        active_exe_path,
        installed_version,
        version_source,
        exe_mtime_secs,
        is_verified_ledger_install,
    ) = if let Some((best_path, best_ver, best_src, best_mtime, _, verified_ledger)) =
        scored_exes.first()
    {
        (
            true,
            Some(best_path.to_string_lossy().to_string()),
            best_ver.as_ref().map(|v| v.to_string()),
            Some(best_src.clone()),
            Some(*best_mtime),
            *verified_ledger,
        )
    } else {
        (false, None, None, None, None, false)
    };

    // 3. Kiểm tra tiến trình sống theo đường dẫn ảnh đầy đủ + quét sidecar trong thư mục cài đặt
    let mut extra_install_dirs = Vec::new();
    for r in &matched_regs {
        if let Some(loc) = &r.install_location {
            extra_install_dirs.push(PathBuf::from(loc));
        }
    }
    if let Some(ref exe_s) = active_exe_path {
        if let Some(p) = Path::new(exe_s).parent() {
            extra_install_dirs.push(p.to_path_buf());
        }
    }
    let (active_processes, matched_pids) =
        running_procs.match_tool_processes(tool, selected_channel, &extra_install_dirs);

    // 4. Dò cổng dịch vụ (tái sử dụng kết quả dò cổng dùng chung nếu đã có để tránh mở kết nối TCP lặp trên :8188)
    let mut open_ports = Vec::new();
    for hp in &tool.protection.health_ports {
        let open = precomputed_ports
            .and_then(|m| m.get(&hp.port).copied())
            .unwrap_or_else(|| probe_tcp_port(hp.port));
        open_ports.push(OpenPortStatus {
            port: hp.port,
            label: hp.label.clone(),
            is_open: open,
            blocks_update: hp.block_update_when_open,
        });
    }

    let is_running = !active_processes.is_empty()
        || open_ports
            .iter()
            .any(|p| p.is_open && p.blocks_update);

    // 5. Trạng thái các tệp khóa bất biến (ví dụ cowriter-core.exe)
    let mut immutable_guards = Vec::new();
    for imm in &tool.protection.immutable_files {
        let p = Path::new(imm);
        let (exists, size_bytes) = match std::fs::metadata(p) {
            Ok(m) if m.is_file() => (true, m.len()),
            _ => (false, 0),
        };
        immutable_guards.push(ImmutableFileStatus {
            path: imm.clone(),
            exists,
            size_bytes,
        });
    }

    DiscoveredToolLocal {
        is_installed,
        active_exe_path,
        all_detected_exes,
        installed_version,
        version_source,
        exe_mtime_secs,
        is_running,
        active_processes,
        open_ports,
        immutable_guards,
        can_rollback: false,
        rollback_target_version: None,
        is_verified_ledger_install,
        matched_pids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        GitSpec, InstallSpec, ProtectionSpec, ReleaseChannelSpec, ToolManifest, UpdaterSpec,
    };
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    #[test]
    fn normalizes_mixed_ecosystem_version_strings_including_4_part_and_prerelease() {
        assert_eq!(
            normalize_semver("v2.3.1", Some("v")),
            Some(Version::new(2, 3, 1))
        );
        assert_eq!(
            normalize_semver("1.9.0", Some("v")),
            Some(Version::new(1, 9, 0))
        );
        assert_eq!(
            normalize_semver("desktop-admin-v0.1.15", Some("desktop-admin-v")),
            Some(Version::new(0, 1, 15))
        );
        assert_eq!(
            normalize_semver("3.0.87.0", Some("v")),
            Some(Version::new(3, 0, 87))
        );
        // 4 phần có số thứ 4 khác 0 -> chuẩn hóa thành +build.W thay vì trả None!
        let four_part = normalize_semver("1.8.0.1", Some("v"))
            .expect("Phải phân tích được PE FileVersion 4 phần 1.8.0.1");
        assert_eq!(four_part.major, 1);
        assert_eq!(four_part.minor, 8);
        assert_eq!(four_part.patch, 0);
        assert_eq!(four_part.build.as_str(), "build.1");

        // Giữ nguyên hậu tố pre-release
        let pre = normalize_semver("v2.4.0-beta.1", Some("v")).unwrap();
        let release = normalize_semver("v2.4.0", Some("v")).unwrap();
        assert!(pre < release, "2.4.0-beta.1 bắt buộc nhỏ hơn 2.4.0 theo chuẩn SemVer");
    }

    #[test]
    fn isolates_channels_and_prioritizes_verified_ledger_over_stale_registry() {
        let tmp = tempdir().unwrap();
        let rtx_dir = tmp.path().join("NeuroForge RTX");
        let std_dir = tmp.path().join("NeuroForge");
        std::fs::create_dir_all(&rtx_dir).unwrap();
        std::fs::create_dir_all(&std_dir).unwrap();

        let rtx_exe = rtx_dir.join("neuroforge.exe");
        std::fs::write(&rtx_exe, b"MZ_RTX_BINARY").unwrap();
        let (mtime, size) = file_mtime_and_size(&rtx_exe).unwrap();

        let mut channels = BTreeMap::new();
        channels.insert(
            "rtx".to_string(),
            ReleaseChannelSpec {
                label: "RTX".to_string(),
                endpoint: "https://example.com/latest-rtx.json".to_string(),
                pubkey: "A".repeat(44),
                exe_candidates: vec![rtx_exe.to_string_lossy().to_string()],
                registry_names: vec!["NeuroForge RTX".to_string()],
            },
        );
        channels.insert(
            "standard".to_string(),
            ReleaseChannelSpec {
                label: "Standard".to_string(),
                endpoint: "https://example.com/latest.json".to_string(),
                pubkey: "A".repeat(44),
                exe_candidates: vec![std_dir.join("neuroforge.exe").to_string_lossy().to_string()],
                registry_names: vec!["NeuroForge".to_string()],
            },
        );

        let tool = ToolManifest {
            id: "neuroforge".to_string(),
            order: 5,
            name: "NeuroForge RTX".to_string(),
            subtitle: String::new(),
            category: String::new(),
            accent_color: "#EF4444".to_string(),
            icon: None,
            install: InstallSpec {
                installer_kind: "tauri-nsis".to_string(),
                exe_candidates: vec![rtx_exe.to_string_lossy().to_string()],
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
                repo_path: tmp.path().join("repo").to_string_lossy().to_string(),
                watch_paths: vec!["tauri-app".to_string()],
                extra_repos: vec![],
                tag_prefix: "v".to_string(),
                hot_swap_hint: None,
            },
        };

        // Registry còn lưu số cũ cao hơn (v3.0.99) sau khi người dùng đã Rollback về v3.0.88 trong Ledger
        let regs = vec![RegistryAppInfo {
            display_name: "NeuroForge RTX".to_string(),
            display_version: Some("3.0.99".to_string()),
            install_location: Some(rtx_dir.to_string_lossy().to_string()),
            display_icon: None,
        }];
        let procs = ProcessSnapshot::default();

        // 1. Khi chọn kênh "standard" (chưa cài) -> KHÔNG ĐƯỢC lấy nhầm bản RTX hay Registry "NeuroForge RTX"!
        assert!(!registry_name_matches_pattern("NeuroForge RTX", "NeuroForge"));
        assert!(registry_name_matches_pattern("Co-Writer 1.8.0", "Co-Writer"));
        let std_disc = discover_tool_local(&tool, "standard", &procs, &regs, None, None);
        assert!(
            !std_disc.is_installed,
            "Kênh standard chưa cài không được mượn nhầm tệp .exe của kênh RTX"
        );

        // 2. Khi chọn kênh "rtx" với Ledger khớp (path, size, mtime) ở v3.0.88 -> Ledger phải thắng Registry v3.0.99!
        let ledger = ToolLedgerEntry {
            exe_path: rtx_exe.to_string_lossy().to_string(),
            exe_size: size,
            exe_mtime_secs: mtime,
            installed_version: "3.0.88".to_string(),
            channel: "rtx".to_string(),
            installed_at_iso: "2026-11-26T00:00:00Z".to_string(),
        };
        let rtx_disc = discover_tool_local(&tool, "rtx", &procs, &regs, Some(&ledger), None);
        assert!(rtx_disc.is_installed);
        assert!(rtx_disc.is_verified_ledger_install);
        assert_eq!(rtx_disc.installed_version.as_deref(), Some("3.0.88"));
        assert_eq!(rtx_disc.version_source.as_deref(), Some("Launcher Ledger"));
    }

    #[test]
    fn disambiguates_generic_app_exe_and_detects_sidecars_inside_install_dir() {
        let tmp = tempdir().unwrap();
        let admin_dir = tmp.path().join("Selorson Admin");
        let other_dir = tmp.path().join("ThirdPartyTool");
        std::fs::create_dir_all(&admin_dir).unwrap();
        std::fs::create_dir_all(&other_dir).unwrap();

        let tool = ToolManifest {
            id: "selorson-admin".to_string(),
            order: 4,
            name: "Selorson Admin".to_string(),
            subtitle: String::new(),
            category: String::new(),
            accent_color: "#EC4899".to_string(),
            icon: None,
            install: InstallSpec {
                installer_kind: "tauri-nsis".to_string(),
                exe_candidates: vec![admin_dir.join("app.exe").to_string_lossy().to_string()],
                registry_names: vec!["Selorson Admin".to_string()],
                exe_filename: "app.exe".to_string(),
                launch_args: vec![],
                working_dir: None,
            },
            updater: UpdaterSpec {
                default_channel: "stable".to_string(),
                channels: BTreeMap::new(),
            },
            protection: ProtectionSpec {
                running_processes: vec!["app.exe".to_string()],
                ..Default::default()
            },
            git: GitSpec {
                repo_path: tmp.path().join("repo").to_string_lossy().to_string(),
                watch_paths: vec!["src".to_string()],
                extra_repos: vec![],
                tag_prefix: "v".to_string(),
                hot_swap_hint: None,
            },
        };

        // Tiến trình `app.exe` của bên thứ ba ngoài thư mục -> KHÔNG báo giả đang chạy
        let foreign_snap = ProcessSnapshot {
            entries: vec![RunningProcessInfo {
                pid: 99991,
                exe_name_lower: "app.exe".to_string(),
                full_path: Some(other_dir.join("app.exe")),
            }],
        };
        let (names_foreign, _) = foreign_snap.match_tool_processes(&tool, "stable", &[]);
        assert!(names_foreign.is_empty());

        // Tiến trình con / sidecar bất kỳ nằm trong thư mục cài đặt đích -> PHẢI bắt được để chặn treo NSIS
        let sidecar_snap = ProcessSnapshot {
            entries: vec![RunningProcessInfo {
                pid: 99992,
                exe_name_lower: "helper-worker.exe".to_string(),
                full_path: Some(admin_dir.join("helper-worker.exe")),
            }],
        };
        let (names_sidecar, pids_sidecar) = sidecar_snap.match_tool_processes(&tool, "stable", &[]);
        assert_eq!(names_sidecar, vec!["helper-worker.exe".to_string()]);
        assert_eq!(pids_sidecar, vec![99992]);
    }
}
