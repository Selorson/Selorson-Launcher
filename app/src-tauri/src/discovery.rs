use crate::ledger::ToolLedgerEntry;
use crate::manifest::ToolManifest;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
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
    // Hỗ trợ định dạng 4 phần của Windows PE FileVersion (ví dụ 1.8.0.0 -> 1.8.0)
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 && parts[3] == "0" {
        let three = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
        if let Ok(v) = Version::parse(&three) {
            return Some(v);
        }
    } else if parts.len() == 2 {
        let three = format!("{}.{}.0", parts[0], parts[1]);
        if let Ok(v) = Version::parse(&three) {
            return Some(v);
        }
    }
    None
}

pub fn probe_tcp_port(port: u16) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    TcpStream::connect_timeout(&addr, Duration::from_millis(45)).is_ok()
}

pub fn capture_running_processes() -> HashSet<String> {
    let mut set = HashSet::new();
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
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
                    let name = String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase();
                    if !name.is_empty() {
                        set.insert(name);
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }
    }
    set
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
            return None;
        }
        let info = &*(lp_buffer as *const VS_FIXEDFILEINFO);
        if info.dwSignature != 0xFEEF04BD {
            return None;
        }
        let prod_major = (info.dwProductVersionMS >> 16) & 0xFFFF;
        let prod_minor = info.dwProductVersionMS & 0xFFFF;
        let prod_patch = (info.dwProductVersionLS >> 16) & 0xFFFF;

        let file_major = (info.dwFileVersionMS >> 16) & 0xFFFF;
        let file_minor = info.dwFileVersionMS & 0xFFFF;
        let file_patch = (info.dwFileVersionLS >> 16) & 0xFFFF;

        let prod_ver = Version::new(prod_major as u64, prod_minor as u64, prod_patch as u64);
        let file_ver = Version::new(file_major as u64, file_minor as u64, file_patch as u64);
        let best = std::cmp::max(prod_ver, file_ver);
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

pub fn discover_tool_local(
    tool: &ToolManifest,
    running_procs: &HashSet<String>,
    registry_apps: &[RegistryAppInfo],
    ledger_entry: Option<&ToolLedgerEntry>,
) -> DiscoveredToolLocal {
    // 1. Khớp khóa Registry Uninstall
    let matched_regs: Vec<&RegistryAppInfo> = registry_apps
        .iter()
        .filter(|r| {
            let r_low = r.display_name.to_lowercase();
            tool.install.registry_names.iter().any(|pat| {
                let p_low = pat.to_lowercase();
                r_low == p_low || r_low.starts_with(&format!("{p_low} "))
            })
        })
        .collect();

    let best_reg_version: Option<Version> = matched_regs
        .iter()
        .filter_map(|r| r.display_version.as_deref())
        .filter_map(|v| normalize_semver(v, Some(&tool.git.tag_prefix)))
        .max();

    // 2. Gom tất cả ứng viên .exe thực sự tồn tại trên đĩa
    let mut raw_candidates: Vec<PathBuf> = Vec::new();
    if let Some(le) = ledger_entry {
        raw_candidates.push(PathBuf::from(&le.exe_path));
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
    for cand in &tool.install.exe_candidates {
        raw_candidates.push(PathBuf::from(cand));
    }

    let mut seen_keys = HashSet::new();
    let mut scored_exes: Vec<(PathBuf, Option<Version>, String, u64, u64)> = Vec::new();

    for cand in raw_candidates {
        if let Some((mtime, size)) = file_mtime_and_size(&cand) {
            let canon_key = cand.to_string_lossy().to_lowercase();
            if !seen_keys.insert(canon_key.clone()) {
                continue;
            }

            let pe_ver = read_pe_version(&cand)
                .and_then(|s| normalize_semver(&s, Some(&tool.git.tag_prefix)));

            let ledger_ver = ledger_entry.and_then(|le| {
                if le.exe_path.to_lowercase() == canon_key
                    && le.exe_size == size
                    && le.exe_mtime_secs == mtime
                {
                    normalize_semver(&le.installed_version, Some(&tool.git.tag_prefix))
                } else {
                    None
                }
            });

            // Chỉ áp dụng Registry version cho ứng viên nằm trong %LOCALAPPDATA% hoặc khớp InstallLocation
            let applies_reg = matched_regs.iter().any(|r| {
                r.install_location
                    .as_ref()
                    .is_some_and(|loc| canon_key.starts_with(&loc.to_lowercase()))
            }) || canon_key.contains("appdata\\local");

            let reg_ver = if applies_reg {
                best_reg_version.clone()
            } else {
                None
            };

            // Giải quyết trường hợp Cargo.toml gốc để "1.0.0" chưa bơm tag (như Co-Writer) trong khi Registry ghi "1.8.0"
            let mut chosen_ver: Option<Version> = None;
            let mut chosen_src = String::from("PE Header");

            for (v_opt, label) in [
                (ledger_ver, "Launcher Ledger"),
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

            scored_exes.push((cand, chosen_ver, chosen_src, mtime, size));
        }
    }

    // Ưu tiên: Phiên bản SemVer cao nhất -> Thời gian cập nhật tệp mới nhất
    scored_exes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.3.cmp(&a.3)));

    let all_detected_exes: Vec<String> = scored_exes
        .iter()
        .map(|x| x.0.to_string_lossy().to_string())
        .collect();

    let (is_installed, active_exe_path, installed_version, version_source, exe_mtime_secs) =
        if let Some((best_path, best_ver, best_src, best_mtime, _)) = scored_exes.first() {
            (
                true,
                Some(best_path.to_string_lossy().to_string()),
                best_ver.as_ref().map(|v| v.to_string()),
                Some(best_src.clone()),
                Some(*best_mtime),
            )
        } else {
            (false, None, None, None, None)
        };

    // 3. Kiểm tra tiến trình sống (bao gồm cả trường hợp Selorson Admin dùng tên chung app.exe: kiểm tra cẩn thận)
    let mut active_processes = Vec::new();
    for proc_name in &tool.protection.running_processes {
        let p_low = proc_name.to_lowercase();
        if running_procs.contains(&p_low) && !active_processes.contains(proc_name) {
            active_processes.push(proc_name.clone());
        }
    }

    // 4. Dò cổng dịch vụ
    let mut open_ports = Vec::new();
    for hp in &tool.protection.health_ports {
        let open = probe_tcp_port(hp.port);
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

    let _ = HashMap::<u8, u8>::new();

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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_mixed_ecosystem_version_strings() {
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
    }
}
