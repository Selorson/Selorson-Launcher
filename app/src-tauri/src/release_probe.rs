use crate::discovery::normalize_semver;
use crate::git_drift::GitDriftStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TauriLatestManifest {
    pub version: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub pub_date: Option<String>,
    #[serde(default)]
    pub platforms: HashMap<String, TauriPlatformAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TauriPlatformAsset {
    pub signature: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteReleaseInfo {
    pub channel: String,
    pub raw_version: String,
    pub normalized_version: String,
    pub pub_date: Option<String>,
    pub notes: Option<String>,
    pub download_url: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ReleaseComparisonState {
    NotInstalled,
    UpdateAvailable,
    UpToDate,
    LocalNewerOrHotSwapped,
    OfflineOrError { message: String },
}

pub fn build_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent("Selorson-Launcher/0.1.0")
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|e| format!("Không khởi tạo được HTTP client: {e}"))
}

pub async fn fetch_remote_release(
    client: &reqwest::Client,
    channel_key: &str,
    endpoint: &str,
    tag_prefix: &str,
) -> Result<RemoteReleaseInfo, String> {
    let resp = client
        .get(endpoint)
        .send()
        .await
        .map_err(|e| format!("Không kết nối được tới kênh phát hành: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Kênh phát hành trả về mã HTTP {}",
            resp.status().as_u16()
        ));
    }

    let payload: TauriLatestManifest = resp
        .json()
        .await
        .map_err(|e| format!("Dữ liệu latest.json không hợp lệ: {e}"))?;

    let asset = payload
        .platforms
        .get("windows-x86_64")
        .or_else(|| payload.platforms.get("windows-x86_64-nsis"))
        .ok_or_else(|| "Bản phát hành không chứa gói cài đặt cho windows-x86_64.".to_string())?;

    let norm = normalize_semver(&payload.version, Some(tag_prefix))
        .ok_or_else(|| format!("Không phân tích được số phiên bản '{}'.", payload.version))?;

    Ok(RemoteReleaseInfo {
        channel: channel_key.to_string(),
        raw_version: payload.version,
        normalized_version: norm.to_string(),
        pub_date: payload.pub_date,
        notes: payload.notes,
        download_url: asset.url.clone(),
        signature: asset.signature.clone(),
    })
}

pub fn compare_installed_vs_remote(
    is_installed: bool,
    installed_version: Option<&str>,
    tag_prefix: &str,
    remote: &Result<RemoteReleaseInfo, String>,
    git_drift: &GitDriftStatus,
) -> ReleaseComparisonState {
    let Ok(rem) = remote else {
        let err = remote.as_ref().err().cloned().unwrap_or_default();
        return if !is_installed {
            ReleaseComparisonState::NotInstalled
        } else {
            ReleaseComparisonState::OfflineOrError { message: err }
        };
    };

    if !is_installed {
        return ReleaseComparisonState::NotInstalled;
    }

    let Some(inst_str) = installed_version else {
        return ReleaseComparisonState::UpdateAvailable;
    };

    let inst_v = normalize_semver(inst_str, Some(tag_prefix));
    let rem_v = normalize_semver(&rem.normalized_version, Some(tag_prefix));

    match (inst_v, rem_v) {
        (Some(iv), Some(rv)) => {
            if rv > iv {
                ReleaseComparisonState::UpdateAvailable
            } else if iv > rv {
                ReleaseComparisonState::LocalNewerOrHotSwapped
            } else if matches!(git_drift, GitDriftStatus::HotSwappedAhead { .. }) {
                ReleaseComparisonState::LocalNewerOrHotSwapped
            } else {
                ReleaseComparisonState::UpToDate
            }
        }
        _ => ReleaseComparisonState::UpToDate,
    }
}
