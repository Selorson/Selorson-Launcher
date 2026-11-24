use crate::manifest::GitSpec;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitCommitSummary {
    pub short_sha: String,
    pub full_sha: String,
    pub timestamp_secs: u64,
    pub date_iso: String,
    pub subject: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GitDriftStatus {
    /// Không tìm thấy kho Git cục bộ (vẫn dùng bình thường qua GitHub Releases)
    RepoMissing,
    /// Chưa cài bản .exe trên máy
    NotInstalled,
    /// Bản .exe khớp hoàn toàn với mã nguồn đã commit trong watch_paths
    InSync,
    /// Mã nguồn trong watch_paths có N commit mới hơn bản .exe đang cài
    SourceAhead {
        commits_ahead: usize,
        comparison_basis: String,
    },
    /// Bản .exe được biên dịch/Hot-Swap cục bộ MỚI HƠN tag phát hành (chứa các commit mới)
    HotSwappedAhead {
        commits_since_tag: usize,
        base_tag: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRepoReport {
    pub repo_exists: bool,
    pub branch: Option<String>,
    pub head_watch_commit: Option<GitCommitSummary>,
    pub dirty_files_count: usize,
    pub drift_status: GitDriftStatus,
    pub ahead_commits: Vec<GitCommitSummary>,
}

async fn run_git(repo_dir: &Path, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo_dir).args(args);
    #[cfg(windows)]
    {
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let output = cmd.output().await.ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn parse_commit_line(line: &str) -> Option<GitCommitSummary> {
    let mut parts = line.splitn(5, '|');
    let full_sha = parts.next()?.trim().to_string();
    let short_sha = parts.next()?.trim().to_string();
    let ts_str = parts.next()?.trim();
    let timestamp_secs: u64 = ts_str.parse().ok()?;
    let date_iso = parts.next()?.trim().to_string();
    let subject = parts.next()?.trim().to_string();
    if full_sha.is_empty() {
        return None;
    }
    Some(GitCommitSummary {
        short_sha,
        full_sha,
        timestamp_secs,
        date_iso,
        subject,
    })
}

pub async fn inspect_git_drift(
    git_spec: &GitSpec,
    installed_version: Option<&str>,
    exe_mtime_secs: Option<u64>,
    remote_version: Option<&str>,
) -> GitRepoReport {
    let repo_path = Path::new(&git_spec.repo_path);
    if !repo_path.exists() {
        return GitRepoReport {
            repo_exists: false,
            branch: None,
            head_watch_commit: None,
            dirty_files_count: 0,
            drift_status: GitDriftStatus::RepoMissing,
            ahead_commits: Vec::new(),
        };
    }

    // Kiểm tra đây có thực sự nằm trong một kho Git không
    if run_git(repo_path, &["rev-parse", "--is-inside-work-tree"])
        .await
        .is_none()
    {
        return GitRepoReport {
            repo_exists: false,
            branch: None,
            head_watch_commit: None,
            dirty_files_count: 0,
            drift_status: GitDriftStatus::RepoMissing,
            ahead_commits: Vec::new(),
        };
    }

    let branch = run_git(repo_path, &["rev-parse", "--abbrev-ref", "HEAD"]).await;

    let watch_refs: Vec<&str> = if git_spec.watch_paths.is_empty() {
        vec!["."]
    } else {
        git_spec.watch_paths.iter().map(|s| s.as_str()).collect()
    };

    // 1. Lấy commit mới nhất chạm vào watch_paths
    let mut head_args = vec!["log", "-1", "--format=%H|%h|%ct|%ci|%s", "--"];
    head_args.extend_from_slice(&watch_refs);
    let head_watch_commit = run_git(repo_path, &head_args)
        .await
        .and_then(|s| s.lines().next().and_then(parse_commit_line));

    // 2. Đếm số tệp đang sửa dở (chưa commit) trong watch_paths
    let mut status_args = vec!["status", "--porcelain", "--"];
    status_args.extend_from_slice(&watch_refs);
    let dirty_files_count = run_git(repo_path, &status_args)
        .await
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0);

    let Some(exe_mtime) = exe_mtime_secs else {
        return GitRepoReport {
            repo_exists: true,
            branch,
            head_watch_commit,
            dirty_files_count,
            drift_status: GitDriftStatus::NotInstalled,
            ahead_commits: Vec::new(),
        };
    };

    let Some(ref head_commit) = head_watch_commit else {
        return GitRepoReport {
            repo_exists: true,
            branch,
            head_watch_commit,
            dirty_files_count,
            drift_status: GitDriftStatus::InSync,
            ahead_commits: Vec::new(),
        };
    };

    // Tầng 1: Neo theo Tag phiên bản đang cài (chính xác tuyệt đối, triệt tiêu sai số mtime khi amend/CI)
    if let Some(inst_ver) = installed_version {
        let candidate_tag = format!("{}{}", git_spec.tag_prefix, inst_ver);
        let tag_ref = format!("refs/tags/{candidate_tag}^{{commit}}");
        if run_git(repo_path, &["rev-parse", "-q", "--verify", &tag_ref])
            .await
            .is_some()
        {
            let range = format!("{candidate_tag}..HEAD");
            let mut count_args = vec!["rev-list", "--count", &range, "--"];
            count_args.extend_from_slice(&watch_refs);
            if let Some(cnt_str) = run_git(repo_path, &count_args).await {
                if let Ok(cnt) = cnt_str.trim().parse::<usize>() {
                    if cnt == 0 {
                        return GitRepoReport {
                            repo_exists: true,
                            branch,
                            head_watch_commit,
                            dirty_files_count,
                            drift_status: GitDriftStatus::InSync,
                            ahead_commits: Vec::new(),
                        };
                    }

                    // Có commit mới hơn tag đang cài -> kiểm tra xem .exe đã được Hot-Swap sau commit đó chưa
                    if exe_mtime >= head_commit.timestamp_secs {
                        return GitRepoReport {
                            repo_exists: true,
                            branch,
                            head_watch_commit,
                            dirty_files_count,
                            drift_status: GitDriftStatus::HotSwappedAhead {
                                commits_since_tag: cnt,
                                base_tag: candidate_tag,
                            },
                            ahead_commits: Vec::new(),
                        };
                    }

                    let mut log_args =
                        vec!["log", &range, "-n", "10", "--format=%H|%h|%ct|%ci|%s", "--"];
                    log_args.extend_from_slice(&watch_refs);
                    let ahead_commits = run_git(repo_path, &log_args)
                        .await
                        .map(|out| out.lines().filter_map(parse_commit_line).collect())
                        .unwrap_or_default();

                    return GitRepoReport {
                        repo_exists: true,
                        branch,
                        head_watch_commit,
                        dirty_files_count,
                        drift_status: GitDriftStatus::SourceAhead {
                            commits_ahead: cnt,
                            comparison_basis: format!("Sau tag {candidate_tag}"),
                        },
                        ahead_commits,
                    };
                }
            }
        }
    }

    // Tầng 2: Dự phòng theo mốc thời gian phạm vi watch_paths (khi kho cục bộ chưa gắn tag)
    let same_as_remote = match (installed_version, remote_version) {
        (Some(iv), Some(rv)) => iv == rv,
        _ => false,
    };
    // Biên độ 180 giây cho sai lệch đóng gói / amend nhỏ khi cùng phiên bản phát hành
    let grace_secs = if same_as_remote { 180 } else { 2 };

    if head_commit.timestamp_secs > exe_mtime.saturating_add(grace_secs) {
        let since_arg = format!("--since=@{}", exe_mtime.saturating_add(1));
        let mut log_args = vec![
            "log",
            &since_arg,
            "-n",
            "10",
            "--format=%H|%h|%ct|%ci|%s",
            "--",
        ];
        log_args.extend_from_slice(&watch_refs);
        let ahead_commits: Vec<GitCommitSummary> = run_git(repo_path, &log_args)
            .await
            .map(|out| out.lines().filter_map(parse_commit_line).collect())
            .unwrap_or_default();

        let count = ahead_commits.len().max(1);
        return GitRepoReport {
            repo_exists: true,
            branch,
            head_watch_commit,
            dirty_files_count,
            drift_status: GitDriftStatus::SourceAhead {
                commits_ahead: count,
                comparison_basis: "Mốc thời gian tệp .exe".to_string(),
            },
            ahead_commits,
        };
    }

    GitRepoReport {
        repo_exists: true,
        branch,
        head_watch_commit,
        dirty_files_count,
        drift_status: GitDriftStatus::InSync,
        ahead_commits: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as StdCommand;
    use tempfile::tempdir;

    fn git_sync(dir: &Path, args: &[&str]) {
        let status = StdCommand::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .status()
            .expect("Phải chạy được lệnh git trong test");
        assert!(status.success(), "git {:?} thất bại", args);
    }

    #[tokio::test]
    async fn ignores_manuscript_commits_outside_watch_paths_and_detects_real_app_commits() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path();

        git_sync(repo, &["init", "-b", "main"]);
        git_sync(repo, &["config", "user.email", "studio@selorson.vn"]);
        git_sync(repo, &["config", "user.name", "Selorson Test"]);

        std::fs::create_dir_all(repo.join("app")).unwrap();
        std::fs::create_dir_all(repo.join("kho-cowriter")).unwrap();
        std::fs::write(repo.join("app/main.rs"), "fn main() {}").unwrap();
        std::fs::write(repo.join("kho-cowriter/chuong-05.md"), "Chương 5").unwrap();

        git_sync(repo, &["add", "."]);
        git_sync(repo, &["commit", "-m", "feat: khoi tao v1.0.0"]);
        git_sync(repo, &["tag", "v1.0.0"]);

        let spec = GitSpec {
            repo_path: repo.to_string_lossy().to_string(),
            watch_paths: vec!["app".to_string()],
            tag_prefix: "v".to_string(),
            hot_swap_hint: None,
        };

        // 1. Commit mới CHỈ sửa bản thảo truyện -> KHÔNG ĐƯỢC báo giả là .exe lỗi thời!
        std::fs::write(repo.join("kho-cowriter/chuong-06.md"), "Chương 6 mới").unwrap();
        git_sync(repo, &["add", "."]);
        git_sync(repo, &["commit", "-m", "docs: viet ban thao chuong 6"]);

        let report_manuscript = inspect_git_drift(&spec, Some("1.0.0"), Some(1000), Some("1.0.0")).await;
        assert_eq!(report_manuscript.drift_status, GitDriftStatus::InSync);

        // 2. Commit mới chạm vào thư mục app/ -> PHẢI phát hiện chính xác 1 commit mới hơn .exe!
        std::fs::write(repo.join("app/main.rs"), "fn main() { println!(\"v2\"); }").unwrap();
        git_sync(repo, &["add", "."]);
        git_sync(repo, &["commit", "-m", "feat(app): nang cap bo loc RAG"]);

        let report_ahead = inspect_git_drift(&spec, Some("1.0.0"), Some(1000), Some("1.0.0")).await;
        match report_ahead.drift_status {
            GitDriftStatus::SourceAhead { commits_ahead, .. } => assert_eq!(commits_ahead, 1),
            other => panic!("Kỳ vọng SourceAhead(1), nhận được: {:?}", other),
        }
        assert_eq!(report_ahead.ahead_commits.len(), 1);

        // 3. Nếu tác giả vừa Hot-Swap .exe sau commit đó (exe_mtime >= commit_ts) -> báo HotSwappedAhead!
        let future_mtime = report_ahead.head_watch_commit.unwrap().timestamp_secs + 10;
        let report_hotswap =
            inspect_git_drift(&spec, Some("1.0.0"), Some(future_mtime), Some("1.0.0")).await;
        match report_hotswap.drift_status {
            GitDriftStatus::HotSwappedAhead {
                commits_since_tag, ..
            } => assert_eq!(commits_since_tag, 1),
            other => panic!("Kỳ vọng HotSwappedAhead(1), nhận được: {:?}", other),
        }
    }
}
