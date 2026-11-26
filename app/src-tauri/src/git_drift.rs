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
    /// Kho cục bộ đang checkout lùi N commit về trước tag của bản .exe đang cài
    SourceBehind {
        commits_behind: usize,
        base_tag: String,
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
    cmd.env("GIT_OPTIONAL_LOCKS", "0");
    cmd.arg("--no-optional-locks")
        .arg("-C")
        .arg(repo_dir)
        .args(args);
    cmd.kill_on_drop(true);
    #[cfg(windows)]
    {
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let output = tokio::time::timeout(std::time::Duration::from_secs(5), cmd.output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn parse_commit_line(line: &str, repo_prefix: Option<&str>) -> Option<GitCommitSummary> {
    let mut parts = line.splitn(5, '|');
    let full_sha = parts.next()?.trim().to_string();
    let short_sha = parts.next()?.trim().to_string();
    let ts_str = parts.next()?.trim();
    let timestamp_secs: u64 = ts_str.parse().ok()?;
    let date_iso = parts.next()?.trim().to_string();
    let raw_subject = parts.next()?.trim().to_string();
    if full_sha.is_empty() {
        return None;
    }
    let subject = match repo_prefix {
        Some(pref) if !pref.is_empty() => format!("[{pref}] {raw_subject}"),
        _ => raw_subject,
    };
    Some(GitCommitSummary {
        short_sha,
        full_sha,
        timestamp_secs,
        date_iso,
        subject,
    })
}

async fn resolve_branch_label(repo_path: &Path) -> Option<String> {
    if let Some(symbolic) = run_git(repo_path, &["symbolic-ref", "-q", "--short", "HEAD"]).await {
        if !symbolic.is_empty() {
            return Some(symbolic);
        }
    }
    let short_sha = run_git(repo_path, &["rev-parse", "--short", "HEAD"]).await?;
    if short_sha.is_empty() {
        None
    } else {
        Some(format!("Detached HEAD @ {short_sha}"))
    }
}

async fn is_valid_git_worktree(repo_path: &Path) -> bool {
    repo_path.exists()
        && run_git(repo_path, &["rev-parse", "--is-inside-work-tree"])
            .await
            .is_some()
}

async fn latest_watch_commit(
    repo_path: &Path,
    watch_refs: &[&str],
    target_rev: &str,
    repo_prefix: Option<&str>,
) -> Option<GitCommitSummary> {
    let mut args = vec!["log", "-1", "--format=%H|%h|%ct|%ci|%s", target_rev, "--"];
    args.extend_from_slice(watch_refs);
    run_git(repo_path, &args)
        .await
        .and_then(|s| s.lines().next().and_then(|l| parse_commit_line(l, repo_prefix)))
}

async fn count_dirty_watch_files(repo_path: &Path, watch_refs: &[&str]) -> usize {
    let mut status_args = vec!["status", "--porcelain", "--"];
    status_args.extend_from_slice(watch_refs);
    run_git(repo_path, &status_args)
        .await
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
}

async fn count_commits_since_ts(repo_path: &Path, since_ts: u64, target_rev: &str, watch_refs: &[&str]) -> usize {
    let since_arg = format!("--since=@{since_ts}");
    let mut args = vec!["rev-list", "--count", &since_arg, target_rev, "--"];
    args.extend_from_slice(watch_refs);
    run_git(repo_path, &args)
        .await
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

async fn log_commits_since_ts(
    repo_path: &Path,
    since_ts: u64,
    target_rev: &str,
    watch_refs: &[&str],
    repo_prefix: Option<&str>,
) -> Vec<GitCommitSummary> {
    let since_arg = format!("--since=@{since_ts}");
    let mut args = vec![
        "log",
        &since_arg,
        "-n",
        "10",
        "--format=%H|%h|%ct|%ci|%s",
        target_rev,
        "--",
    ];
    args.extend_from_slice(watch_refs);
    run_git(repo_path, &args)
        .await
        .map(|out| {
            out.lines()
                .filter_map(|l| parse_commit_line(l, repo_prefix))
                .collect()
        })
        .unwrap_or_default()
}

fn merge_and_trim_commits(mut list: Vec<GitCommitSummary>) -> Vec<GitCommitSummary> {
    list.sort_by(|a, b| b.timestamp_secs.cmp(&a.timestamp_secs));
    list.truncate(10);
    list
}

pub async fn inspect_git_drift(
    git_spec: &GitSpec,
    installed_version: Option<&str>,
    exe_mtime_secs: Option<u64>,
    is_verified_ledger_install: bool,
) -> GitRepoReport {
    let repo_path = Path::new(&git_spec.repo_path);
    if !is_valid_git_worktree(repo_path).await {
        return GitRepoReport {
            repo_exists: false,
            branch: None,
            head_watch_commit: None,
            dirty_files_count: 0,
            drift_status: GitDriftStatus::RepoMissing,
            ahead_commits: Vec::new(),
        };
    }

    let branch = resolve_branch_label(repo_path).await;

    let watch_refs: Vec<&str> = if git_spec.watch_paths.is_empty() {
        vec!["."]
    } else {
        git_spec.watch_paths.iter().map(|s| s.as_str()).collect()
    };

    let mut head_watch_commit = latest_watch_commit(repo_path, &watch_refs, "HEAD", None).await;
    let mut dirty_files_count = count_dirty_watch_files(repo_path, &watch_refs).await;

    // Thu thập thông tin các kho phụ (VD: Selorson\backend-v3 nhúng trực tiếp vào Selorson Admin)
    struct ActiveExtraRepo<'a> {
        path: &'a Path,
        label: String,
        watch_refs: Vec<&'a str>,
        tag_prefix: &'a str,
    }
    let mut active_extras: Vec<ActiveExtraRepo<'_>> = Vec::new();
    for er in &git_spec.extra_repos {
        let ep = Path::new(&er.repo_path);
        if is_valid_git_worktree(ep).await {
            let label = ep
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("extra")
                .to_string();
            let ew_refs: Vec<&str> = if er.watch_paths.is_empty() {
                vec!["."]
            } else {
                er.watch_paths.iter().map(|s| s.as_str()).collect()
            };
            dirty_files_count += count_dirty_watch_files(ep, &ew_refs).await;
            if let Some(ec) = latest_watch_commit(ep, &ew_refs, "HEAD", Some(&label)).await {
                if head_watch_commit
                    .as_ref()
                    .is_none_or(|cur| ec.timestamp_secs > cur.timestamp_secs)
                {
                    head_watch_commit = Some(ec);
                }
            }
            active_extras.push(ActiveExtraRepo {
                path: ep,
                label,
                watch_refs: ew_refs,
                tag_prefix: er.tag_prefix.as_deref().unwrap_or(&git_spec.tag_prefix),
            });
        }
    }

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

    // Tầng 1: Neo theo Tag phiên bản đang cài
    if let Some(inst_ver) = installed_version {
        let candidate_tag = format!("{}{}", git_spec.tag_prefix, inst_ver);
        let tag_ref = format!("refs/tags/{candidate_tag}^{{commit}}");
        if run_git(repo_path, &["rev-parse", "-q", "--verify", &tag_ref])
            .await
            .is_some()
        {
            let tag_commit_ts: Option<u64> =
                run_git(repo_path, &["log", "-1", "--format=%ct", &tag_ref])
                    .await
                    .and_then(|s| s.trim().parse::<u64>().ok());
            let tag_watch_commit =
                latest_watch_commit(repo_path, &watch_refs, &candidate_tag, None).await;

            let ahead_range = format!("{candidate_tag}..HEAD");
            let mut count_args = vec!["rev-list", "--count", &ahead_range, "--"];
            count_args.extend_from_slice(&watch_refs);

            let behind_range = format!("HEAD..{candidate_tag}");
            let mut behind_args = vec!["rev-list", "--count", &behind_range, "--"];
            behind_args.extend_from_slice(&watch_refs);
            let behind_cnt = run_git(repo_path, &behind_args)
                .await
                .and_then(|s| s.trim().parse::<usize>().ok())
                .unwrap_or(0);

            if let Some(main_ahead_cnt) = run_git(repo_path, &count_args)
                .await
                .and_then(|s| s.trim().parse::<usize>().ok())
            {
                let mut total_ahead = main_ahead_cnt;
                let mut combined_commits: Vec<GitCommitSummary> = Vec::new();

                if main_ahead_cnt > 0 {
                    let mut log_args = vec![
                        "log",
                        &ahead_range,
                        "-n",
                        "10",
                        "--format=%H|%h|%ct|%ci|%s",
                        "--",
                    ];
                    log_args.extend_from_slice(&watch_refs);
                    if let Some(out) = run_git(repo_path, &log_args).await {
                        combined_commits.extend(
                            out.lines()
                                .filter_map(|l| parse_commit_line(l, None)),
                        );
                    }
                }

                // Kiểm tra thêm các kho phụ (extra_repos) so với tag tương ứng hoặc mốc thời gian đóng tag chính
                for extra in &active_extras {
                    let extra_tag = format!("{}{}", extra.tag_prefix, inst_ver);
                    let extra_tag_ref = format!("refs/tags/{extra_tag}^{{commit}}");
                    if run_git(extra.path, &["rev-parse", "-q", "--verify", &extra_tag_ref])
                        .await
                        .is_some()
                    {
                        let erange = format!("{extra_tag}..HEAD");
                        let mut ec_args = vec!["rev-list", "--count", &erange, "--"];
                        ec_args.extend_from_slice(&extra.watch_refs);
                        let ecnt = run_git(extra.path, &ec_args)
                            .await
                            .and_then(|s| s.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if ecnt > 0 {
                            total_ahead += ecnt;
                            let mut el_args = vec![
                                "log",
                                &erange,
                                "-n",
                                "10",
                                "--format=%H|%h|%ct|%ci|%s",
                                "--",
                            ];
                            el_args.extend_from_slice(&extra.watch_refs);
                            if let Some(out) = run_git(extra.path, &el_args).await {
                                combined_commits.extend(
                                    out.lines()
                                        .filter_map(|l| parse_commit_line(l, Some(&extra.label))),
                                );
                            }
                        }
                    } else {
                        // Kho phụ không gắn chung tag -> đối chiếu theo mốc thời gian đóng tag chính (hoặc exe_mtime nếu Hot-Swap)
                        let anchor = if is_verified_ledger_install {
                            tag_commit_ts
                                .unwrap_or(exe_mtime)
                                .saturating_add(180)
                        } else {
                            tag_commit_ts
                                .map(|ts| ts.max(exe_mtime))
                                .unwrap_or(exe_mtime)
                                .saturating_add(2)
                        };
                        let ecnt = count_commits_since_ts(
                            extra.path,
                            anchor.saturating_add(1),
                            "HEAD",
                            &extra.watch_refs,
                        )
                        .await;
                        if ecnt > 0 {
                            total_ahead += ecnt;
                            combined_commits.extend(
                                log_commits_since_ts(
                                    extra.path,
                                    anchor.saturating_add(1),
                                    "HEAD",
                                    &extra.watch_refs,
                                    Some(&extra.label),
                                )
                                .await,
                            );
                        }
                    }
                }

                if total_ahead > 0 {
                    // CHỈ báo HotSwappedAhead khi tệp .exe KHÔNG phải bản cài NSIS chính thức trong Ledger
                    // VÀ được biên dịch sau commit ứng dụng mới nhất!
                    if !is_verified_ledger_install && exe_mtime >= head_commit.timestamp_secs {
                        return GitRepoReport {
                            repo_exists: true,
                            branch,
                            head_watch_commit,
                            dirty_files_count,
                            drift_status: GitDriftStatus::HotSwappedAhead {
                                commits_since_tag: total_ahead,
                                base_tag: candidate_tag,
                            },
                            ahead_commits: Vec::new(),
                        };
                    }

                    let basis = if behind_cnt > 0 {
                        format!("Nhánh phân kỳ (+{total_ahead}/-{behind_cnt} so với {candidate_tag})")
                    } else {
                        format!("Sau tag {candidate_tag}")
                    };

                    return GitRepoReport {
                        repo_exists: true,
                        branch,
                        head_watch_commit,
                        dirty_files_count,
                        drift_status: GitDriftStatus::SourceAhead {
                            commits_ahead: total_ahead,
                            comparison_basis: basis,
                        },
                        ahead_commits: merge_and_trim_commits(combined_commits),
                    };
                }

                // total_ahead == 0: Kiểm tra trường hợp .exe cục bộ (ngoài Ledger) được build TRƯỚC thời điểm đóng chính tag đó (VD: ToneForge_Studio.exe cũ mang PE 0.1.0)
                if !is_verified_ledger_install {
                    if let Some(ref twc) = tag_watch_commit {
                        if exe_mtime.saturating_add(60) < twc.timestamp_secs {
                            let pre_cnt = count_commits_since_ts(
                                repo_path,
                                exe_mtime.saturating_add(1),
                                &candidate_tag,
                                &watch_refs,
                            )
                            .await
                            .max(1);
                            let pre_commits = log_commits_since_ts(
                                repo_path,
                                exe_mtime.saturating_add(1),
                                &candidate_tag,
                                &watch_refs,
                                None,
                            )
                            .await;

                            return GitRepoReport {
                                repo_exists: true,
                                branch,
                                head_watch_commit,
                                dirty_files_count,
                                drift_status: GitDriftStatus::SourceAhead {
                                    commits_ahead: pre_cnt,
                                    comparison_basis: format!(
                                        "Tệp .exe biên dịch trước tag {candidate_tag}"
                                    ),
                                },
                                ahead_commits: pre_commits,
                            };
                        }
                    }
                }

                if behind_cnt > 0 {
                    return GitRepoReport {
                        repo_exists: true,
                        branch,
                        head_watch_commit,
                        dirty_files_count,
                        drift_status: GitDriftStatus::SourceBehind {
                            commits_behind: behind_cnt,
                            base_tag: candidate_tag,
                        },
                        ahead_commits: Vec::new(),
                    };
                }

                return GitRepoReport {
                    repo_exists: true,
                    branch,
                    head_watch_commit,
                    dirty_files_count,
                    drift_status: GitDriftStatus::InSync,
                    ahead_commits: Vec::new(),
                };
            }
        }
    }

    // Tầng 2: Dự phòng theo mốc thời gian phạm vi watch_paths (ổn định theo Ledger, không phụ thuộc trạng thái mạng!)
    let grace_secs = if is_verified_ledger_install { 180 } else { 2 };
    let cutoff = exe_mtime.saturating_add(grace_secs);

    if head_commit.timestamp_secs > cutoff {
        let since_ts = cutoff.saturating_add(1);
        let mut total_count = count_commits_since_ts(repo_path, since_ts, "HEAD", &watch_refs).await;
        let mut combined =
            log_commits_since_ts(repo_path, since_ts, "HEAD", &watch_refs, None).await;

        for extra in &active_extras {
            let ecnt =
                count_commits_since_ts(extra.path, since_ts, "HEAD", &extra.watch_refs).await;
            if ecnt > 0 {
                total_count += ecnt;
                combined.extend(
                    log_commits_since_ts(
                        extra.path,
                        since_ts,
                        "HEAD",
                        &extra.watch_refs,
                        Some(&extra.label),
                    )
                    .await,
                );
            }
        }

        return GitRepoReport {
            repo_exists: true,
            branch,
            head_watch_commit,
            dirty_files_count,
            drift_status: GitDriftStatus::SourceAhead {
                commits_ahead: total_count.max(1),
                comparison_basis: "Mốc thời gian tệp .exe".to_string(),
            },
            ahead_commits: merge_and_trim_commits(combined),
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
            extra_repos: Vec::new(),
            tag_prefix: "v".to_string(),
            hot_swap_hint: None,
        };

        // 1. Commit mới CHỈ sửa bản thảo truyện -> KHÔNG ĐƯỢC báo giả là .exe lỗi thời!
        std::fs::write(repo.join("kho-cowriter/chuong-06.md"), "Chương 6 mới").unwrap();
        git_sync(repo, &["add", "."]);
        git_sync(repo, &["commit", "-m", "docs: viet ban thao chuong 6"]);

        let report_manuscript = inspect_git_drift(&spec, Some("1.0.0"), Some(1000), true).await;
        assert_eq!(report_manuscript.drift_status, GitDriftStatus::InSync);

        // 2. Commit mới chạm vào thư mục app/ -> PHẢI phát hiện chính xác 1 commit mới hơn .exe!
        std::fs::write(repo.join("app/main.rs"), "fn main() { println!(\"v2\"); }").unwrap();
        git_sync(repo, &["add", "."]);
        git_sync(repo, &["commit", "-m", "feat(app): nang cap bo loc RAG"]);

        let report_ahead = inspect_git_drift(&spec, Some("1.0.0"), Some(1000), true).await;
        match report_ahead.drift_status {
            GitDriftStatus::SourceAhead { commits_ahead, .. } => assert_eq!(commits_ahead, 1),
            other => panic!("Kỳ vọng SourceAhead(1), nhận được: {:?}", other),
        }
        assert_eq!(report_ahead.ahead_commits.len(), 1);

        // 3. Nếu tác giả vừa Hot-Swap .exe cục bộ (is_verified_ledger_install = false, exe_mtime >= commit_ts) -> báo HotSwappedAhead!
        let future_mtime = report_ahead.head_watch_commit.unwrap().timestamp_secs + 10;
        let report_hotswap =
            inspect_git_drift(&spec, Some("1.0.0"), Some(future_mtime), false).await;
        match report_hotswap.drift_status {
            GitDriftStatus::HotSwappedAhead {
                commits_since_tag, ..
            } => assert_eq!(commits_since_tag, 1),
            other => panic!("Kỳ vọng HotSwappedAhead(1), nhận được: {:?}", other),
        }

        // 4. Nhưng nếu tệp .exe là bản cài NSIS chính thức trong Ledger (is_verified_ledger_install = true) -> vẫn báo SourceAhead, KHÔNG báo giả HotSwappedAhead!
        let report_official_reinstall =
            inspect_git_drift(&spec, Some("1.0.0"), Some(future_mtime), true).await;
        match report_official_reinstall.drift_status {
            GitDriftStatus::SourceAhead { commits_ahead, .. } => assert_eq!(commits_ahead, 1),
            other => panic!(
                "Bản cài chính thức trong Ledger không được báo giả HotSwappedAhead, nhận được: {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn detects_pre_tag_stale_exe_detached_head_source_behind_and_extra_repos() {
        use crate::manifest::ExtraGitRepoSpec;

        let tmp = tempdir().unwrap();
        let main_repo = tmp.path().join("frontend-v3");
        let extra_repo = tmp.path().join("backend-v3");
        std::fs::create_dir_all(main_repo.join("src")).unwrap();
        std::fs::create_dir_all(extra_repo.join("src")).unwrap();

        for r in [&main_repo, &extra_repo] {
            git_sync(r, &["init", "-b", "main"]);
            git_sync(r, &["config", "user.email", "studio@selorson.vn"]);
            git_sync(r, &["config", "user.name", "Selorson Test"]);
        }

        // Commit gốc (timestamp = 1_700_000_000) và commit đóng tag (timestamp = 1_700_010_000)
        std::fs::write(main_repo.join("src/app.ts"), "export const v = 1;").unwrap();
        git_sync(&main_repo, &["add", "."]);
        let status = StdCommand::new("git")
            .arg("-C")
            .arg(&main_repo)
            .args(["commit", "-m", "feat: initial"])
            .env("GIT_COMMITTER_DATE", "@1700000000 +0000")
            .env("GIT_AUTHOR_DATE", "@1700000000 +0000")
            .status()
            .unwrap();
        assert!(status.success());

        std::fs::write(main_repo.join("src/app.ts"), "export const v = 2;").unwrap();
        git_sync(&main_repo, &["add", "."]);
        let status2 = StdCommand::new("git")
            .arg("-C")
            .arg(&main_repo)
            .args(["commit", "-m", "feat: final fix before v0.1.0 tag"])
            .env("GIT_COMMITTER_DATE", "@1700010000 +0000")
            .env("GIT_AUTHOR_DATE", "@1700010000 +0000")
            .status()
            .unwrap();
        assert!(status2.success());
        git_sync(&main_repo, &["tag", "desktop-admin-v0.1.0"]);

        std::fs::write(extra_repo.join("src/lib.rs"), "pub fn api_v1() {}").unwrap();
        git_sync(&extra_repo, &["add", "."]);
        let status_ex1 = StdCommand::new("git")
            .arg("-C")
            .arg(&extra_repo)
            .args(["commit", "-m", "feat(backend): init"])
            .env("GIT_COMMITTER_DATE", "@1700005000 +0000")
            .env("GIT_AUTHOR_DATE", "@1700005000 +0000")
            .status()
            .unwrap();
        assert!(status_ex1.success());

        let spec = GitSpec {
            repo_path: main_repo.to_string_lossy().to_string(),
            watch_paths: vec!["src".to_string()],
            extra_repos: vec![ExtraGitRepoSpec {
                repo_path: extra_repo.to_string_lossy().to_string(),
                watch_paths: vec!["src".to_string()],
                tag_prefix: None,
            }],
            tag_prefix: "desktop-admin-v".to_string(),
            hot_swap_hint: None,
        };

        // 1. Tệp .exe cục bộ build tại ts=1_700_000_500 (trước khi đóng tag v0.1.0 ở 1_700_010_000) -> PHẢI báo SourceAhead!
        let stale_pre_tag =
            inspect_git_drift(&spec, Some("0.1.0"), Some(1_700_000_500), false).await;
        match stale_pre_tag.drift_status {
            GitDriftStatus::SourceAhead { commits_ahead, .. } => assert_eq!(commits_ahead, 1),
            other => panic!("Kỳ vọng phát hiện .exe cũ trước tag, nhận được: {:?}", other),
        }

        // 2. Commit mới trong kho phụ backend-v3 (ts=1_700_020_000 > tag_ts + 180) -> PHẢI phát hiện qua extra_repos!
        std::fs::write(extra_repo.join("src/lib.rs"), "pub fn api_v2() {}").unwrap();
        git_sync(&extra_repo, &["add", "."]);
        let status_ex2 = StdCommand::new("git")
            .arg("-C")
            .arg(&extra_repo)
            .args(["commit", "-m", "feat(backend): add alpha publish endpoint"])
            .env("GIT_COMMITTER_DATE", "@1700020000 +0000")
            .env("GIT_AUTHOR_DATE", "@1700020000 +0000")
            .status()
            .unwrap();
        assert!(status_ex2.success());

        let extra_ahead = inspect_git_drift(&spec, Some("0.1.0"), Some(1_700_010_050), true).await;
        match extra_ahead.drift_status {
            GitDriftStatus::SourceAhead { commits_ahead, .. } => assert_eq!(commits_ahead, 1),
            other => panic!("Phải phát hiện commit mới bên kho backend-v3, nhận được: {:?}", other),
        }
        assert!(extra_ahead.ahead_commits[0].subject.starts_with("[backend-v3]"));

        // 3. Checkout Detached HEAD lùi về HEAD~1 trên main_repo (với spec không kèm extra_repo để test riêng SourceBehind & Detached HEAD)
        let single_spec = GitSpec {
            extra_repos: vec![],
            ..spec
        };
        git_sync(&main_repo, &["checkout", "--detach", "HEAD~1"]);
        let behind_rep =
            inspect_git_drift(&single_spec, Some("0.1.0"), Some(1_700_010_050), true).await;
        assert!(
            behind_rep
                .branch
                .as_deref()
                .is_some_and(|b| b.starts_with("Detached HEAD @ ")),
            "Detached HEAD phải hiển thị rõ kèm short SHA: {:?}",
            behind_rep.branch
        );
        assert_eq!(
            behind_rep.drift_status,
            GitDriftStatus::SourceBehind {
                commits_behind: 1,
                base_tag: "desktop-admin-v0.1.0".to_string(),
            }
        );
    }
}
