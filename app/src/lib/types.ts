export interface OpenPortStatus {
	port: number;
	label: string;
	is_open: boolean;
	blocks_update: boolean;
}

export interface ImmutableFileStatus {
	path: string;
	exists: boolean;
	size_bytes: number;
}

export interface DiscoveredToolLocal {
	is_installed: boolean;
	active_exe_path: string | null;
	all_detected_exes: string[];
	installed_version: string | null;
	version_source: string | null;
	exe_mtime_secs: number | null;
	is_running: boolean;
	active_processes: string[];
	open_ports: OpenPortStatus[];
	immutable_guards: ImmutableFileStatus[];
	can_rollback: boolean;
	rollback_target_version: string | null;
}

export interface GitCommitSummary {
	short_sha: string;
	full_sha: string;
	timestamp_secs: number;
	date_iso: string;
	subject: string;
}

export type GitDriftStatus =
	| { kind: 'repo_missing' }
	| { kind: 'not_installed' }
	| { kind: 'in_sync' }
	| { kind: 'source_ahead'; commits_ahead: number; comparison_basis: string }
	| { kind: 'source_behind'; commits_behind: number; base_tag: string }
	| { kind: 'hot_swapped_ahead'; commits_since_tag: number; base_tag: string };

export interface GitRepoReport {
	repo_exists: boolean;
	branch: string | null;
	head_watch_commit: GitCommitSummary | null;
	dirty_files_count: number;
	drift_status: GitDriftStatus;
	ahead_commits: GitCommitSummary[];
}

export interface RemoteReleaseInfo {
	channel: string;
	raw_version: string;
	normalized_version: string;
	pub_date: string | null;
	notes: string | null;
	download_url: string;
	signature: string;
}

export type ReleaseComparisonState =
	| { state: 'not_installed' }
	| { state: 'update_available' }
	| { state: 'up_to_date' }
	| { state: 'local_newer_or_hot_swapped' }
	| { state: 'offline_or_error'; message: string };

export interface ChannelOptionDto {
	key: string;
	label: string;
	endpoint: string;
}

export interface ToolFullStatusDto {
	id: string;
	order: number;
	name: string;
	subtitle: string;
	category: string;
	accent_color: string;
	icon_path: string | null;
	icon_data_url: string | null;
	selected_channel: string;
	available_channels: ChannelOptionDto[];
	repo_path: string;
	watch_paths: string[];
	extra_repo_paths: string[];
	tag_prefix: string;
	hot_swap_hint: string | null;
	local: DiscoveredToolLocal;
	git: GitRepoReport;
	remote: RemoteReleaseInfo | null;
	remote_error: string | null;
	release_state: ReleaseComparisonState;
}

export interface LauncherSettings {
	close_to_tray: boolean;
	global_hotkey_enabled: boolean;
	selected_channels: Record<string, string>;
}

export interface EcosystemSnapshotDto {
	ecosystem_name: string;
	manifest_path: string;
	ecosystem_root: string;
	vault_root: string;
	shared_ports: OpenPortStatus[];
	settings: LauncherSettings;
	tools: ToolFullStatusDto[];
	checked_at_iso: string;
	active_install_tool_id: string | null;
}

export interface InstallProgressEvent {
	tool_id: string;
	tool_name: string;
	phase: string;
	percent: number | null;
	downloaded_bytes: number;
	total_bytes: number | null;
	message: string;
}

export interface VaultVerificationReport {
	restored_immutable_files: string[];
	verified_backup_files: string[];
	verified_external_paths: string[];
	snapshot_dir: string | null;
}

export interface InstallResultDto {
	tool_id: string;
	installed_version: string;
	active_exe_path: string | null;
	vault_report: VaultVerificationReport;
}

export interface ManifestValidationDto {
	valid: boolean;
	manifest_path: string;
	tool_count: number;
	message: string;
}
