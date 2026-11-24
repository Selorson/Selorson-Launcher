<script lang="ts">
	import { onMount } from 'svelte';
	import {
		getEcosystemSnapshot,
		installOrUpdateTool,
		launchTool,
		onInstallProgress,
		onManifestReloaded,
		openFilesystemPath,
		setToolChannel,
		updateLauncherSettings,
		validateManifestNow
	} from '$lib/api';
	import GitDriftDrawer from '$lib/components/GitDriftDrawer.svelte';
	import ManifestInspector from '$lib/components/ManifestInspector.svelte';
	import SettingsModal from '$lib/components/SettingsModal.svelte';
	import ToolCard from '$lib/components/ToolCard.svelte';
	import UpdateProgressModal from '$lib/components/UpdateProgressModal.svelte';
	import type {
		EcosystemSnapshotDto,
		InstallProgressEvent,
		InstallResultDto,
		ManifestValidationDto,
		ToolFullStatusDto
	} from '$lib/types';

	type FilterMode = 'all' | 'updates' | 'drift' | 'running';

	let snapshot = $state<EcosystemSnapshotDto | null>(null);
	let loading = $state(true);
	let refreshing = $state(false);
	let toastMessage = $state<{ text: string; kind: 'ok' | 'err' } | null>(null);

	let searchQuery = $state('');
	let filterMode = $state<FilterMode>('all');

	// Ngăn kéo & hộp thoại
	let activeGitToolId = $state<string | null>(null);
	let releaseNotesTool = $state<ToolFullStatusDto | null>(null);
	let showManifestModal = $state(false);
	let manifestValidation = $state<ManifestValidationDto | null>(null);
	let showSettingsModal = $state(false);

	// Trạng thái cài đặt / nâng cấp
	let busyToolId = $state<string | null>(null);
	let showProgressModal = $state(false);
	let currentProgress = $state<InstallProgressEvent | null>(null);
	let progressLogs = $state<string[]>([]);
	let lastInstallResult = $state<InstallResultDto | null>(null);
	let installError = $state<string | null>(null);

	const activeGitTool = $derived(
		snapshot?.tools.find((t) => t.id === activeGitToolId) ?? null
	);

	const installedCount = $derived(
		snapshot?.tools.filter((t) => t.local.is_installed).length ?? 0
	);

	const updatableTools = $derived(
		snapshot?.tools.filter(
			(t) =>
				t.release_state.state === 'update_available' &&
				!t.local.is_running &&
				t.git.drift_status.kind !== 'hot_swapped_ahead'
		) ?? []
	);

	const updateAvailableCount = $derived(
		snapshot?.tools.filter((t) => t.release_state.state === 'update_available').length ?? 0
	);

	const sourceAheadCount = $derived(
		snapshot?.tools.filter((t) => t.git.drift_status.kind === 'source_ahead').length ?? 0
	);

	const runningCount = $derived(
		snapshot?.tools.filter((t) => t.local.is_running).length ?? 0
	);

	const filteredTools = $derived.by(() => {
		if (!snapshot) return [];
		const q = searchQuery.trim().toLowerCase();
		return snapshot.tools.filter((t) => {
			if (filterMode === 'updates' && t.release_state.state !== 'update_available') return false;
			if (filterMode === 'drift' && t.git.drift_status.kind !== 'source_ahead') return false;
			if (filterMode === 'running' && !t.local.is_running) return false;
			if (!q) return true;
			return (
				t.name.toLowerCase().includes(q) ||
				t.subtitle.toLowerCase().includes(q) ||
				t.category.toLowerCase().includes(q) ||
				t.id.toLowerCase().includes(q)
			);
		});
	});

	function showToast(text: string, kind: 'ok' | 'err' = 'ok') {
		toastMessage = { text, kind };
		setTimeout(() => {
			if (toastMessage?.text === text) toastMessage = null;
		}, 3600);
	}

	async function loadSnapshot(forceRemote = false) {
		try {
			if (snapshot) refreshing = true;
			else loading = true;
			snapshot = await getEcosystemSnapshot(forceRemote);
		} catch (e) {
			showToast(String(e), 'err');
		} finally {
			loading = false;
			refreshing = false;
		}
	}

	async function handleLaunch(tool: ToolFullStatusDto) {
		try {
			await launchTool(tool.id);
			showToast(`Đã khởi chạy ${tool.name}`);
			setTimeout(() => loadSnapshot(false), 1400);
		} catch (e) {
			showToast(String(e), 'err');
		}
	}

	async function handleInstallOrUpdate(tool: ToolFullStatusDto) {
		busyToolId = tool.id;
		showProgressModal = true;
		lastInstallResult = null;
		installError = null;
		progressLogs = [`[${new Date().toLocaleTimeString('vi-VN')}] Bắt đầu giao dịch cho ${tool.name}...`];
		currentProgress = {
			tool_id: tool.id,
			tool_name: tool.name,
			phase: 'starting',
			percent: 2,
			downloaded_bytes: 0,
			total_bytes: null,
			message: `Đang khởi tạo bảo hộ cho ${tool.name}...`
		};

		try {
			const res = await installOrUpdateTool(tool.id);
			lastInstallResult = res;
			await loadSnapshot(false);
		} catch (e) {
			installError = String(e);
			progressLogs = [...progressLogs, `❌ Lỗi: ${String(e)}`];
		} finally {
			busyToolId = null;
		}
	}

	async function handleBatchUpdateIdleTools() {
		if (updatableTools.length === 0 || busyToolId) return;
		const queue = [...updatableTools];
		showProgressModal = true;
		lastInstallResult = null;
		installError = null;
		progressLogs = [
			`[${new Date().toLocaleTimeString('vi-VN')}] Bắt đầu nâng cấp tuần tự ${queue.length} công cụ đang rảnh...`
		];

		for (const tool of queue) {
			busyToolId = tool.id;
			try {
				const res = await installOrUpdateTool(tool.id);
				lastInstallResult = res;
				progressLogs = [
					...progressLogs,
					`✓ Hoàn tất ${tool.name} -> v${res.installed_version}`
				];
			} catch (e) {
				installError = `${tool.name}: ${String(e)}`;
				progressLogs = [...progressLogs, `❌ Dừng tại ${tool.name}: ${String(e)}`];
				break;
			}
		}

		busyToolId = null;
		await loadSnapshot(false);
	}

	async function handleChangeChannel(toolId: string, channel: string) {
		try {
			await setToolChannel(toolId, channel);
			await loadSnapshot(true);
			showToast('Đã chuyển kênh phát hành và cập nhật thông tin mới nhất.');
		} catch (e) {
			showToast(String(e), 'err');
		}
	}

	async function handleSaveSettings(closeToTray: boolean, hotkeyEnabled: boolean) {
		try {
			const updated = await updateLauncherSettings(closeToTray, hotkeyEnabled);
			if (snapshot) {
				snapshot.settings = updated;
			}
			showSettingsModal = false;
			showToast('Đã lưu cài đặt Selorson Launcher.');
		} catch (e) {
			showToast(String(e), 'err');
		}
	}

	async function handleOpenPath(path: string) {
		try {
			await openFilesystemPath(path);
		} catch (e) {
			showToast(String(e), 'err');
		}
	}

	async function handleValidateManifest() {
		manifestValidation = await validateManifestNow();
		await loadSnapshot(true);
	}

	function handleKeydown(e: KeyboardEvent) {
		const target = e.target as HTMLElement | null;
		if (
			target &&
			(target.tagName === 'INPUT' ||
				target.tagName === 'TEXTAREA' ||
				target.tagName === 'SELECT')
		) {
			return;
		}
		if (showProgressModal || showManifestModal || showSettingsModal || activeGitToolId || releaseNotesTool) {
			if (e.key === 'Escape') {
				activeGitToolId = null;
				releaseNotesTool = null;
				showManifestModal = false;
				showSettingsModal = false;
			}
			return;
		}
		if (!e.ctrlKey && !e.altKey && !e.metaKey && e.key >= '1' && e.key <= '9') {
			const ord = Number(e.key);
			const found = snapshot?.tools.find((t) => t.order === ord && t.local.is_installed);
			if (found) {
				e.preventDefault();
				handleLaunch(found);
			}
		}
	}

	onMount(() => {
		loadSnapshot(true);

		let unlistenProgress: (() => void) | null = null;
		let unlistenManifest: (() => void) | null = null;

		onInstallProgress((evt) => {
			currentProgress = evt;
			if (evt.phase !== 'downloading' || progressLogs.length === 0) {
				const stamp = new Date().toLocaleTimeString('vi-VN');
				const last = progressLogs[progressLogs.length - 1] ?? '';
				if (!last.includes(evt.message)) {
					progressLogs = [...progressLogs, `[${stamp}] ${evt.message}`];
				}
			}
		}).then((fn) => (unlistenProgress = fn));

		onManifestReloaded(() => {
			showToast('Phát hiện thay đổi trong ecosystem-manifest.json — Đã tự động nạp nóng!');
			loadSnapshot(true);
		}).then((fn) => (unlistenManifest = fn));

		const focusRefresh = () => {
			if (!busyToolId) loadSnapshot(false);
		};
		window.addEventListener('focus', focusRefresh);

		return () => {
			unlistenProgress?.();
			unlistenManifest?.();
			window.removeEventListener('focus', focusRefresh);
		};
	});
</script>

<svelte:window onkeydown={handleKeydown} />

<div
	class="min-h-screen bg-[radial-gradient(ellipse_at_top,_rgba(20,184,166,0.11),_transparent_55%),#0B1416] text-slate-100"
>
	<!-- Thanh điều phối trung tâm -->
	<header class="sticky top-0 z-30 border-b border-white/[0.08] bg-[#0B1416]/90 backdrop-blur-md">
		<div class="mx-auto flex max-w-[1400px] flex-wrap items-center justify-between gap-3 px-5 py-3">
			<div class="flex items-center gap-3.5">
				<img
					src="/favicon.png"
					alt="Selorson Launcher"
					class="h-11 w-11 rounded-xl shadow-md"
				/>
				<div>
					<div class="flex items-center gap-2.5">
						<h1 class="font-display text-xl font-bold tracking-tight text-white">
							Selorson Launcher
						</h1>
						<span
							class="rounded-full border border-teal-400/30 bg-teal-500/12 px-2.5 py-0.5 text-[11px] font-semibold text-teal-300 tabular-nums"
						>
							{installedCount}/{snapshot?.tools.length ?? 7} sẵn sàng
						</span>
					</div>
					<p class="mt-0.5 text-xs text-slate-400">
						Trung tâm khởi chạy 1 chạm, cập nhật ký số Ed25519 bảo hộ DB/sidecar & đối chiếu mã nguồn
					</p>
				</div>
			</div>

			<!-- Đèn trạng thái GPU / ComfyUI dùng chung + Cụm nút hệ thống -->
			<div class="flex flex-wrap items-center gap-2">
				{#if snapshot}
					{#each snapshot.shared_ports as sp (sp.port)}
						<span
							class="inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium {sp.is_open
								? 'border-amber-400/35 bg-amber-500/12 text-amber-200'
								: 'border-white/[0.07] bg-white/[0.03] text-slate-400'}"
							title={sp.is_open
								? 'Đang bật và sử dụng tài nguyên GPU'
								: 'Đang nghỉ (0 MB VRAM)'}
						>
							<span
								class="h-2 w-2 rounded-full {sp.is_open ? 'bg-amber-400 animate-pulse' : 'bg-slate-600'}"
							></span>
							{sp.label}
						</span>
					{/each}
				{/if}

				{#if updatableTools.length > 0}
					<button
						type="button"
						disabled={busyToolId !== null}
						onclick={handleBatchUpdateIdleTools}
						class="rounded-xl bg-amber-400 px-3.5 py-2 text-xs font-bold text-slate-950 shadow transition hover:bg-amber-300 disabled:opacity-50"
					>
						🚀 Cập nhật tất cả rảnh ({updatableTools.length})
					</button>
				{/if}

				<button
					type="button"
					disabled={refreshing || busyToolId !== null}
					onclick={() => loadSnapshot(true)}
					class="rounded-xl border border-white/12 bg-white/[0.05] px-3 py-2 text-xs font-semibold text-slate-200 transition hover:bg-white/[0.1] disabled:opacity-50"
				>
					{refreshing ? '⟳ Đang quét...' : '🔄 Làm mới'}
				</button>

				<button
					type="button"
					onclick={() => {
						manifestValidation = null;
						showManifestModal = true;
					}}
					class="rounded-xl border border-white/12 bg-white/[0.05] px-3 py-2 text-xs font-semibold text-slate-200 transition hover:bg-white/[0.1]"
				>
					📄 Manifest
				</button>

				<button
					type="button"
					onclick={() => (showSettingsModal = true)}
					class="rounded-xl border border-white/12 bg-white/[0.05] px-3 py-2 text-xs font-semibold text-slate-200 transition hover:bg-white/[0.1]"
				>
					⚙️ Cài đặt
				</button>
			</div>
		</div>

		<!-- Thanh lọc nhanh & Tìm kiếm -->
		<div class="mx-auto flex max-w-[1400px] flex-wrap items-center justify-between gap-3 border-t border-white/[0.05] px-5 py-2">
			<div class="flex flex-wrap items-center gap-1.5 text-xs">
				<button
					type="button"
					onclick={() => (filterMode = 'all')}
					class="rounded-lg px-3 py-1.5 font-semibold transition {filterMode === 'all'
						? 'bg-teal-500/20 text-teal-200 border border-teal-400/35'
						: 'text-slate-400 hover:text-white'}"
				>
					Tất cả ({snapshot?.tools.length ?? 0})
				</button>
				<button
					type="button"
					onclick={() => (filterMode = 'updates')}
					class="rounded-lg px-3 py-1.5 font-semibold transition {filterMode === 'updates'
						? 'bg-amber-500/20 text-amber-200 border border-amber-400/35'
						: 'text-slate-400 hover:text-white'}"
				>
					Có bản mới ({updateAvailableCount})
				</button>
				<button
					type="button"
					onclick={() => (filterMode = 'drift')}
					class="rounded-lg px-3 py-1.5 font-semibold transition {filterMode === 'drift'
						? 'bg-amber-500/20 text-amber-200 border border-amber-400/35'
						: 'text-slate-400 hover:text-white'}"
				>
					Code mới hơn .exe ({sourceAheadCount})
				</button>
				<button
					type="button"
					onclick={() => (filterMode = 'running')}
					class="rounded-lg px-3 py-1.5 font-semibold transition {filterMode === 'running'
						? 'bg-emerald-500/20 text-emerald-200 border border-emerald-400/35'
						: 'text-slate-400 hover:text-white'}"
				>
					Đang chạy ({runningCount})
				</button>
			</div>

			<div class="flex items-center gap-3">
				<input
					type="search"
					bind:value={searchQuery}
					placeholder="Tìm công cụ hoặc vai trò... (Phím 1–7 mở nhanh)"
					class="w-80 rounded-xl border border-white/10 bg-[#081012] px-3.5 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 outline-none focus:border-teal-400"
				/>
				{#if snapshot}
					<span class="hidden text-[11px] text-slate-500 lg:inline tabular-nums">
						Quét lúc {snapshot.checked_at_iso}
					</span>
				{/if}
			</div>
		</div>
	</header>

	<!-- Lưới thẻ công cụ động -->
	<main class="mx-auto max-w-[1400px] px-5 py-4">
		{#if loading && !snapshot}
			<div class="grid grid-cols-1 gap-3.5 md:grid-cols-2 xl:grid-cols-3">
				{#each Array(6) as _, idx (idx)}
					<div class="h-48 animate-pulse rounded-2xl border border-white/[0.06] bg-[#112023]/60 p-4"></div>
				{/each}
			</div>
		{:else if filteredTools.length === 0}
			<div class="rounded-2xl border border-white/10 bg-[#112023]/70 p-12 text-center">
				<div class="text-sm font-semibold text-slate-300">
					Không có công cụ nào khớp bộ lọc hiện tại.
				</div>
				<button
					type="button"
					onclick={() => {
						filterMode = 'all';
						searchQuery = '';
					}}
					class="mt-3 rounded-xl border border-teal-400/30 bg-teal-500/15 px-4 py-2 text-xs font-semibold text-teal-200 hover:bg-teal-500/25"
				>
					Hiển thị lại toàn bộ
				</button>
			</div>
		{:else}
			<div class="grid grid-cols-1 gap-3.5 md:grid-cols-2 xl:grid-cols-3">
				{#each filteredTools as tool (tool.id)}
					<ToolCard
						{tool}
						{busyToolId}
						onLaunch={handleLaunch}
						onInstallOrUpdate={handleInstallOrUpdate}
						onOpenGitDrawer={(t) => (activeGitToolId = t.id)}
						onOpenReleaseNotes={(t) => (releaseNotesTool = t)}
						onOpenPath={handleOpenPath}
						onChangeChannel={handleChangeChannel}
					/>
				{/each}
			</div>
		{/if}
	</main>

	<!-- Thông báo nổi ngắn gọn -->
	{#if toastMessage}
		<div
			class="fixed right-6 bottom-6 z-50 max-w-md rounded-xl border px-4 py-3 text-xs font-semibold shadow-2xl transition {toastMessage.kind ===
			'err'
				? 'border-rose-400/40 bg-[#2A1215] text-rose-200'
				: 'border-teal-400/40 bg-[#0F2928] text-teal-100'}"
		>
			{toastMessage.text}
		</div>
	{/if}

	<!-- Ngăn chi tiết Git Drift -->
	<GitDriftDrawer
		tool={activeGitTool}
		onClose={() => (activeGitToolId = null)}
		onOpenPath={handleOpenPath}
	/>

	<!-- Hộp thoại tiến trình Guardian Vault -->
	<UpdateProgressModal
		open={showProgressModal}
		progress={currentProgress}
		logs={progressLogs}
		lastResult={lastInstallResult}
		errorMsg={installError}
		onClose={() => (showProgressModal = false)}
	/>

	<!-- Hộp thoại quản lý Manifest -->
	<ManifestInspector
		open={showManifestModal}
		manifestPath={snapshot?.manifest_path ?? ''}
		validation={manifestValidation}
		onValidate={handleValidateManifest}
		onOpenManifestFile={() => snapshot && handleOpenPath(snapshot.manifest_path)}
		onClose={() => (showManifestModal = false)}
	/>

	<!-- Hộp thoại Cài đặt -->
	{#if snapshot}
		<SettingsModal
			open={showSettingsModal}
			settings={snapshot.settings}
			vaultRoot={snapshot.vault_root}
			onSave={handleSaveSettings}
			onOpenPath={handleOpenPath}
			onClose={() => (showSettingsModal = false)}
		/>
	{/if}

	<!-- Hộp thoại xem Ghi chú phát hành (Release Notes) -->
	{#if releaseNotesTool}
		<div
			class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-xs"
			role="dialog"
			aria-modal="true"
		>
			<div class="w-full max-w-xl rounded-2xl border border-white/12 bg-[#0E1B1D] p-6 shadow-2xl">
				<div class="flex items-start justify-between gap-4">
					<div>
						<div class="text-xs font-semibold tracking-wider text-teal-400 uppercase">
							Ghi Chú Phát Hành Chính Thức
						</div>
						<h3 class="font-display mt-1 text-lg font-bold text-white">
							{releaseNotesTool.name} · v{releaseNotesTool.remote?.normalized_version ?? ''}
						</h3>
					</div>
					<button
						type="button"
						onclick={() => (releaseNotesTool = null)}
						class="rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 text-xs font-semibold text-slate-300 hover:bg-white/10"
					>
						Đóng ✕
					</button>
				</div>
				<pre
					class="mt-4 max-h-80 overflow-y-auto rounded-xl border border-white/[0.08] bg-[#081012] p-4 font-sans text-xs leading-relaxed whitespace-pre-wrap text-slate-200"
				>{releaseNotesTool.remote?.notes ?? 'Không có ghi chú chi tiết.'}</pre>
			</div>
		</div>
	{/if}
</div>
