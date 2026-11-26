<script lang="ts">
	import { onMount } from 'svelte';
	import { getVersion } from '@tauri-apps/api/app';
	import { check, type Update } from '@tauri-apps/plugin-updater';
	import {
		getEcosystemSnapshot,
		installOrUpdateTool,
		launchTool,
		onCloseBlocked,
		onInstallProgress,
		onManifestReloaded,
		openFilesystemPath,
		prepareSelfUpdateExit,
		rollbackTool,
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
	let releaseNotesToolId = $state<string | null>(null);
	let showManifestModal = $state(false);
	let manifestValidation = $state<ManifestValidationDto | null>(null);
	let showSettingsModal = $state(false);

	// Trạng thái tự cập nhật của chính Selorson Launcher
	let launcherVersion = $state('0.1.2');
	let selfUpdate = $state<Update | null>(null);
	let selfUpdating = $state(false);
	let selfUpdatePct = $state<number | null>(null);

	// Trạng thái cài đặt / nâng cấp / khôi phục
	let busyToolId = $state<string | null>(null);
	let localInvokeActive = false;
	let launchingIds = $state<Record<string, boolean>>({});
	let rollbackConfirmToolId = $state<string | null>(null);
	let showProgressModal = $state(false);
	let currentProgress = $state<InstallProgressEvent | null>(null);
	let progressLogs = $state<string[]>([]);
	let lastInstallResult = $state<InstallResultDto | null>(null);
	let installError = $state<string | null>(null);

	let latestSnapshotReqId = 0;
	let activeSnapshotRequests = 0;

	const activeGitTool = $derived(
		snapshot?.tools.find((t) => t.id === activeGitToolId) ?? null
	);

	const releaseNotesTool = $derived(
		snapshot?.tools.find((t) => t.id === releaseNotesToolId) ?? null
	);

	const rollbackConfirmTool = $derived(
		snapshot?.tools.find((t) => t.id === rollbackConfirmToolId) ?? null
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
		const reqId = ++latestSnapshotReqId;
		activeSnapshotRequests += 1;
		try {
			if (snapshot) refreshing = true;
			else loading = true;
			const data = await getEcosystemSnapshot(forceRemote);
			if (reqId === latestSnapshotReqId) {
				snapshot = data;
				if (!localInvokeActive) {
					busyToolId = data.active_install_tool_id;
					if (data.active_install_tool_id) {
						showProgressModal = true;
					}
				}
			}
		} catch (e) {
			if (reqId === latestSnapshotReqId) {
				showToast(String(e), 'err');
			}
		} finally {
			activeSnapshotRequests = Math.max(0, activeSnapshotRequests - 1);
			if (activeSnapshotRequests === 0) {
				loading = false;
				refreshing = false;
			}
		}
	}

	async function handleLaunch(tool: ToolFullStatusDto) {
		if (busyToolId !== null || selfUpdating || launchingIds[tool.id]) return;
		launchingIds = { ...launchingIds, [tool.id]: true };
		const wasAlreadyRunning = tool.local.is_running;
		try {
			await launchTool(tool.id);
			showToast(
				wasAlreadyRunning
					? `Đã chuyển tới cửa sổ đang mở của ${tool.name}`
					: `Đã khởi chạy ${tool.name}`
			);
			setTimeout(async () => {
				await loadSnapshot(false);
				const next = { ...launchingIds };
				delete next[tool.id];
				launchingIds = next;
			}, 2000);
		} catch (e) {
			const next = { ...launchingIds };
			delete next[tool.id];
			launchingIds = next;
			showToast(String(e), 'err');
		}
	}

	async function handleInstallOrUpdate(tool: ToolFullStatusDto) {
		if (busyToolId !== null || selfUpdating) return;
		localInvokeActive = true;
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
			localInvokeActive = false;
			busyToolId = null;
		}
	}

	function handleRequestRollback(tool: ToolFullStatusDto) {
		if (busyToolId || selfUpdating || tool.local.is_running) return;
		rollbackConfirmToolId = tool.id;
	}

	async function executeConfirmedRollback() {
		const tool = rollbackConfirmTool;
		if (!tool || busyToolId || selfUpdating || tool.local.is_running) return;
		rollbackConfirmToolId = null;
		localInvokeActive = true;
		busyToolId = tool.id;
		showProgressModal = true;
		lastInstallResult = null;
		installError = null;
		progressLogs = [
			`[${new Date().toLocaleTimeString('vi-VN')}] Bắt đầu khôi phục ${tool.name} từ Guardian Vault...`
		];
		currentProgress = {
			tool_id: tool.id,
			tool_name: tool.name,
			phase: 'rolling_back',
			percent: 20,
			downloaded_bytes: 0,
			total_bytes: null,
			message: `Đang kiểm tra SHA-256 bản sao lưu của ${tool.name}...`
		};

		try {
			const res = await rollbackTool(tool.id);
			lastInstallResult = res;
			await loadSnapshot(false);
		} catch (e) {
			installError = String(e);
			progressLogs = [...progressLogs, `❌ Lỗi khôi phục: ${String(e)}`];
		} finally {
			localInvokeActive = false;
			busyToolId = null;
		}
	}

	async function handleBatchUpdateIdleTools() {
		if (updatableTools.length === 0 || busyToolId !== null || selfUpdating) return;
		const queue = [...updatableTools];
		localInvokeActive = true;
		showProgressModal = true;
		lastInstallResult = null;
		installError = null;
		currentProgress = null;
		progressLogs = [
			`[${new Date().toLocaleTimeString('vi-VN')}] Bắt đầu nâng cấp tuần tự ${queue.length} công cụ đang rảnh...`
		];

		try {
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
		} finally {
			localInvokeActive = false;
			busyToolId = null;
		}
		await loadSnapshot(false);
	}

	async function handleChangeChannel(toolId: string, channel: string) {
		if (busyToolId !== null || selfUpdating) return;
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
		try {
			const res = await validateManifestNow();
			manifestValidation = res;
			if (res.valid) {
				await loadSnapshot(true);
			}
		} catch (e) {
			showToast(String(e), 'err');
		}
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
		if (
			showProgressModal ||
			showManifestModal ||
			showSettingsModal ||
			activeGitToolId ||
			releaseNotesTool ||
			rollbackConfirmTool
		) {
			if (e.key === 'Escape') {
				activeGitToolId = null;
				releaseNotesToolId = null;
				showManifestModal = false;
				showSettingsModal = false;
				rollbackConfirmToolId = null;
				if (showProgressModal && busyToolId === null) {
					showProgressModal = false;
				}
			}
			return;
		}
		if (busyToolId !== null || selfUpdating) {
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

	async function checkSelfUpdate() {
		try {
			const upd = await check();
			selfUpdate = upd ?? null;
		} catch {
			// Bỏ qua êm nếu chưa có bản phát hành trên GitHub hoặc đang ngoại tuyến
		}
	}

	async function handleSelfUpdateLauncher() {
		if (!selfUpdate || selfUpdating || busyToolId !== null) return;
		selfUpdating = true;
		selfUpdatePct = 0;
		let downloaded = 0;
		let total = 0;

		try {
			await prepareSelfUpdateExit(true);
			await selfUpdate.downloadAndInstall((event) => {
				if (event.event === 'Started') {
					total = event.data.contentLength ?? 0;
				} else if (event.event === 'Progress') {
					downloaded += event.data.chunkLength;
					if (total > 0) {
						selfUpdatePct = Math.min(99, Math.round((downloaded * 100) / total));
					}
				} else if (event.event === 'Finished') {
					selfUpdatePct = 100;
				}
			});
			// Trên Windows NSIS, tauri-plugin-updater v2 đã tự kích hoạt bộ cài & thoát tiến trình; không gọi relaunch() chồng!
		} catch (e) {
			await prepareSelfUpdateExit(false).catch(() => {});
			selfUpdating = false;
			selfUpdatePct = null;
			showToast(`Không tự cập nhật được Launcher: ${String(e)}`, 'err');
		}
	}

	onMount(() => {
		getVersion()
			.then((v) => (launcherVersion = v))
			.catch(() => {});
		loadSnapshot(true);
		checkSelfUpdate();

		let disposed = false;
		let unlistenProgress: (() => void) | null = null;
		let unlistenManifest: (() => void) | null = null;
		let unlistenCloseBlocked: (() => void) | null = null;

		onInstallProgress((evt) => {
			currentProgress = evt;
			if (evt.phase !== 'downloading' || progressLogs.length === 0) {
				const stamp = new Date().toLocaleTimeString('vi-VN');
				const last = progressLogs[progressLogs.length - 1] ?? '';
				if (!last.includes(evt.message)) {
					progressLogs = [...progressLogs, `[${stamp}] ${evt.message}`];
				}
			}
			// Nếu cửa sổ vừa dựng lại từ Tray giữa giao dịch đang chạy ngầm -> tự mở khóa khi nhận sự kiện kết thúc!
			if (!localInvokeActive && (evt.phase === 'completed' || evt.phase === 'failed')) {
				busyToolId = null;
				if (evt.phase === 'failed') {
					installError = evt.message;
				}
				loadSnapshot(false);
			}
		}).then((fn) => {
			if (disposed) fn();
			else unlistenProgress = fn;
		});

		onManifestReloaded(() => {
			showToast('Phát hiện thay đổi trong ecosystem-manifest.json — Đã tự động nạp nóng!');
			loadSnapshot(true);
		}).then((fn) => {
			if (disposed) fn();
			else unlistenManifest = fn;
		});

		onCloseBlocked((msg) => {
			showProgressModal = true;
			showToast(msg, 'err');
		}).then((fn) => {
			if (disposed) fn();
			else unlistenCloseBlocked = fn;
		});

		let lastFocusAt = 0;
		const focusRefresh = () => {
			const now = Date.now();
			if (now - lastFocusAt < 5000) return;
			if (busyToolId !== null || selfUpdating || activeSnapshotRequests > 0) return;
			lastFocusAt = now;
			loadSnapshot(false);
		};
		window.addEventListener('focus', focusRefresh);

		return () => {
			disposed = true;
			unlistenProgress?.();
			unlistenManifest?.();
			unlistenCloseBlocked?.();
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
							class="rounded-full border border-white/12 bg-white/[0.05] px-2 py-0.5 text-[11px] font-medium text-slate-300 tabular-nums"
						>
							v{launcherVersion}
						</span>
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

				{#if selfUpdate}
					<button
						type="button"
						disabled={selfUpdating || busyToolId !== null}
						onclick={handleSelfUpdateLauncher}
						title={selfUpdate.body || `Nâng cấp Selorson Launcher lên ${selfUpdate.version}`}
						class="rounded-xl bg-teal-400 px-3.5 py-2 text-xs font-bold text-slate-950 shadow transition hover:bg-teal-300 disabled:opacity-60"
					>
						{#if selfUpdating}
							⏳ Đang nâng cấp Launcher{selfUpdatePct !== null ? ` (${selfUpdatePct}%)` : '...'}
						{:else}
							⬆️ Cập nhật Launcher ({selfUpdate.version})
						{/if}
					</button>
				{/if}

				{#if updatableTools.length > 0}
					<button
						type="button"
						disabled={busyToolId !== null || selfUpdating}
						onclick={handleBatchUpdateIdleTools}
						class="rounded-xl bg-amber-400 px-3.5 py-2 text-xs font-bold text-slate-950 shadow transition hover:bg-amber-300 disabled:opacity-50"
					>
						🚀 Cập nhật tất cả rảnh ({updatableTools.length})
					</button>
				{:else if updateAvailableCount > 0}
					<span
						class="rounded-xl border border-amber-400/25 bg-amber-500/10 px-3 py-2 text-xs font-semibold text-amber-200/90"
						title="Các công cụ có bản mới hiện đang chạy hoặc đang giữ bản Hot-Swap cục bộ nên được tự động khóa bảo vệ khỏi cập nhật hàng loạt"
					>
						🔒 {updateAvailableCount} bản mới (đang mở / Hot-Swap)
					</span>
				{/if}

				<button
					type="button"
					disabled={refreshing || busyToolId !== null || selfUpdating}
					onclick={() => {
						loadSnapshot(true);
						checkSelfUpdate();
					}}
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
						globalBusy={busyToolId !== null || selfUpdating}
						isLaunching={Boolean(launchingIds[tool.id])}
						onLaunch={handleLaunch}
						onInstallOrUpdate={handleInstallOrUpdate}
						onRollback={handleRequestRollback}
						onOpenGitDrawer={(t) => (activeGitToolId = t.id)}
						onOpenReleaseNotes={(t) => (releaseNotesToolId = t.id)}
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
		isBusy={busyToolId !== null}
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

	<!-- Hộp thoại xác nhận khôi phục phiên bản từ Guardian Vault -->
	{#if rollbackConfirmTool}
		<div
			class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-xs"
			role="dialog"
			aria-modal="true"
		>
			<div class="w-full max-w-md rounded-2xl border border-amber-400/30 bg-[#0E1B1D] p-6 shadow-2xl">
				<div class="text-xs font-semibold tracking-wider text-amber-300 uppercase">
					Guardian Vault · Khôi Phục Nguyên Tử
				</div>
				<h3 class="font-display mt-1 text-lg font-bold text-white">
					Khôi phục {rollbackConfirmTool.name}{rollbackConfirmTool.local.rollback_target_version
						? ` về v${rollbackConfirmTool.local.rollback_target_version}`
						: ''}?
				</h3>
				<p class="mt-2.5 text-xs leading-relaxed text-slate-300">
					Launcher sẽ kiểm khớp 100% chữ ký băm <code class="text-amber-200">SHA-256</code> trong kho
					sao lưu gần nhất và hoàn trả nguyên tử tệp thực thi ổn định kèm cơ sở dữ liệu / khóa cấu
					hình của <strong>{rollbackConfirmTool.name}</strong>.
				</p>
				<div class="mt-5 flex justify-end gap-2 border-t border-white/10 pt-4">
					<button
						type="button"
						onclick={() => (rollbackConfirmToolId = null)}
						class="rounded-xl border border-white/12 bg-white/5 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-white/10"
					>
						Hủy
					</button>
					<button
						type="button"
						onclick={executeConfirmedRollback}
						class="rounded-xl bg-amber-400 px-4 py-2 text-xs font-bold text-slate-950 hover:bg-amber-300"
					>
						⏪ Xác nhận khôi phục
					</button>
				</div>
			</div>
		</div>
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
						onclick={() => (releaseNotesToolId = null)}
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
