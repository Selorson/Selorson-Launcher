<script lang="ts">
	import { resolveIconUrl } from '$lib/api';
	import type { ToolFullStatusDto } from '$lib/types';

	let {
		tool,
		busyToolId,
		globalBusy = false,
		isLaunching = false,
		onLaunch,
		onInstallOrUpdate,
		onRollback,
		onOpenGitDrawer,
		onOpenReleaseNotes,
		onOpenPath,
		onChangeChannel
	}: {
		tool: ToolFullStatusDto;
		busyToolId: string | null;
		globalBusy?: boolean;
		isLaunching?: boolean;
		onLaunch: (tool: ToolFullStatusDto) => void;
		onInstallOrUpdate: (tool: ToolFullStatusDto) => void;
		onRollback: (tool: ToolFullStatusDto) => void;
		onOpenGitDrawer: (tool: ToolFullStatusDto) => void;
		onOpenReleaseNotes: (tool: ToolFullStatusDto) => void;
		onOpenPath: (path: string) => void;
		onChangeChannel: (toolId: string, channel: string) => void;
	} = $props();

	let imgBroken = $state(false);
	$effect(() => {
		tool.icon_path;
		tool.icon_data_url;
		imgBroken = false;
	});
	const iconSrc = $derived(
		!imgBroken ? resolveIconUrl(tool.icon_path, tool.icon_data_url) : null
	);
	const isThisBusy = $derived(busyToolId === tool.id);
	const anyBusy = $derived(globalBusy || busyToolId !== null);
	const remoteVersionColorClass = $derived(
		tool.release_state.state === 'update_available'
			? 'text-amber-300'
			: tool.release_state.state === 'not_installed'
				? 'text-teal-300'
				: tool.release_state.state === 'local_newer_or_hot_swapped'
					? 'text-purple-300'
					: 'text-emerald-300'
	);

	function formatMegabytes(bytes: number): string {
		if (bytes <= 0) return '0 MB';
		return `${(bytes / 1_048_576).toFixed(1)} MB`;
	}

	function basename(p: string): string {
		const parts = p.split(/[/\\]/);
		return parts[parts.length - 1] || p;
	}
</script>

<article
	class="group relative flex flex-col justify-between overflow-hidden rounded-2xl border border-white/[0.08] bg-[#112023]/90 p-4 shadow-lg transition-all duration-200 hover:border-white/[0.16] hover:bg-[#14262A]"
>
	<!-- Dải màu nhận diện riêng từ Manifest -->
	<div
		class="pointer-events-none absolute inset-x-0 top-0 h-[3px] opacity-90"
		style="background: linear-gradient(90deg, {tool.accent_color}, transparent 85%);"
	></div>

	<div>
		<!-- Hàng đầu: Biểu tượng + Tên + Trạng thái sống -->
		<div class="flex items-start justify-between gap-2.5">
			<div class="flex items-center gap-3 min-w-0">
				<div
					class="relative flex h-11 w-11 shrink-0 items-center justify-center overflow-hidden rounded-xl border border-white/10 bg-[#0B1416] shadow-inner"
				>
					{#if iconSrc}
						<img
							src={iconSrc}
							alt={tool.name}
							class="h-8.5 w-8.5 object-contain"
							onerror={() => (imgBroken = true)}
						/>
					{:else}
						<span
							class="font-display text-base font-bold"
							style="color: {tool.accent_color};"
						>
							{tool.name.slice(0, 2).toUpperCase()}
						</span>
					{/if}
					{#if tool.order <= 9}
						<span
							class="absolute right-0.5 bottom-0.5 rounded bg-black/75 px-1 text-[9px] font-semibold text-slate-400 tabular-nums"
							title="Bấm phím {tool.order} để mở nhanh"
						>
							{tool.order}
						</span>
					{/if}
				</div>

				<div class="min-w-0">
					<h2 class="font-display truncate text-[15px] font-bold tracking-tight text-white">
						{tool.name}
					</h2>
					<div class="mt-0.5 flex items-center gap-1.5 min-w-0">
						<span
							class="shrink-0 rounded border border-white/[0.07] bg-white/[0.04] px-1.5 py-0.5 text-[10px] font-medium text-slate-300"
						>
							{tool.category}
						</span>
						<span class="truncate text-[11px] text-slate-400" title={tool.subtitle}>
							{tool.subtitle}
						</span>
					</div>
				</div>
			</div>

			<!-- Đèn tiến trình đang chạy + chọn kênh gọn -->
			<div class="flex shrink-0 items-center gap-1.5">
				{#if tool.available_channels.length > 1}
					<select
						class="rounded-lg border border-white/10 bg-[#0B1416] px-1.5 py-0.5 text-[10.5px] font-medium text-slate-200 outline-none focus:border-teal-400"
						value={tool.selected_channel}
						disabled={anyBusy}
						onchange={(e) =>
							onChangeChannel(tool.id, (e.currentTarget as HTMLSelectElement).value)}
					>
						{#each tool.available_channels as ch (ch.key)}
							<option value={ch.key}>{ch.label}</option>
						{/each}
					</select>
				{/if}

				{#if tool.local.is_running}
					<span
						class="inline-flex items-center gap-1 rounded-full border border-emerald-400/30 bg-emerald-500/15 px-2 py-0.5 text-[10.5px] font-semibold text-emerald-300"
					>
						<span class="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400"></span>
						Chạy
					</span>
				{/if}
			</div>
		</div>

		<!-- Bảng thông số 3 cột: Đang cài · Bản phát hành · Radar Git -->
		<div
			class="mt-2.5 grid grid-cols-3 gap-2 rounded-xl border border-white/[0.06] bg-[#0B1416]/85 px-2.5 py-2 text-xs"
		>
			<div class="min-w-0">
				<div class="text-[10px] font-medium tracking-wider text-slate-400 uppercase">
					Đang cài
				</div>
				{#if tool.local.is_installed}
					<div
						class="mt-0.5 truncate font-semibold text-slate-100 tabular-nums"
						title="{tool.local.active_exe_path ?? ''} ({tool.local.version_source ?? ''})"
					>
						v{tool.local.installed_version ?? '?'}
					</div>
				{:else}
					<div class="mt-0.5 font-medium text-slate-500">Chưa cài</div>
				{/if}
			</div>

			<div class="min-w-0 border-l border-white/[0.06] pl-2.5">
				<div class="flex items-center justify-between gap-1">
					<span class="text-[10px] font-medium tracking-wider text-slate-400 uppercase">
						GitHub Release
					</span>
					{#if tool.remote?.notes}
						<button
							type="button"
							class="text-[10px] font-medium text-teal-400 hover:text-teal-300 hover:underline"
							onclick={() => onOpenReleaseNotes(tool)}
						>
							Ghi chú
						</button>
					{/if}
				</div>
				{#if tool.remote}
					<div class="mt-0.5 flex items-center gap-1.5">
						<span class="truncate font-semibold tabular-nums {remoteVersionColorClass}">
							v{tool.remote.normalized_version}
						</span>
					</div>
				{:else}
					<div
						class="mt-0.5 truncate text-[11px] text-rose-400"
						title={tool.remote_error ?? ''}
					>
						Ngoại tuyến
					</div>
				{/if}
			</div>

			<div class="min-w-0 border-l border-white/[0.06] pl-2.5">
				<div class="text-[10px] font-medium tracking-wider text-slate-400 uppercase">
					Mã nguồn Git
				</div>
				<div class="mt-0.5">
					{#if tool.git.drift_status.kind === 'in_sync'}
						<button
							type="button"
							class="inline-flex items-center gap-1 truncate font-medium text-emerald-300 hover:underline"
							onclick={() => onOpenGitDrawer(tool)}
						>
							<span>●</span>
							<span class="truncate">Khớp mã nguồn</span>
						</button>
					{:else if tool.git.drift_status.kind === 'source_ahead'}
						<button
							type="button"
							class="inline-flex items-center gap-1 truncate font-semibold text-amber-300 hover:text-amber-200 hover:underline"
							onclick={() => onOpenGitDrawer(tool)}
							title="Bấm để xem {tool.git.drift_status.commits_ahead} commit mới hơn bản .exe"
						>
							<span>⚡</span>
							<span class="truncate">+{tool.git.drift_status.commits_ahead} commit mới</span>
						</button>
					{:else if tool.git.drift_status.kind === 'source_behind'}
						<button
							type="button"
							class="inline-flex items-center gap-1 truncate font-semibold text-sky-300 hover:underline"
							onclick={() => onOpenGitDrawer(tool)}
							title="Kho Git hiện đang checkout lùi {tool.git.drift_status.commits_behind} commit trước {tool.git.drift_status.base_tag}"
						>
							<span>⏪</span>
							<span class="truncate">Lùi -{tool.git.drift_status.commits_behind} commit</span>
						</button>
					{:else if tool.git.drift_status.kind === 'hot_swapped_ahead'}
						<button
							type="button"
							class="inline-flex items-center gap-1 truncate font-semibold text-purple-300 hover:underline"
							onclick={() => onOpenGitDrawer(tool)}
						>
							<span>🔧</span>
							<span class="truncate">Hot-Swap (+{tool.git.drift_status.commits_since_tag})</span>
						</button>
					{:else if tool.git.drift_status.kind === 'not_installed'}
						<span class="text-slate-500">Chờ cài .exe</span>
					{:else}
						<span class="text-slate-500">Không có kho</span>
					{/if}
				</div>
			</div>
		</div>

		<!-- Dải huy hiệu bảo hộ Guardian Vault, Cổng dịch vụ & Tệp sửa dở -->
		<div class="mt-2 flex min-h-[22px] flex-wrap items-center gap-1.5">
			{#each tool.local.immutable_guards as guard (guard.path)}
				{#if guard.exists}
					<span
						class="inline-flex items-center gap-1 rounded-md border border-amber-400/25 bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-200"
						title="Guardian Vault khóa bất biến SHA-256: không cho phép trình cài đặt xóa hay ghi đè tệp này"
					>
						🛡️ Khóa bảo vệ {basename(guard.path)} ({formatMegabytes(guard.size_bytes)})
					</span>
				{/if}
			{/each}

			{#each tool.local.open_ports as p (p.port)}
				{#if p.is_open}
					<span
						class="inline-flex items-center gap-1 rounded-md border border-sky-400/25 bg-sky-500/10 px-2 py-0.5 text-[11px] font-medium text-sky-200"
					>
						🔌 {p.label}
					</span>
				{/if}
			{/each}

			{#if tool.git.dirty_files_count > 0}
				<button
					type="button"
					onclick={() => onOpenGitDrawer(tool)}
					class="inline-flex items-center gap-1 rounded-md border border-white/10 bg-white/[0.04] px-2 py-0.5 text-[11px] text-slate-300 hover:bg-white/[0.08]"
				>
					✎ Đang sửa dở {tool.git.dirty_files_count} tệp
				</button>
			{/if}

			{#if tool.local.all_detected_exes.length > 1}
				<span
					class="inline-flex items-center rounded-md border border-white/10 bg-white/[0.03] px-2 py-0.5 text-[11px] text-slate-400"
					title="Đang ưu tiên mở bản mới nhất tại: {tool.local.active_exe_path}"
				>
					Đa vị trí ({tool.local.all_detected_exes.length})
				</span>
			{/if}
		</div>
	</div>

	<!-- Thanh thao tác 1 chạm -->
	<div class="mt-2.5 flex items-center justify-between gap-2 border-t border-white/[0.06] pt-2.5">
		<div class="flex flex-1 items-center gap-2">
			{#if !tool.local.is_installed}
				<button
					type="button"
					disabled={anyBusy || !tool.remote}
					onclick={() => onInstallOrUpdate(tool)}
					class="flex flex-1 items-center justify-center gap-2 rounded-xl bg-teal-500 px-3.5 py-2 text-xs font-bold text-slate-950 shadow transition hover:bg-teal-400 disabled:cursor-not-allowed disabled:opacity-50"
				>
					{#if isThisBusy}
						<span class="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-950 border-t-transparent"></span>
						Đang cài đặt...
					{:else}
						⬇️ Cài đặt {tool.remote ? `v${tool.remote.normalized_version}` : 'mới'}
					{/if}
				</button>
			{:else if tool.release_state.state === 'update_available' && tool.remote}
				<button
					type="button"
					disabled={anyBusy}
					onclick={() => onInstallOrUpdate(tool)}
					class="flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-amber-400 px-3.5 py-2 text-xs font-bold text-slate-950 shadow transition hover:bg-amber-300 disabled:cursor-not-allowed disabled:opacity-50"
				>
					{#if isThisBusy}
						<span class="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-950 border-t-transparent"></span>
						Đang nâng cấp...
					{:else}
						🚀 Cập nhật v{tool.remote.normalized_version}
					{/if}
				</button>
				<button
					type="button"
					disabled={anyBusy || isLaunching}
					onclick={() => onLaunch(tool)}
					class="rounded-xl border border-white/12 bg-white/[0.06] px-3 py-2 text-xs font-semibold text-white transition hover:bg-white/[0.12] disabled:cursor-not-allowed disabled:opacity-50"
					title="Mở ngay phiên bản v{tool.local.installed_version ?? ''} hiện tại mà chưa cần cập nhật"
				>
					{isLaunching ? '⏳...' : '▶️ Mở'}
				</button>
			{:else}
				<button
					type="button"
					disabled={anyBusy || isLaunching}
					onclick={() => onLaunch(tool)}
					class="flex flex-1 items-center justify-center gap-2 rounded-xl border border-teal-400/30 bg-teal-500/15 px-3.5 py-2 text-xs font-bold text-teal-200 transition hover:border-teal-400/50 hover:bg-teal-500/25 disabled:cursor-not-allowed disabled:opacity-50"
				>
					{isLaunching ? `⏳ Đang mở ${tool.name}...` : `▶️ Mở ${tool.name}`}
				</button>
			{/if}
		</div>

		<!-- Cụm nút mở nhanh thư mục, khôi phục Vault & kiểm tra Git -->
		<div class="flex items-center gap-1">
			{#if tool.local.can_rollback}
				<button
					type="button"
					disabled={anyBusy || tool.local.is_running}
					onclick={() => onRollback(tool)}
					class="rounded-lg border border-amber-400/25 bg-amber-500/10 p-2 text-xs text-amber-200 transition hover:border-amber-400/50 hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-40"
					title={tool.local.is_running
						? `Hãy đóng ${tool.name} trước khi khôi phục từ Guardian Vault`
						: `Khôi phục phiên bản ổn định trước đó từ Guardian Vault${tool.local.rollback_target_version ? ` (v${tool.local.rollback_target_version})` : ''}`}
				>
					⏪
				</button>
			{/if}
			{#if tool.local.active_exe_path}
				<button
					type="button"
					onclick={() => tool.local.active_exe_path && onOpenPath(tool.local.active_exe_path)}
					class="rounded-lg border border-white/[0.07] bg-white/[0.03] p-2 text-xs text-slate-300 transition hover:border-white/20 hover:bg-white/[0.09] hover:text-white"
					title="Mở vị trí tệp .exe đang cài ({tool.local.active_exe_path})"
				>
					📂
				</button>
			{/if}
			{#if tool.git.repo_exists}
				<button
					type="button"
					onclick={() => onOpenPath(tool.repo_path)}
					class="rounded-lg border border-white/[0.07] bg-white/[0.03] p-2 text-xs text-slate-300 transition hover:border-white/20 hover:bg-white/[0.09] hover:text-white"
					title="Mở thư mục mã nguồn trong Ecosystem ({tool.repo_path})"
				>
					💻
				</button>
				<button
					type="button"
					onclick={() => onOpenGitDrawer(tool)}
					class="rounded-lg border border-white/[0.07] bg-white/[0.03] p-2 text-xs text-slate-300 transition hover:border-white/20 hover:bg-white/[0.09] hover:text-white"
					title="Xem chi tiết đối chiếu Commit Git & câu lệnh bàn giao cho AI"
				>
					⚡
				</button>
			{/if}
		</div>
	</div>
</article>
