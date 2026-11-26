<script lang="ts">
	import type { ToolFullStatusDto } from '$lib/types';

	let {
		tool,
		onClose,
		onOpenPath
	}: {
		tool: ToolFullStatusDto | null;
		onClose: () => void;
		onOpenPath: (path: string) => void;
	} = $props();

	let copiedKind = $state<'release' | 'hotswap' | null>(null);

	function buildAiReleasePrompt(t: ToolFullStatusDto): string {
		return `Kiểm tra các thay đổi mới nhất của ${t.name} tại ${t.repo_path}, chạy bộ test/check, tăng số phiên bản và đẩy git tag (${t.tag_prefix}X.Y.Z) lên GitHub để kênh phát hành tự động xuất bản cài mới cho Selorson Launcher.`;
	}

	function buildAiHotSwapPrompt(t: ToolFullStatusDto): string {
		return `Kiểm thử và thực hiện Hot-Swap cục bộ cho ${t.name} từ mã nguồn ${t.repo_path} sang bản thực thi đang cài (${t.local.active_exe_path ?? '%LOCALAPPDATA%'}), đảm bảo tuân thủ quy tắc bảo vệ DB/sidecar trong AGENTS.md.`;
	}

	async function copyText(text: string, kind: 'release' | 'hotswap') {
		try {
			await navigator.clipboard.writeText(text);
			copiedKind = kind;
			setTimeout(() => {
				if (copiedKind === kind) copiedKind = null;
			}, 2200);
		} catch {
			// Bỏ qua nếu hệ thống chặn quyền clipboard tạm thời
		}
	}
</script>

{#if tool}
	<div
		class="fixed inset-0 z-50 flex items-center justify-end bg-black/65 backdrop-blur-xs"
		role="dialog"
		aria-modal="true"
	>
		<div
			class="flex h-full w-full max-w-xl flex-col border-l border-white/10 bg-[#0E1B1D] p-6 shadow-2xl"
		>
			<div class="flex items-start justify-between gap-4 border-b border-white/10 pb-4">
				<div>
					<div class="text-xs font-semibold tracking-wider text-teal-400 uppercase">
						Radar Đối Chiếu Mã Nguồn Cục Bộ
					</div>
					<h3 class="font-display mt-1 text-xl font-bold text-white">
						{tool.name}
						{#if tool.git.branch}
							<span class="ml-2 rounded-md bg-white/10 px-2 py-0.5 text-xs font-medium text-slate-300">
								{tool.git.branch.startsWith('Detached HEAD')
									? tool.git.branch
									: `nhánh ${tool.git.branch}`}
							</span>
						{/if}
					</h3>
					<p class="mt-1 text-xs text-slate-400">
						Đường dẫn theo dõi: <code class="text-slate-200">{tool.repo_path}</code>
						(phạm vi: <code class="text-teal-300">{tool.watch_paths.join(', ')}</code>)
						{#if tool.extra_repo_paths.length > 0}
							<br />
							Kho liên kết: <code class="text-slate-200">{tool.extra_repo_paths.join(', ')}</code>
						{/if}
					</p>
				</div>
				<button
					type="button"
					onclick={onClose}
					class="rounded-lg border border-white/10 bg-white/5 px-2.5 py-1.5 text-xs font-semibold text-slate-300 hover:bg-white/10 hover:text-white"
				>
					Đóng ✕
				</button>
			</div>

			<div class="mt-5 flex-1 space-y-5 overflow-y-auto pr-1">
				<!-- Khối tóm tắt trạng thái -->
				<div class="rounded-xl border border-white/10 bg-[#0B1416] p-4 text-xs space-y-2">
					<div class="flex justify-between">
						<span class="text-slate-400">Tệp .exe đang dùng:</span>
						<span class="font-mono text-slate-200 truncate max-w-[330px]" title={tool.local.active_exe_path ?? ''}>
							{tool.local.active_exe_path ?? 'Chưa cài đặt'}
						</span>
					</div>
					<div class="flex justify-between">
						<span class="text-slate-400">Phiên bản đang cài / GitHub Release:</span>
						<span class="font-semibold text-white tabular-nums">
							{tool.local.installed_version ? `v${tool.local.installed_version}` : '—'} / {tool.remote?.normalized_version
								? `v${tool.remote.normalized_version}`
								: '—'}
						</span>
					</div>
					<div class="flex justify-between">
						<span class="text-slate-400">Tệp đang sửa dở chưa commit:</span>
						<span class="font-semibold {tool.git.dirty_files_count > 0 ? 'text-amber-300' : 'text-emerald-300'}">
							{tool.git.dirty_files_count} tệp
						</span>
					</div>
				</div>

				<!-- Trạng thái chi tiết -->
				{#if tool.git.drift_status.kind === 'source_ahead'}
					<div class="rounded-xl border border-amber-400/30 bg-amber-500/10 p-4">
						<div class="text-sm font-bold text-amber-200">
							⚡ Phát hiện {tool.git.drift_status.commits_ahead} commit mới hơn bản .exe đang cài
						</div>
						<p class="mt-1 text-xs leading-relaxed text-amber-100/80">
							Đối chiếu theo: <strong>{tool.git.drift_status.comparison_basis}</strong> (chỉ tính các thay đổi chạm vào mã nguồn ứng dụng, tự động bỏ qua bản thảo truyện hoặc tài liệu ngoài lề).
						</p>
					</div>

					<div>
						<div class="mb-2 text-xs font-semibold tracking-wider text-slate-400 uppercase">
							Danh sách commit chưa có trong .exe
						</div>
						<div class="space-y-2">
							{#each tool.git.ahead_commits as c (c.full_sha)}
								<div class="rounded-xl border border-white/[0.07] bg-[#0B1416] p-3">
									<div class="flex items-center justify-between text-[11px] text-slate-400">
										<code class="font-semibold text-teal-300">{c.short_sha}</code>
										<span>{c.date_iso}</span>
									</div>
									<div class="mt-1 text-xs font-medium text-slate-100">
										{c.subject}
									</div>
								</div>
							{/each}
						</div>
					</div>
				{:else if tool.git.drift_status.kind === 'source_behind'}
					<div class="rounded-xl border border-sky-400/30 bg-sky-500/10 p-4">
						<div class="text-sm font-bold text-sky-200">
							⏪ Kho mã nguồn đang checkout lùi {tool.git.drift_status.commits_behind} commit trước {tool.git.drift_status.base_tag}
						</div>
						<p class="mt-1 text-xs leading-relaxed text-sky-100/80">
							Bản .exe đang cài thuộc tag <strong>{tool.git.drift_status.base_tag}</strong>, trong khi cây Git cục bộ đang dừng ở một commit cũ hơn.
						</p>
					</div>
				{:else if tool.git.drift_status.kind === 'hot_swapped_ahead'}
					<div class="rounded-xl border border-purple-400/30 bg-purple-500/10 p-4">
						<div class="text-sm font-bold text-purple-200">
							🔧 Bản .exe đang chạy là bản Hot-Swap cục bộ (+{tool.git.drift_status.commits_since_tag} commit sau {tool.git.drift_status.base_tag})
						</div>
						<p class="mt-1 text-xs leading-relaxed text-purple-100/80">
							Tệp .exe trên máy đã được biên dịch mới hơn cả bản trên GitHub Releases. Launcher tự động khóa bảo vệ để nút "Cập nhật tất cả" không tải bản cũ đè ngược lên bản Hot-Swap của anh.
						</p>
					</div>
				{:else if tool.git.drift_status.kind === 'in_sync'}
					<div class="rounded-xl border border-emerald-400/25 bg-emerald-500/10 p-4">
						<div class="text-sm font-bold text-emerald-200">
							✓ Bản .exe đang cài khớp hoàn toàn với mã nguồn đã commit
						</div>
						{#if tool.git.head_watch_commit}
							<p class="mt-1 text-xs text-emerald-100/80">
								Commit ứng dụng gần nhất: <code class="text-white">{tool.git.head_watch_commit.short_sha}</code> — {tool.git.head_watch_commit.subject}
							</p>
						{/if}
					</div>
				{/if}

				<!-- Bàn giao lệnh 1 chạm cho AI (Chuẩn UnrealGameSync) -->
				<div class="rounded-xl border border-white/10 bg-white/[0.03] p-4 space-y-3">
					<div class="text-xs font-bold text-white">
						Bàn giao lệnh 1 chạm cho Antigravity / Claude
					</div>
					{#if tool.hot_swap_hint}
						<p class="text-xs text-slate-400 leading-relaxed">
							{tool.hot_swap_hint}
						</p>
					{/if}
					<div class="grid grid-cols-1 gap-2 sm:grid-cols-2">
						<button
							type="button"
							onclick={() => copyText(buildAiReleasePrompt(tool), 'release')}
							class="rounded-xl border border-teal-400/35 bg-teal-500/15 px-3 py-2.5 text-xs font-semibold text-teal-200 transition hover:bg-teal-500/25"
						>
							{copiedKind === 'release'
								? '✓ Đã chép Prompt Phát hành!'
								: '📋 Chép Prompt Đóng Tag Release'}
						</button>
						<button
							type="button"
							onclick={() => copyText(buildAiHotSwapPrompt(tool), 'hotswap')}
							class="rounded-xl border border-amber-400/35 bg-amber-500/15 px-3 py-2.5 text-xs font-semibold text-amber-200 transition hover:bg-amber-500/25"
						>
							{copiedKind === 'hotswap'
								? '✓ Đã chép Prompt Hot-Swap!'
								: '📋 Chép Prompt Nhờ AI Hot-Swap'}
						</button>
					</div>
				</div>
			</div>

			<div class="mt-4 flex justify-between border-t border-white/10 pt-4">
				<button
					type="button"
					onclick={() => onOpenPath(tool.repo_path)}
					class="rounded-xl border border-white/15 bg-white/5 px-4 py-2 text-xs font-semibold text-slate-200 hover:bg-white/10"
				>
					💻 Mở thư mục Repo trong Explorer
				</button>
				<button
					type="button"
					onclick={onClose}
					class="rounded-xl bg-teal-500 px-4 py-2 text-xs font-bold text-slate-950 hover:bg-teal-400"
				>
					Xong
				</button>
			</div>
		</div>
	</div>
{/if}
