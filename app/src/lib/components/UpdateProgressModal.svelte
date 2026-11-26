<script lang="ts">
	import type { InstallProgressEvent, InstallResultDto } from '$lib/types';

	let {
		open,
		isBusy = false,
		progress,
		logs,
		lastResult,
		errorMsg,
		onClose
	}: {
		open: boolean;
		isBusy?: boolean;
		progress: InstallProgressEvent | null;
		logs: string[];
		lastResult: InstallResultDto | null;
		errorMsg: string | null;
		onClose: () => void;
	} = $props();

	const canClose = $derived(!isBusy && Boolean(lastResult || errorMsg));
</script>

{#if open}
	<div
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-xs"
		role="dialog"
		aria-modal="true"
	>
		<div
			class="w-full max-w-lg rounded-2xl border border-white/12 bg-[#0E1B1D] p-6 shadow-2xl"
		>
			<div class="flex items-center justify-between gap-3">
				<div>
					<div class="text-xs font-semibold tracking-wider text-teal-400 uppercase">
						Giao Dịch Cài Đặt Bảo Hộ · Guardian Vault
					</div>
					<h3 class="font-display mt-1 text-lg font-bold text-white">
						{progress?.tool_name ?? 'Đang xử lý gói cài đặt'}
					</h3>
				</div>
				{#if canClose}
					<button
						type="button"
						onclick={onClose}
						class="rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 text-xs font-semibold text-slate-300 hover:bg-white/10"
					>
						Đóng ✕
					</button>
				{/if}
			</div>

			<!-- Thanh tiến trình -->
			<div class="mt-4">
				<div class="flex items-center justify-between text-xs text-slate-300">
					<span class="truncate pr-2">{progress?.message ?? 'Đang chuẩn bị...'}</span>
					<span class="font-bold text-teal-300 tabular-nums">
						{progress?.percent ?? 0}%
					</span>
				</div>
				<div class="mt-2 h-2.5 w-full overflow-hidden rounded-full bg-[#081012]">
					<div
						class="h-full rounded-full bg-gradient-to-r from-teal-500 to-amber-400 transition-all duration-200"
						style="width: {errorMsg ? 100 : (progress?.percent ?? 8)}%;"
					></div>
				</div>
			</div>

			<!-- Nhật ký từng bước -->
			<div
				class="mt-4 max-h-48 space-y-1.5 overflow-y-auto rounded-xl border border-white/[0.07] bg-[#081012] p-3 font-mono text-[11px] text-slate-300"
			>
				{#each logs as line, idx (idx)}
					<div class="leading-relaxed">{line}</div>
				{/each}
			</div>

			{#if errorMsg}
				<div class="mt-4 rounded-xl border border-rose-400/35 bg-rose-500/12 p-3.5 text-xs text-rose-200">
					<div class="font-bold">⚠️ Đã dừng an toàn giao dịch:</div>
					<div class="mt-1 leading-relaxed">{errorMsg}</div>
				</div>
			{/if}

			{#if lastResult}
				<div class="mt-4 rounded-xl border border-emerald-400/30 bg-emerald-500/12 p-3.5 text-xs text-emerald-200 space-y-1">
					<div class="font-bold">
						✓ Đã nâng cấp lên v{lastResult.installed_version} thành công!
					</div>
					{#if lastResult.vault_report.restored_immutable_files.length > 0}
						<div>
							🛡️ Đã khôi phục & kiểm khớp 100% SHA-256 cho {lastResult.vault_report.restored_immutable_files.length} tệp bất biến.
						</div>
					{/if}
					{#if lastResult.vault_report.verified_backup_files.length > 0}
						<div>
							💾 Đã hậu kiểm nguyên vẹn {lastResult.vault_report.verified_backup_files.length} tệp cơ sở dữ liệu & khóa bảo mật.
						</div>
					{/if}
				</div>
			{/if}

			{#if canClose}
				<div class="mt-5 flex justify-end">
					<button
						type="button"
						onclick={onClose}
						class="rounded-xl bg-teal-500 px-5 py-2 text-xs font-bold text-slate-950 hover:bg-teal-400"
					>
						Hoàn tất
					</button>
				</div>
			{/if}
		</div>
	</div>
{/if}
