<script lang="ts">
	import type { ManifestValidationDto } from '$lib/types';

	let {
		open,
		manifestPath,
		validation,
		onValidate,
		onOpenManifestFile,
		onClose
	}: {
		open: boolean;
		manifestPath: string;
		validation: ManifestValidationDto | null;
		onValidate: () => void;
		onOpenManifestFile: () => void;
		onClose: () => void;
	} = $props();
</script>

{#if open}
	<div
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-xs"
		role="dialog"
		aria-modal="true"
	>
		<div class="w-full max-w-xl rounded-2xl border border-white/12 bg-[#0E1B1D] p-6 shadow-2xl">
			<div class="flex items-start justify-between gap-4">
				<div>
					<div class="text-xs font-semibold tracking-wider text-teal-400 uppercase">
						Kiến Trúc Manifest-Driven · Mở Rộng Không Sửa Code
					</div>
					<h3 class="font-display mt-1 text-lg font-bold text-white">
						Quản Lý ecosystem-manifest.json
					</h3>
				</div>
				<button
					type="button"
					onclick={onClose}
					class="rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 text-xs font-semibold text-slate-300 hover:bg-white/10"
				>
					Đóng ✕
				</button>
			</div>

			<div class="mt-4 space-y-4 text-xs text-slate-300">
				<div class="rounded-xl border border-white/10 bg-[#0B1416] p-3.5">
					<div class="text-[11px] font-medium text-slate-400">Đường dẫn Manifest đang nạp trực tiếp:</div>
					<code class="mt-1 block break-all font-mono text-teal-300">{manifestPath}</code>
				</div>

				<div class="rounded-xl border border-white/[0.08] bg-white/[0.03] p-4 leading-relaxed text-slate-300">
					<div class="font-bold text-white">Cách thêm Công cụ thứ 8 trong 30 giây:</div>
					<p class="mt-1.5 text-slate-400">
						Chỉ cần thêm một khối JSON mới vào mảng <code class="text-teal-300">tools</code> trong tệp
						<code class="text-slate-200">ecosystem-manifest.json</code> (khai báo <code class="text-slate-200">id</code>,
						<code class="text-slate-200">endpoint</code>, khóa công khai <code class="text-slate-200">pubkey</code> Ed25519,
						đường dẫn <code class="text-slate-200">exe_candidates</code> và <code class="text-slate-200">git.repo_path</code>).
						Ngay khi bấm Lưu, bộ lắng nghe tự động nạp nóng công cụ thứ 8 lên bảng điều khiển mà không cần biên dịch lại Launcher!
					</p>
				</div>

				{#if validation}
					<div
						class="rounded-xl border p-3.5 {validation.valid
							? 'border-emerald-400/30 bg-emerald-500/10 text-emerald-200'
							: 'border-rose-400/35 bg-rose-500/12 text-rose-200'}"
					>
						<div class="font-bold">
							{validation.valid ? '✓ Kiểm tra hợp lệ:' : '⚠️ Lỗi cấu hình Manifest:'}
						</div>
						<div class="mt-1">{validation.message}</div>
					</div>
				{/if}
			</div>

			<div class="mt-5 flex flex-wrap justify-between gap-2 border-t border-white/10 pt-4">
				<div class="flex gap-2">
					<button
						type="button"
						onclick={onOpenManifestFile}
						class="rounded-xl border border-white/15 bg-white/5 px-4 py-2 text-xs font-semibold text-white hover:bg-white/10"
					>
						📂 Mở vị trí tệp Manifest
					</button>
					<button
						type="button"
						onclick={onValidate}
						class="rounded-xl border border-teal-400/35 bg-teal-500/15 px-4 py-2 text-xs font-semibold text-teal-200 hover:bg-teal-500/25"
					>
						🔍 Kiểm tra cú pháp & Khóa Ed25519
					</button>
				</div>
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
