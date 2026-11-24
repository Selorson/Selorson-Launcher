<script lang="ts">
	import type { LauncherSettings } from '$lib/types';

	let {
		open,
		settings,
		vaultRoot,
		onSave,
		onOpenPath,
		onClose
	}: {
		open: boolean;
		settings: LauncherSettings;
		vaultRoot: string;
		onSave: (closeToTray: boolean, hotkeyEnabled: boolean) => void;
		onOpenPath: (path: string) => void;
		onClose: () => void;
	} = $props();

	let closeToTray = $state(false);
	let hotkeyEnabled = $state(false);

	$effect(() => {
		if (open) {
			closeToTray = settings.close_to_tray;
			hotkeyEnabled = settings.global_hotkey_enabled;
		}
	});
</script>

{#if open}
	<div
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-xs"
		role="dialog"
		aria-modal="true"
	>
		<div class="w-full max-w-lg rounded-2xl border border-white/12 bg-[#0E1B1D] p-6 shadow-2xl">
			<div class="flex items-start justify-between">
				<div>
					<div class="text-xs font-semibold tracking-wider text-teal-400 uppercase">
						Tối Ưu Tài Nguyên Máy Trạm RTX 4080
					</div>
					<h3 class="font-display mt-1 text-lg font-bold text-white">
						Cài Đặt Selorson Launcher
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

			<div class="mt-5 space-y-4 text-xs">
				<label
					class="flex cursor-pointer items-start justify-between gap-4 rounded-xl border border-white/10 bg-[#0B1416] p-4"
				>
					<div>
						<div class="font-bold text-white">
							Giữ ở khay hệ thống khi đóng cửa sổ (Chế độ Hủy WebView ~4 MB RAM)
						</div>
						<p class="mt-1 leading-relaxed text-slate-400">
							<strong>Đang Tắt (Khuyên dùng mặc định):</strong> Đóng cửa sổ sẽ thoát hẳn 100% tiến trình (0 MB RAM nền).<br />
							<strong>Khi Bật:</strong> Đóng cửa sổ sẽ giải phóng sạch nhân trình duyệt WebView2 (~100 MB), chỉ giữ hạt nhân Rust siêu nhẹ ở góc phải màn hình.
						</p>
					</div>
					<input
						type="checkbox"
						bind:checked={closeToTray}
						onchange={() => {
							if (!closeToTray) hotkeyEnabled = false;
						}}
						class="mt-1 h-4 w-4 accent-teal-400"
					/>
				</label>

				<label
					class="flex cursor-pointer items-start justify-between gap-4 rounded-xl border border-white/10 bg-[#0B1416] p-4 {!closeToTray
						? 'opacity-60'
						: ''}"
				>
					<div>
						<div class="font-bold text-white">
							Phím tắt gọi nhanh toàn cục <kbd class="rounded bg-white/10 px-1.5 py-0.5 text-teal-300">Alt + Shift + S</kbd>
						</div>
						<p class="mt-1 leading-relaxed text-slate-400">
							Bấm <code class="text-slate-200">Alt + Shift + S</code> ở bất kỳ đâu để bật cửa sổ Selorson Launcher lên ngay lập tức (yêu cầu bật chế độ giữ ở khay hệ thống).
						</p>
					</div>
					<input
						type="checkbox"
						disabled={!closeToTray}
						bind:checked={hotkeyEnabled}
						class="mt-1 h-4 w-4 accent-teal-400"
					/>
				</label>

				<div class="rounded-xl border border-white/[0.08] bg-white/[0.03] p-3.5 flex items-center justify-between gap-3">
					<div class="min-w-0">
						<div class="font-semibold text-slate-200">Kho sao lưu Guardian Vault:</div>
						<div class="mt-0.5 truncate font-mono text-[11px] text-slate-400">{vaultRoot}</div>
					</div>
					<button
						type="button"
						onclick={() => onOpenPath(vaultRoot)}
						class="shrink-0 rounded-lg border border-white/12 bg-white/5 px-3 py-1.5 font-semibold text-slate-200 hover:bg-white/10"
					>
						📂 Mở Kho Vault
					</button>
				</div>
			</div>

			<div class="mt-6 flex justify-end gap-2 border-t border-white/10 pt-4">
				<button
					type="button"
					onclick={onClose}
					class="rounded-xl border border-white/12 bg-white/5 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-white/10"
				>
					Hủy
				</button>
				<button
					type="button"
					onclick={() => onSave(closeToTray, hotkeyEnabled)}
					class="rounded-xl bg-teal-500 px-5 py-2 text-xs font-bold text-slate-950 hover:bg-teal-400"
				>
					Lưu cài đặt
				</button>
			</div>
		</div>
	</div>
{/if}
