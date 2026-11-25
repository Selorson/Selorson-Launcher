import { convertFileSrc, invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type {
	EcosystemSnapshotDto,
	InstallProgressEvent,
	InstallResultDto,
	LauncherSettings,
	ManifestValidationDto
} from './types';

export function resolveIconUrl(iconPath: string | null): string | null {
	if (!iconPath) return null;
	try {
		return convertFileSrc(iconPath);
	} catch {
		return null;
	}
}

export async function getEcosystemSnapshot(forceRemote = false): Promise<EcosystemSnapshotDto> {
	return invoke<EcosystemSnapshotDto>('get_ecosystem_snapshot', { forceRemote });
}

export async function launchTool(toolId: string): Promise<string> {
	return invoke<string>('launch_tool', { toolId });
}

export async function installOrUpdateTool(toolId: string): Promise<InstallResultDto> {
	return invoke<InstallResultDto>('install_or_update_tool', { toolId });
}

export async function setToolChannel(toolId: string, channel: string): Promise<void> {
	return invoke<void>('set_tool_channel', { toolId, channel });
}

export async function updateLauncherSettings(
	closeToTray: boolean,
	globalHotkeyEnabled: boolean
): Promise<LauncherSettings> {
	return invoke<LauncherSettings>('update_launcher_settings', {
		closeToTray,
		globalHotkeyEnabled
	});
}

export async function openFilesystemPath(path: string): Promise<void> {
	return invoke<void>('open_filesystem_path', { path });
}

export async function validateManifestNow(): Promise<ManifestValidationDto> {
	return invoke<ManifestValidationDto>('validate_manifest_now');
}

export async function prepareSelfUpdateExit(): Promise<void> {
	return invoke<void>('prepare_self_update_exit');
}

export async function onInstallProgress(
	handler: (evt: InstallProgressEvent) => void
): Promise<UnlistenFn> {
	return listen<InstallProgressEvent>('launcher://install-progress', (e) => handler(e.payload));
}

export async function onManifestReloaded(handler: () => void): Promise<UnlistenFn> {
	return listen('launcher://manifest-reloaded', () => handler());
}
