import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
	clearScreen: false,
	plugins: [
		tailwindcss(),
		sveltekit({
			alias: {
				$lib: 'src/lib'
			},
			compilerOptions: {
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			adapter: adapter({
				pages: 'build',
				assets: 'build',
				fallback: 'index.html'
			})
		})
	],
	server: {
		port: 5195,
		strictPort: true,
		host: host || false,
		watch: {
			ignored: ['**/src-tauri/**']
		}
	}
});
