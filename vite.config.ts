import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// https://vite.dev/config/
export default defineConfig({
  plugins: [svelte()],
  // strictPort: without it vite silently moves to 5174 when 5173 is taken,
  // while tauri.conf.json's devUrl stays pinned to 5173 — the symptom is a
  // blank always-on-top window with no obvious cause.
  // host: this machine was observed binding IPv6-only (::1) by default.
  server: { port: 5173, strictPort: true, host: '127.0.0.1' },
})
