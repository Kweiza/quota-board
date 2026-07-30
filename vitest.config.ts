import { svelte } from '@sveltejs/vite-plugin-svelte'
import { svelteTesting } from '@testing-library/svelte/vite'
import { defineConfig } from 'vitest/config'

// Standalone on purpose: do not move `test` into vite.config.ts and do not
// mergeConfig() the two. Vite's own defineConfig rejects a `test` key, which
// breaks `tsc -p tsconfig.node.json`, and either route also resolves svelte to
// its server build, so every render dies with "mount(...) is not available on
// the server". svelteTesting() is the part that fixes that: it inserts the
// `browser` resolve condition ahead of `node`, and registers auto-cleanup.
// css: true is not cosmetic. Without it the components' scoped stylesheets are
// never injected and `getComputedStyle` answers with initial values for every
// element, so a rule that dims the bar on a stale row — or one that only looks
// like it dims text — is invisible to the suite. With it, jsdom 29 resolves the
// cascade well enough to assert `opacity` and `color`; measured, not assumed.
export default defineConfig({
  plugins: [svelte(), svelteTesting()],
  test: { environment: 'jsdom', css: true },
})
