import { svelte } from '@sveltejs/vite-plugin-svelte'
import { svelteTesting } from '@testing-library/svelte/vite'
import { configDefaults, defineConfig } from 'vitest/config'

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
  test: {
    environment: 'jsdom',
    css: true,
    // **Spread the defaults, never replace them** — a bare `exclude` drops
    // `node_modules` and `dist` and the run slows to a crawl on vendored specs.
    //
    // `.local/`, `.superpowers/`, `.claude/` and `.flightdeck/` are git-ignored
    // working directories, so a clone does not have them and CI cannot run what
    // they contain. Without this the local totals and the CI totals silently
    // disagree: measured, a scratch probe in `.local/` added 4 tests and one
    // file to every number this project quoted as a gate result, none of which
    // any checkout could reproduce.
    //
    // The last two hold **git worktrees**, which is worse than a scratch probe:
    // a worktree is a whole checkout of another branch, so every spec in the
    // repository has a second copy running against that branch's components.
    // Measured — an older worktree's `AccountList.test.ts` failed eight
    // assertions against this branch's rewritten component, in a run where
    // every spec in `src/` had passed.
    exclude: [
      ...configDefaults.exclude,
      '.local/**',
      '.superpowers/**',
      '.claude/**',
      '.flightdeck/**',
    ],
  },
})
