import type { AccountView } from './types'

export interface WidgetProps {
  accounts: AccountView[]
  /**
   * Set only when the saved accounts could not be read. It replaces the empty
   * state rather than joining it: "Add an account in Settings" is a false
   * statement to someone who has accounts the app failed to load.
   */
  warning: string | null
  onOpenSettings: () => void
  onRelogin: (uuid: string) => void
  onUnlock: (uuid: string) => void
  /**
   * Returns a promise so `AccountRow` can disable its own button until the
   * refresh settles — the press waits for §6.1's global permit, so it is not
   * instantaneous.
   */
  onRefresh: (uuid: string) => void | Promise<void>
}

/**
 * A `$state` proxy, not a plain object. Measured with this repo's own svelte
 * 5.56.8: `mount(Widget, { target, props })` followed by `props.accounts = [...]`
 * plus `flushSync()` leaves the DOM reading "Add an account in Settings" — a
 * plain props object is not reactive after mount. The same sequence through a
 * `$state` proxy does re-render.
 *
 * **The `.svelte.ts` extension is load-bearing.** `$state` in a plain `.ts`
 * throws `rune_outside_svelte` at import time under the dev/vitest transform,
 * and in a production build it is emitted as an undeclared `$state(...)` call:
 * measured, `vite build` succeeded and `svelte-check` reported 0 errors while
 * the bundle contained a bare `$state({accounts:[]})` — a runtime
 * ReferenceError and a blank widget that neither project gate catches.
 * `src/main.ts` is a plain `.ts` (index.html:11 loads it), so the box cannot
 * live there.
 *
 * All keys exist at creation so nothing is added to the proxy later, and
 * `Widget.svelte` keeps its `export let` props unchanged — Svelte 5 forbids
 * mixing runes with `export let`, and the shipped component already reacts to a
 * `$state` proxy passed as the whole props object (measured).
 */
export const widgetProps = $state<WidgetProps>({
  accounts: [],
  warning: null,
  onOpenSettings: () => {},
  onRelogin: () => {},
  onUnlock: () => {},
  onRefresh: () => {},
})
