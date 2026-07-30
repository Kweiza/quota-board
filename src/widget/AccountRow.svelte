<script lang="ts">
  import Bar from './Bar.svelte'
  import { relativeAge } from '../lib/format'
  import type { AccountView } from '../lib/types'

  export let account: AccountView
  export let now: Date = new Date()
  export let onRelogin: () => void = () => {}
  export let onUnlock: () => void = () => {}

  $: state = account.state
  // Spec §5.3: the weekly window count is 0, 1 or N — never assumed.
  $: windows = state.kind === 'ok' || state.kind === 'stale' ? state.windows : []
  $: hasWeekly = windows.some(
    (w) => w.window_id.startsWith('weekly') || w.window_id === 'seven_day',
  )
  $: isStale = state.kind === 'stale'

  /** docs/design.md §7.1 fixes this as "throttled, after HH:MM" — a locale string is wrong. */
  function untilHhMm(iso: string): string {
    const d = new Date(iso)
    const hh = String(d.getHours()).padStart(2, '0')
    const mm = String(d.getMinutes()).padStart(2, '0')
    return `${hh}:${mm}`
  }
</script>

<div class="account" class:stale={isStale}>
  <div class="head">
    <span class="name" title={account.label}>{account.label}</span>
    {#if isStale && state.kind === 'stale'}
      <span class="age">{relativeAge(new Date(state.fetched_at), now)}</span>
    {/if}
  </div>

  <!-- The bar branch is explicit rather than the {:else} fallback: an
       unenumerated kind must not be painted as a healthy account. -->
  {#if state.kind === 'ok' || state.kind === 'stale'}
    {#each windows as w (w.window_id)}
      <Bar window_={w} {now} />
    {/each}
    {#if !hasWeekly}
      <div class="note small">weekly not reported</div>
    {/if}
  {:else if state.kind === 'loading'}
    <div class="note">…</div>
  {:else if state.kind === 'auth_expired'}
    <!-- §7.1 calls this "loading", but a permanent failure that renders
         byte-identical to the spinner is the confusion it warns about, so the
         three waiting-shaped states each say something different. -->
    <div class="note">refreshing…</div>
  {:else if state.kind === 'auth_dead'}
    <!-- §7.1: the click is this state's only remedy, so the parent must be
         able to hear it. -->
    <button class="note action" on:click={onRelogin}>re-login required</button>
  {:else if state.kind === 'secrets_locked'}
    <button class="note action" on:click={onUnlock}>unlock</button>
  {:else if state.kind === 'throttled'}
    <div class="note">throttled, after {untilHhMm(state.until)}</div>
  {:else if state.kind === 'network'}
    <div class="note">offline</div>
  {:else}
    <div class="note">unknown</div>
  {/if}
</div>

<style>
  .account { padding: .35em 0; }
  /* Stale dims every piece of text in the row — name, age, note, and the bar
     row's label, percent and reset time. The bar glyphs keep full-strength
     colour: a stale 95% must still read as red (§8.1 annotates the stale row
     "entire row dimmed"; §7.3 asks for dimming and names no number).

     These opacities are lower than each element's own base value on purpose.
     An earlier version set .7 here, which was a no-op for `.reset` (already .7)
     and a 5% change for `.label` (.75), because a `.account.stale :global(.x)`
     selector is more specific than the element's own rule and therefore
     *replaces* its opacity instead of multiplying with it. A stale 38% then
     shipped pixel-for-pixel as bright as a live one.

     The values are the dimmest that still clear WCAG against the worst-case
     composited background. The widget is rgba(20,20,24,.88), so over a white
     desktop — the brightest backdrop, and therefore the lowest contrast for
     light text — it composites to rgb(48,48,52). Against that, #e5e7eb at
     .58 measures 4.67:1 (AA for the account name), at .5 measures 3.90:1 and
     at .45 measures 3.42:1 (both above the 3:1 floor for the secondary text).
     Any darker backdrop only raises these. */
  .account.stale .name,
  .account.stale .age { opacity: .58; }
  .account.stale .note { opacity: .5; }
  .account.stale :global(.label),
  .account.stale :global(.pct),
  .account.stale :global(.reset) { opacity: .45; }
  .head { display: flex; justify-content: space-between; align-items: baseline; gap: .5em; }
  .name { font-size: 11px; font-weight: 600; white-space: nowrap;
          overflow: hidden; text-overflow: ellipsis; }
  .age  { font-size: 10px; opacity: .8; white-space: nowrap; }
  .note { font-size: 11px; opacity: .85; padding: .15em 0; }
  .note.small { font-size: 10px; opacity: .7; }
  .action { background: none; border: none; color: #f87171; cursor: pointer;
            padding: .15em 0; font: inherit; }
</style>
