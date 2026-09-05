<script lang="ts">
  import Bar from './Bar.svelte'
  import CreditLine from './CreditLine.svelte'
  import ResetCreditsLine from './ResetCreditsLine.svelte'
  import { relativeAge, untilHhMm } from '../lib/format'
  import { providerName } from '../lib/provider'
  import type { AccountView } from '../lib/types'

  export let account: AccountView
  export let now: Date = new Date()
  export let onRelogin: () => void = () => {}
  export let onUnlock: () => void = () => {}
  /**
   * §6.4's manual refresh, on the row the user is already looking at. Returning
   * a promise is optional but is what drives `busy` below; a caller that
   * returns nothing simply never disables the button.
   */
  export let onRefresh: () => void | Promise<void> = () => {}

  /**
   * True from the press until the refresh it started settles. It exists because
   * `refresh_account` waits for §6.1's global permit rather than giving up when
   * the polling loop holds it, so a press can legitimately take a while — and
   * on a row with nothing else to show, an undisabled button gives no sign the
   * click landed at all.
   *
   * Local to the component on purpose. The alternative — a uuid-keyed pending
   * map in `widgetProps` — would put per-row transient state in the box that
   * `usage://updated` replaces wholesale.
   */
  let busy = false

  async function refresh(): Promise<void> {
    // Not merely `disabled`: the guard is what makes a second press cost
    // nothing even if the button is somehow reachable.
    if (busy) return
    busy = true
    try {
      await onRefresh()
    } finally {
      // `finally`, so a rejected refresh does not leave the row's only control
      // disabled for the life of the widget.
      busy = false
    }
  }

  $: provider = providerName(account.provider)
  $: refreshLabel = `${busy ? 'Refreshing' : 'Refresh'} ${provider} account ${account.label}`

  $: state = account.state
  // Spec §5.3: the weekly window count is 0, 1 or N — never assumed.
  $: windows = state.kind === 'ok' || state.kind === 'stale' ? state.windows : []
  /**
   * §5.3's read order is Anthropic's; Codex has no counterpart, so a plan
   * simply has the windows it has. Ungated, this note appears on every Codex
   * row forever.
   *
   * `weekly` rather than a test on `window_id`, so the one definition of
   * "weekly" lives in the parser that read the response — the same field
   * §8.6's auto sort orders by. A name test would also have to know that
   * Anthropic's per-model windows are `weekly:<model>` and Codex's is
   * `secondary` only on some plans; see `UsageWindow::weekly` in
   * `crates/core/src/model.rs`.
   *
   * **`undefined` is not `false` here.** A snapshot cached before the field
   * existed comes back with the flag missing, and that means the weekliness
   * was not recorded — not that there is no weekly window. Claiming "weekly
   * not reported" from a missing flag would be the confidently-wrong display
   * AGENTS.md forbids, for the minutes between a restart and the first poll.
   */
  $: weeklyRecorded = windows.every((w) => w.weekly !== undefined)
  $: hasWeekly =
    account.provider !== 'anthropic' || !weeklyRecorded || windows.some((w) => w.weekly)
  /**
   * Absent whenever the account has nothing to put under its bars — an
   * Anthropic account with no spending limit, or a Codex account with no reset
   * credits. Both are the common case, and both are silence, **never a
   * zero**: `usage::anthropic::parse_credit` and
   * `usage::openai::parse_reset_credits` both answer `None` rather than a
   * figure computed from a $0.00/zero-credit response, which is the
   * demote-to-0% AGENTS.md forbids. It is also absent for the first poll
   * after a restart, because the snapshot cache does not persist a figure it
   * cannot date (see `Entry::last_extra`).
   */
  $: extra = state.kind === 'ok' || state.kind === 'stale' ? state.extra : null
  $: isStale = state.kind === 'stale'
</script>

<div class="account" class:stale={isStale}>
  <div class="head">
    <!-- No provider badge. The product name is on the column head in
         `Widget.svelte` now, where it is announced once as the column's
         accessible name instead of once per row — and at half the widget's
         width the account name needs the track the badge used to take.
         docs/design.md §8.1. -->
    <span class="name" title={account.label}>{account.label}</span>
    {#if isStale && state.kind === 'stale'}
      <span class="age">{relativeAge(new Date(state.fetched_at), now)}</span>
    {/if}
    <!-- Outside the display-state branches below because every *recoverable*
         state can use it. AUTH_DEAD is the one exception: the core must not
         retry a dead grant and the row already carries its re-login remedy.
         `aria-label` rather than visible text because the glyph is the whole
         control at this size; the name matches the settings window's button
         verbatim so the two cannot drift. `enableDrag` in Widget.svelte skips
         `closest('button')`, which is what keeps this clickable inside a card
         that is itself the drag handle. -->
    {#if state.kind !== 'auth_dead'}
      <button
        class="refresh"
        class:busy
        type="button"
        aria-label={refreshLabel}
        aria-busy={busy}
        title={busy ? 'Refreshing…' : 'Refresh now'}
        disabled={busy}
        on:click={refresh}>↻</button>
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
    {#if extra?.kind === 'credit'}
      <CreditLine credit={extra} />
    {:else if extra?.kind === 'reset_credits'}
      <ResetCreditsLine credits={extra} />
    {/if}
  {:else if state.kind === 'loading'}
    <div class="note" role="status">loading…</div>
  {:else if state.kind === 'auth_expired'}
    <!-- §7.1 calls this "loading", but a permanent failure that renders
         byte-identical to the spinner is the confusion it warns about, so the
         three waiting-shaped states each say something different. -->
    <div class="note" role="status">refreshing…</div>
  {:else if state.kind === 'auth_dead'}
    <!-- §7.1: the click is this state's only remedy, so the parent must be
         able to hear it. -->
    <button
      class="note action"
      type="button"
      aria-label={`Re-login ${provider} account ${account.label}`}
      on:click={onRelogin}>re-login required</button>
  {:else if state.kind === 'oauth_not_allowed'}
    <!-- No `action` button. §7.1 makes the click a state's remedy, and the two
         remedies this app could offer are both wrong here: re-login is refused
         again, and there is nothing to unlock. The account fixes itself once
         the cause is resolved, so the row says what happened and waits.
         Wording avoids the wire code's word "organization": the case observed
         was a lapsed subscription on an ordinary personal account. -->
    <div class="note">access not available</div>
  {:else if state.kind === 'secrets_locked'}
    <button
      class="note action"
      type="button"
      aria-label={`Unlock ${provider} account ${account.label}`}
      on:click={onUnlock}>unlock</button>
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
  /* Every one of `.head`'s text children belongs in this group. One left out
     lights up at full strength inside an otherwise dimmed row — the shipped
     bug this file's own history records, which is why `.badge` was listed here
     until the badge moved to the column head. */
  .account.stale .name,
  .account.stale .age { opacity: .58; }
  .account.stale .note { opacity: .5; }
  .account.stale :global(.label),
  .account.stale :global(.pct),
  /* `.amounts` belongs in this list for the same reason `.reset` does: it is
     CreditLine's third column and shares `.reset`'s .7 base opacity, so leaving
     it out would light the money up at full strength inside an otherwise dimmed
     row. */
  .account.stale :global(.amounts),
  .account.stale :global(.reset) { opacity: .45; }
  .head { display: flex; justify-content: space-between; align-items: baseline; gap: .5em; }
  /* `flex: 1` so the name takes the slack and the age and the refresh button
     sit together against the right edge. Without it, `space-between` spreads
     three children evenly and strands the age in the middle of the row.
     `min-width: 0` is what still lets the name ellipsise: a flex item's default
     `min-width: auto` refuses to shrink below its content. */
  .name { flex: 1; min-width: 0;
          font-size: 11px; font-weight: 600; white-space: nowrap;
          overflow: hidden; text-overflow: ellipsis; }
  .age  { font-size: 10px; opacity: .8; white-space: nowrap; }
  /* Deliberately matched to `.gear` in Widget.svelte — same colour, same hover,
     same borderless glyph. They are the widget's only two chrome controls and
     must read as one family. `flex-shrink: 0` keeps it whole when a long
     account name squeezes the row. */
  .refresh { flex-shrink: 0; background: none; border: none; color: #9ca3af;
             cursor: pointer; font-size: 11px; padding: 0; line-height: 1; }
  .refresh:hover:not(:disabled) { color: #e5e7eb; }
  .refresh:focus-visible,
  .action:focus-visible { outline: 1px solid currentColor; outline-offset: 2px; border-radius: 2px; }
  .refresh:disabled { cursor: default; }
  .refresh.busy { animation: spin 900ms linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  /* On a `network` or `loading` row the spin is the *only* evidence the press
     landed, so reduced motion substitutes a dim rather than removing the
     feedback outright. */
  @media (prefers-reduced-motion: reduce) {
    .refresh.busy { animation: none; opacity: .5; }
  }
  .note { font-size: 11px; opacity: .85; padding: .15em 0; }
  .note.small { font-size: 10px; opacity: .7; }
  .action { background: none; border: none; color: #f87171; cursor: pointer;
            padding: .15em 0; font: inherit; }
</style>
