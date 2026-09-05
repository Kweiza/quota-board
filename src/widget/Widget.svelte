<script lang="ts">
  import { onDestroy } from 'svelte'
  import AccountRow from './AccountRow.svelte'
  import { enableDrag } from '../lib/ipc'
  import { WIDGET_WIDTH_SPLIT } from '../lib/layout'
  import { PROVIDER_ORDER, accountsOf, providerName } from '../lib/provider'
  import { accountKey } from '../lib/types'
  import type { AccountView, Provider } from '../lib/types'

  export let accounts: AccountView[] = []
  /** False only until the first complete account-list read. */
  export let accountsLoaded = false
  export let warning: string | null = null
  export let onOpenSettings: () => void = () => {}
  // §7.1 makes clicking these the only remedy AUTH_DEAD and SECRETS_LOCKED
  // have, so the row's callbacks must reach the mount site rather than stop
  // here. Keyed by `account_id`, never by email or label — `provider` is the
  // other half of the primary key (§9.3), but neither of these handlers acts
  // on a specific account today; both just open the settings window, which
  // owns the re-login (`begin_login`) and the unlock prompt (`unlock_secrets`).
  export let onRelogin: (uuid: string) => void = () => {}
  export let onUnlock: (uuid: string) => void = () => {}
  /**
   * §6.4's manual refresh. Same keying rule as the two above, plus `provider`:
   * `refresh_account` acts on the (provider, id) pair, so a press on this row
   * must carry both halves, not just the id half the other two get away
   * without. The promise is passed straight through rather than swallowed:
   * `AccountRow` awaits it to disable its own button.
   */
  export let onRefresh: (uuid: string, provider: Provider) => void | Promise<void> = () => {}

  // Re-render relative times once a minute. This never refetches, and a minute is the
  // finest unit relativeAge and formatReset can show, so a faster tick paints nothing new.
  let now = new Date()
  const tick = setInterval(() => (now = new Date()), 60_000)
  onDestroy(() => clearInterval(tick))

  /**
   * §8.1's columns: Claude on the left, Codex on the right, each carrying the
   * product name once at its head instead of once per row.
   *
   * A provider with no accounts is dropped rather than rendered as an empty
   * box, so a user of one service keeps the single narrow column the widget
   * has always had. `src/lib/layout.ts` sizes the window from the same fact.
   *
   * The order inside a column is `list_accounts`' own — §8.6's auto sort has
   * already been applied over there when it is on, and re-sorting here would
   * give the widget a second opinion about an order the settings window is
   * showing at the same time.
   */
  $: columns = PROVIDER_ORDER.map((provider) => ({
    provider,
    accounts: accountsOf(accounts, provider),
  })).filter((c) => c.accounts.length > 0)
  $: split = columns.length > 1
</script>

<!-- The whole card is the drag handle, not just the titlebar: at 19px tall and
     inset 8px from the top edge, the titlebar is a poor handle for a window
     that is meant to be nudged out of the way. `enableDrag`'s
     `closest('button, a, input')` guard is what keeps the gear and the row
     remedies clickable inside it. docs/design.md §8.3. -->
<div class="widget" class:split style:--split-width={`${WIDGET_WIDTH_SPLIT}px`} use:enableDrag>
  <div class="titlebar">
    <button class="gear" type="button" aria-label="Settings" title="Settings" on:click={onOpenSettings}>⚙</button>
  </div>
  <div class="columns">
    {#each columns as column (column.provider)}
      <!-- A `section` with its heading as the accessible name, so the product
           name reaches assistive technology once per column. It used to reach
           it once per row, from a badge on every account; the badge is gone
           because at half the width the account name needs the space more,
           and repeating the same word down a column of Claude accounts told
           nobody anything. docs/design.md §8.1. -->
      <section class="column" aria-labelledby={`column-${column.provider}`}>
        <h2 class="col-head" id={`column-${column.provider}`}>{providerName(column.provider)}</h2>
        {#each column.accounts as a (accountKey(a.account_id, a.provider))}
          <AccountRow
            account={a}
            {now}
            onRelogin={() => onRelogin(a.account_id)}
            onUnlock={() => onUnlock(a.account_id)}
            onRefresh={() => onRefresh(a.account_id, a.provider)}
          />
        {/each}
      </section>
    {/each}
  </div>
  {#if warning}
    <!-- Never both, and never the empty state instead of this: an unreadable
         account file produces an empty list, and telling that user to add an
         account is the confidently-wrong display this project treats as its
         worst failure mode. -->
    <div class="empty warn">{warning}</div>
  {:else if accounts.length === 0 && !accountsLoaded}
    <div class="empty" role="status">Loading accounts…</div>
  {:else if accounts.length === 0}
    <div class="empty">Add a Claude or Codex account in Settings</div>
  {/if}
</div>

<style>
  /* border-box + width:100% is load-bearing: with `width: 280px` the .7em side
     padding pushed the border-box to 302.4px inside a 280px non-resizable
     window, and the reset column fell off the right edge. The background lives
     here and nowhere else — painting :root, html or body would defeat the
     window's transparency (see src/app.css). */
  /* user-select: none belongs with the drag: without it, dragging from an
     account name selects the text under the pointer instead. It also removes
     the double-click-selects-a-word artefact the card would otherwise have. */
  .widget { box-sizing: border-box; width: 100%; padding: .5em .7em .7em;
            background: rgba(20, 20, 24, .88); color: #e5e7eb;
            border-radius: 10px; backdrop-filter: blur(8px);
            font-family: system-ui, sans-serif;
            cursor: grab; user-select: none; }
  /* The document must lay itself out at the width the window is *about to*
     become, not the width it currently has. `followContentHeight` measures the
     rendered height and pushes it back, so without this the first frame after a
     second provider appears would measure two columns squeezed into 280px —
     every bar row wrapped, the height roughly doubled — and push that height
     back before the reflow at 520px could correct it. The value comes from
     `src/lib/layout.ts`, the same constant `src/main.ts` sizes the window with,
     passed in as a custom property so the two cannot drift. */
  .widget.split { min-width: var(--split-width); }
  .titlebar { display: flex; justify-content: flex-end; height: 1.2em; }
  /* One column collapses to a plain block; two share the width evenly.
     `minmax(0, 1fr)` rather than `1fr`: a grid track's default `auto` minimum
     refuses to shrink below its content, which is what lets an account name
     push its own column wider than half and shove the other one off the card. */
  .columns { display: grid; grid-template-columns: minmax(0, 1fr); gap: 0 1em; }
  .widget.split .columns { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .column { min-width: 0; }
  /* Deliberately quiet: this names the column, it is not a row of data. Same
     neutral treatment the row badge had — §8.2 keeps colour for severity, so
     product identity stays text. */
  .col-head { margin: .35em 0 .1em; font-size: 9px; font-weight: 700;
              letter-spacing: .08em; text-transform: uppercase; opacity: .55; }
  .gear { background: none; border: none; color: #9ca3af; cursor: pointer;
          font-size: 12px; padding: 0; line-height: 1; }
  .gear:hover { color: #e5e7eb; }
  .widget :global(button:focus-visible) {
    outline: 1px solid currentColor;
    outline-offset: 2px;
    border-radius: 2px;
  }
  .empty { font-size: 11px; opacity: .6; padding: .5em 0; }
  .empty.warn { color: #fbbf24; opacity: .9; }
</style>
