<script lang="ts">
  import { onDestroy } from 'svelte'
  import AccountRow from './AccountRow.svelte'
  import { enableDrag } from '../lib/ipc'
  import type { AccountView, Provider } from '../lib/types'

  export let accounts: AccountView[] = []
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
</script>

<!-- The whole card is the drag handle, not just the titlebar: at 19px tall and
     inset 8px from the top edge, the titlebar is a poor handle for a window
     that is meant to be nudged out of the way. `enableDrag`'s
     `closest('button, a, input')` guard is what keeps the gear and the row
     remedies clickable inside it. docs/design.md §8.3. -->
<div class="widget" use:enableDrag>
  <div class="titlebar">
    <button class="gear" title="Settings" on:click={onOpenSettings}>⚙</button>
  </div>
  {#each accounts as a (a.account_id)}
    <AccountRow
      account={a}
      {now}
      onRelogin={() => onRelogin(a.account_id)}
      onUnlock={() => onUnlock(a.account_id)}
      onRefresh={() => onRefresh(a.account_id, a.provider)}
    />
  {/each}
  {#if warning}
    <!-- Never both, and never the empty state instead of this: an unreadable
         account file produces an empty list, and telling that user to add an
         account is the confidently-wrong display this project treats as its
         worst failure mode. -->
    <div class="empty warn">{warning}</div>
  {:else if accounts.length === 0}
    <div class="empty">Add an account in Settings</div>
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
  .titlebar { display: flex; justify-content: flex-end; height: 1.2em; }
  .gear { background: none; border: none; color: #9ca3af; cursor: pointer;
          font-size: 12px; padding: 0; line-height: 1; }
  .gear:hover { color: #e5e7eb; }
  .empty { font-size: 11px; opacity: .6; padding: .5em 0; }
  .empty.warn { color: #fbbf24; opacity: .9; }
</style>
