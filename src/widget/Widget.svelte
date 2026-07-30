<script lang="ts">
  import { onDestroy } from 'svelte'
  import AccountRow from './AccountRow.svelte'
  import type { AccountView } from '../lib/types'

  export let accounts: AccountView[] = []
  export let onOpenSettings: () => void = () => {}
  // §7.1 makes clicking these the only remedy AUTH_DEAD and SECRETS_LOCKED
  // have, so the row's callbacks must reach the mount site rather than stop
  // here. Keyed by uuid, never by email or label: the account primary key is
  // `account.uuid`. Task 17 supplies the handlers (OAuth restart, unlock
  // prompt); this task only guarantees the seam is unbroken.
  export let onRelogin: (uuid: string) => void = () => {}
  export let onUnlock: (uuid: string) => void = () => {}

  // Re-render relative times once a minute. This never refetches, and a minute is the
  // finest unit relativeAge and formatReset can show, so a faster tick paints nothing new.
  let now = new Date()
  const tick = setInterval(() => (now = new Date()), 60_000)
  onDestroy(() => clearInterval(tick))
</script>

<div class="widget">
  <div class="titlebar" data-drag>
    <button class="gear" title="Settings" on:click={onOpenSettings}>⚙</button>
  </div>
  {#each accounts as a (a.uuid)}
    <AccountRow
      account={a}
      {now}
      onRelogin={() => onRelogin(a.uuid)}
      onUnlock={() => onUnlock(a.uuid)}
    />
  {/each}
  {#if accounts.length === 0}
    <div class="empty">Add an account in Settings</div>
  {/if}
</div>

<style>
  /* border-box + width:100% is load-bearing: with `width: 280px` the .7em side
     padding pushed the border-box to 302.4px inside a 280px non-resizable
     window, and the reset column fell off the right edge. The background lives
     here and nowhere else — painting :root, html or body would defeat the
     window's transparency (see src/app.css). */
  .widget { box-sizing: border-box; width: 100%; padding: .5em .7em .7em;
            background: rgba(20, 20, 24, .88); color: #e5e7eb;
            border-radius: 10px; backdrop-filter: blur(8px);
            font-family: system-ui, sans-serif; }
  .titlebar { display: flex; justify-content: flex-end; height: 1.2em; cursor: grab; }
  .gear { background: none; border: none; color: #9ca3af; cursor: pointer;
          font-size: 12px; padding: 0; line-height: 1; }
  .gear:hover { color: #e5e7eb; }
  .empty { font-size: 11px; opacity: .6; padding: .5em 0; }
</style>
