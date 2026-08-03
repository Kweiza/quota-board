<script lang="ts">
  import { untilHhMm } from '../lib/format'
  import type { AccountView } from '../lib/types'

  /**
   * Display only, like `src/widget/AccountRow.svelte`: no IPC lives here, only
   * callbacks reported upwards. `Settings.svelte` owns every command, which is
   * what lets this component be rendered from plain props in a test.
   */
  export let accounts: AccountView[] = []
  export let onRemove: (uuid: string) => void = () => {}
  export let onRename: (uuid: string, label: string) => void = () => {}
  export let onMove: (uuid: string, delta: number) => void = () => {}
  export let onRefresh: (uuid: string) => void = () => {}
  /**
   * §6.4's refusal, keyed by uuid: the instant a manual refresh may next fire,
   * for each account whose last "Refresh now" was refused. A map rather than a
   * single value because the refusal is per-account — with three accounts, one
   * line above the list cannot say which row was refused.
   *
   * It is **not** derived from `AccountView.state`: `refresh_account` returns
   * §6.2's refusal early, without touching the scheduler, so re-reading the
   * list races the state it would have to read back. It exists in that
   * command's return value at the moment of the press, which is why the parent
   * hands it down separately.
   */
  export let throttledUntil: Record<string, string> = {}
</script>

<ul class="rows">
  <!-- Keyed by account_id, never by index: `accounts://changed` replaces this
       array wholesale, and an index key would move a half-typed label onto the
       wrong account. CLAUDE.md: the primary key is the (provider, account_id)
       pair — `account_id` alone is what this list's own callbacks are keyed
       by, since `Settings.svelte` resolves the provider itself. -->
  {#each accounts as a, i (a.account_id)}
    <li class="row">
      <div class="ident">
        <!-- `value=` rather than `bind:value=`: binding would write through
             into the parent's array, so a rename the backend rejected would
             stay on screen anyway. The parent re-reads the list instead. -->
        <input
          class="label"
          type="text"
          aria-label="Display name"
          value={a.label}
          on:blur={(e) => onRename(a.account_id, e.currentTarget.value)}
        />
        <!-- §9.3: the label is user-editable and may be duplicated, so this is
             the only thing left that tells two accounts apart. -->
        <span class="email">{a.email}</span>
        <!-- §6.4's exact wording for a refused manual refresh, in its own
             quiet class rather than the parent's `.warn` banner: it is normal,
             expected behaviour — §6.2's server-ordered wait being obeyed — and
             painting it as an error would be its own confidently-wrong
             display. The clock string comes from the shared formatter so this
             window and the widget cannot drift on it.

             `role="status"` because this is the only answer a press gets: a
             refused button is otherwise inert until `Retry-After` runs out,
             which is the defect this note exists to fix. -->
        {#if throttledUntil[a.account_id]}
          <span class="throttle" role="status">
            throttled, available after {untilHhMm(throttledUntil[a.account_id])}
          </span>
        {/if}
      </div>
      <div class="actions">
        <button on:click={() => onRefresh(a.account_id)}>Refresh now</button>
        <!-- A direction, not an index: the parent rebuilds the whole (provider,
             account_id) key array for `reorder_accounts`, and an index captured
             at render time goes stale as soon as the list is re-read. -->
        <button disabled={i === 0} on:click={() => onMove(a.account_id, -1)}>Move up</button>
        <button disabled={i === accounts.length - 1} on:click={() => onMove(a.account_id, 1)}>
          Move down
        </button>
        <button class="danger" on:click={() => onRemove(a.account_id)}>Remove</button>
      </div>
    </li>
  {/each}
</ul>

<style>
  /* Every rule is scoped under this component's own elements. Svelte bundles
     all component styles into one stylesheet that **both** windows load, so a
     `:global(body)` rule here would paint the transparent widget window too
     (src/app.css carries the same warning). */
  .rows { list-style: none; margin: 0; padding: 0; }
  .row { display: flex; align-items: center; justify-content: space-between;
         gap: .75em; padding: .5em 0; border-bottom: 1px solid rgba(148, 163, 184, .25); }
  .ident { display: flex; flex-direction: column; gap: .2em; min-width: 0; }
  .label { font: inherit; font-weight: 600; padding: .2em .35em; }
  .email { font-size: 11px; opacity: .7; overflow: hidden; text-overflow: ellipsis;
           white-space: nowrap; }
  /* Deliberately not `.warn`'s amber: a throttle is expected behaviour, not a
     failure. Same size as `.email` so the row keeps one secondary tier.
     No `nowrap`/`ellipsis` pair here, unlike `.email` above: `.ident` is
     `min-width: 0`, so clipping this line would cut the clock time off the end
     — the one piece of it the user needs. Wrapping is the safe overflow. */
  .throttle { font-size: 11px; opacity: .85; }
  .actions { display: flex; gap: .35em; flex-shrink: 0; }
  .actions button { font: inherit; font-size: 11px; padding: .25em .5em; cursor: pointer; }
  .actions button:disabled { cursor: default; opacity: .5; }
  .danger { color: #f87171; }
</style>
