<script lang="ts">
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
</script>

<ul class="rows">
  <!-- Keyed by uuid, never by index: `accounts://changed` replaces this array
       wholesale, and an index key would move a half-typed label onto the wrong
       account. CLAUDE.md: the primary key is `account.uuid`. -->
  {#each accounts as a, i (a.uuid)}
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
          on:blur={(e) => onRename(a.uuid, e.currentTarget.value)}
        />
        <!-- §9.3: the label is user-editable and may be duplicated, so this is
             the only thing left that tells two accounts apart. -->
        <span class="email">{a.email}</span>
      </div>
      <div class="actions">
        <button on:click={() => onRefresh(a.uuid)}>Refresh now</button>
        <!-- A direction, not an index: the parent rebuilds the whole uuid array
             for `reorder_accounts`, and an index captured at render time goes
             stale as soon as the list is re-read. -->
        <button disabled={i === 0} on:click={() => onMove(a.uuid, -1)}>Move up</button>
        <button disabled={i === accounts.length - 1} on:click={() => onMove(a.uuid, 1)}>
          Move down
        </button>
        <button class="danger" on:click={() => onRemove(a.uuid)}>Remove</button>
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
  .actions { display: flex; gap: .35em; flex-shrink: 0; }
  .actions button { font: inherit; font-size: 11px; padding: .25em .5em; cursor: pointer; }
  .actions button:disabled { cursor: default; opacity: .5; }
  .danger { color: #f87171; }
</style>
