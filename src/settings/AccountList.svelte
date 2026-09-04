<script lang="ts">
  import { untilHhMm } from '../lib/format'
  import { providerName } from '../lib/provider'
  import { accountKey } from '../lib/types'
  import type { AccountView, Provider } from '../lib/types'

  /**
   * Display only, like `src/widget/AccountRow.svelte`: no IPC lives here, only
   * callbacks reported upwards. `Settings.svelte` owns every command, which is
   * what lets this component be rendered from plain props in a test.
   *
   * Every callback below carries `provider` alongside the id: the primary key
   * is the pair (§9.3), and a row that reported only its id would leave the
   * parent to guess the provider by searching its own list for that id — the
   * exact ambiguity that collapses two accounts sharing an id into "whichever
   * sorts first".
   */
  export let accounts: AccountView[] = []
  export let onRemove: (accountId: string, provider: Provider) => void = () => {}
  export let onRename: (accountId: string, provider: Provider, label: string) => void = () => {}
  export let onMove: (accountId: string, provider: Provider, delta: number) => void = () => {}
  export let onRefresh: (
    accountId: string,
    provider: Provider,
  ) => void | Promise<void> = () => {}
  /**
   * §6.4's refusal, keyed by `accountKey(account_id, provider)`: the instant a
   * manual refresh may next fire, for each account whose last "Refresh now"
   * was refused. A map rather than a single value because the refusal is
   * per-account — with three accounts, one line above the list cannot say
   * which row was refused. Keyed by the pair, not the bare id, for the same
   * reason the `{#each}` below is: two accounts sharing an id under different
   * providers must not share one refusal note.
   *
   * It is **not** derived from `AccountView.state`: `refresh_account` returns
   * §6.2's refusal early, without touching the scheduler, so re-reading the
   * list races the state it would have to read back. It exists in that
   * command's return value at the moment of the press, which is why the parent
   * hands it down separately.
   */
  export let throttledUntil: Record<string, string> = {}

  /** Per-row single-flight for §6.4's network-bearing manual refresh. */
  let refreshing: Record<string, boolean> = {}

  async function refresh(account: AccountView): Promise<void> {
    const key = accountKey(account.account_id, account.provider)
    if (account.state.kind === 'auth_dead' || refreshing[key]) return
    refreshing = { ...refreshing, [key]: true }
    try {
      await onRefresh(account.account_id, account.provider)
    } finally {
      const next = { ...refreshing }
      delete next[key]
      refreshing = next
    }
  }
</script>

<ul class="rows">
  <!-- Keyed by the (provider, account_id) pair, never by the bare id or by
       index: `accounts://changed` replaces this array wholesale, an index key
       would move a half-typed label onto the wrong account, and a bare-id key
       collides — a Svelte `each_key_duplicate` error, not a silent mis-render —
       the moment two providers share an id. AGENTS.md: the primary key is the
       pair. -->
  {#each accounts as a, i (accountKey(a.account_id, a.provider))}
    {@const provider = providerName(a.provider)}
    {@const busy = refreshing[accountKey(a.account_id, a.provider)] ?? false}
    {@const refreshBlocked = a.state.kind === 'auth_dead'}
    {@const remedyId = `refresh-remedy-${i}`}
    <li class="row">
      <div class="ident">
        <!-- `value=` rather than `bind:value=`: binding would write through
             into the parent's array, so a rename the backend rejected would
             stay on screen anyway. The parent re-reads the list instead. -->
        <input
          class="label"
          type="text"
          aria-label={`Display name for ${provider} account ${a.email}`}
          value={a.label}
          on:blur={(e) => onRename(a.account_id, a.provider, e.currentTarget.value)}
        />
        <!-- §9.3: labels and emails are display-only and may be duplicated.
             Keep the product name visible so a Claude and Codex account never
             become indistinguishable when both of those strings match. -->
        <span class="meta">
          <span class="provider" aria-label={`Provider: ${provider}`}>{provider}</span>
          <span class="email">{a.email}</span>
        </span>
        <!-- §6.4's exact wording for a refused manual refresh, in its own
             quiet class rather than the parent's `.warn` banner: it is normal,
             expected behaviour — §6.2's server-ordered wait being obeyed — and
             painting it as an error would be its own confidently-wrong
             display. The clock string comes from the shared formatter so this
             window and the widget cannot drift on it.

             `role="status"` because this is the only answer a press gets: a
             refused button is otherwise inert until `Retry-After` runs out,
             which is the defect this note exists to fix. -->
        <!-- AUTH_DEAD outranks a remembered refusal: re-login is now the only
             remedy, and this row can no longer make the later press that would
             otherwise retire the old note. -->
        {#if !refreshBlocked && throttledUntil[accountKey(a.account_id, a.provider)]}
          <span class="throttle" role="status">
            throttled, available after {untilHhMm(throttledUntil[accountKey(a.account_id, a.provider)])}
          </span>
        {/if}
        {#if refreshBlocked}
          <span class="remedy" id={remedyId}>
            Re-login with Add {provider} account below.
          </span>
        {/if}
      </div>
      <div class="actions">
        <button
          type="button"
          aria-label={`${busy ? 'Refreshing' : 'Refresh'} ${provider} account ${a.label}`}
          aria-describedby={refreshBlocked ? remedyId : undefined}
          aria-busy={busy}
          disabled={busy || refreshBlocked}
          on:click={() => refresh(a)}>{busy ? 'Refreshing…' : 'Refresh now'}</button>
        <!-- A direction, not an index: the parent rebuilds the whole (provider,
             account_id) key array for `reorder_accounts`, and an index captured
             at render time goes stale as soon as the list is re-read. -->
        <button
          type="button"
          aria-label={`Move ${provider} account ${a.label} up`}
          disabled={i === 0}
          on:click={() => onMove(a.account_id, a.provider, -1)}>
          Move up
        </button>
        <button
          type="button"
          aria-label={`Move ${provider} account ${a.label} down`}
          disabled={i === accounts.length - 1}
          on:click={() => onMove(a.account_id, a.provider, 1)}
        >
          Move down
        </button>
        <button
          class="danger"
          type="button"
          aria-label={`Remove ${provider} account ${a.label}`}
          on:click={() => onRemove(a.account_id, a.provider)}>Remove</button>
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
  .row { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap;
         gap: .75em; padding: .5em 0; border-bottom: 1px solid rgba(148, 163, 184, .25); }
  .ident { display: flex; flex: 1 1 14em; flex-direction: column; gap: .2em; min-width: 0; }
  .label { font: inherit; font-weight: 600; padding: .2em .35em; }
  .meta { display: flex; align-items: baseline; gap: .45em; min-width: 0; }
  /* Neutral by design: provider is encoded in text, while colour remains
     reserved for quota severity and warnings. */
  .provider { flex-shrink: 0; font-size: 10px; font-weight: 700; letter-spacing: .03em;
              border: 1px solid currentColor; border-radius: 3px;
              padding: 0 .35em; line-height: 1.4; }
  .email { font-size: 11px; opacity: .7; overflow: hidden; text-overflow: ellipsis;
           white-space: nowrap; }
  /* Deliberately not `.warn`'s amber: a throttle is expected behaviour, not a
     failure. Same size as `.email` so the row keeps one secondary tier.
     No `nowrap`/`ellipsis` pair here, unlike `.email` above: `.ident` is
     `min-width: 0`, so clipping this line would cut the clock time off the end
     — the one piece of it the user needs. Wrapping is the safe overflow. */
  .throttle { font-size: 11px; opacity: .85; }
  .remedy { font-size: 11px; color: #f87171; }
  .actions { display: flex; flex: 1 1 auto; justify-content: flex-end;
             flex-wrap: wrap; gap: .35em; }
  .actions button { font: inherit; font-size: 11px; padding: .25em .5em; cursor: pointer; }
  .actions button:disabled { cursor: default; opacity: .5; }
  .actions button:focus-visible,
  .label:focus-visible { outline: 2px solid currentColor; outline-offset: 2px; }
  .danger { color: #f87171; }
</style>
