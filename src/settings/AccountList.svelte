<script lang="ts">
  import { untilHhMm } from '../lib/format'
  import { providerName } from '../lib/provider'
  import { moveTo } from '../lib/reorder'
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
  /**
   * Which column this is. docs/design.md §8.4 renders one of these per
   * provider, so `accounts` is already filtered to it — but the value is still
   * passed rather than read off `accounts[0]`, because an empty column has no
   * first row and still has to name itself.
   */
  export let provider: Provider
  export let onRemove: (accountId: string, provider: Provider) => void = () => {}
  export let onRename: (accountId: string, provider: Provider, label: string) => void = () => {}
  /**
   * The whole rearranged order of **this column**, as account ids.
   *
   * Ids rather than a from/to pair: the parent has to fold this column back
   * into the full (provider, account_id) array that `reorder_accounts` takes,
   * and an index captured at render time goes stale as soon as the list is
   * re-read. It is the same reason the Move up/down buttons this replaced
   * reported a direction rather than an index.
   */
  export let onReorder: (provider: Provider, orderedIds: string[]) => void = () => {}
  export let onRefresh: (
    accountId: string,
    provider: Provider,
  ) => void | Promise<void> = () => {}
  /**
   * False while §8.6's auto sort owns the order. Dragging is then disabled
   * rather than silently discarded: the list on screen is not the stored
   * arrangement, so a drop would either be thrown away or would rewrite the
   * arrangement to match a computed order the user never chose.
   */
  export let reorderable = true
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

  /**
   * The id being dragged, and the id it is currently over.
   *
   * Both are ids rather than indices for the same reason `onReorder` reports
   * ids: `accounts://changed` replaces the array wholesale mid-drag, and an
   * index would then point at a different account than the one under the
   * pointer.
   */
  let draggingId: string | null = null
  let overId: string | null = null
  /**
   * Which row's handle the pointer went down on.
   *
   * **`draggable` is armed by the handle rather than left on permanently.** The
   * row contains the rename field, and a permanently draggable ancestor takes
   * the press that would otherwise place the caret or select text in it — so
   * renaming an account would stop working in exchange for a drag the handle
   * already offers. `mousedown` fires before `dragstart`, which is what leaves
   * Svelte a turn to set the attribute.
   *
   * **Nothing may clear this between the press and `dragstart`.** v0.4.0 shipped
   * an `on:blur` on the handle that did, and WebKit blurs the focused element
   * when a drag begins — before `dragstart`. The row therefore stopped being
   * draggable in that instant, WebKit started a selection drag instead of an
   * element drag, and the release did nothing. Measured in Playwright WebKit
   * 26.6: the entire trace was `focus`, `blur`, silence. Chromium never fires
   * that blur, so every automated check and every look in Chrome passed.
   *
   * The `draggable` binding therefore reads `armedId === id || draggingId ===
   * id`, and the second half is not redundant: it holds the attribute true for
   * the whole life of the drag, so no later state change can take `draggable`
   * away from an element the engine is already dragging.
   */
  let armedId: string | null = null

  /** Each row's drag handle, by account id. See `handleKey`'s refocus. */
  let handles: Record<string, HTMLButtonElement | null> = {}

  function beginDrag(event: DragEvent, id: string): void {
    if (!reorderable || armedId !== id) {
      // A drag that did not start on the handle — a text selection escaping the
      // rename field, say. Refusing it here is what keeps `draggingId` null so
      // every handler below is inert.
      event.preventDefault()
      return
    }
    draggingId = id
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = 'move'
      // Firefox starts no drag at all unless some data is set. The value is
      // never read back: `draggingId` is the source of truth, because a drop
      // from another window would carry a string this list knows nothing about.
      event.dataTransfer.setData('text/plain', id)
    }
  }

  function dragOver(event: DragEvent, id: string): void {
    if (draggingId === null) return
    // Both of these are required to make the row a drop target at all: without
    // `preventDefault` on dragover the browser cancels the drop, and the row
    // never reports being hovered.
    event.preventDefault()
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'move'
    overId = id
  }

  function drop(event: DragEvent, id: string): void {
    if (draggingId === null) return
    event.preventDefault()
    const ids = accounts.map((a) => a.account_id)
    const next = moveTo(ids, ids.indexOf(draggingId), ids.indexOf(id))
    endDrag()
    // `moveTo` answers with the same array for a no-op, which is the cheap way
    // to keep a drop on the row's own position from writing to disk.
    if (next !== ids) onReorder(provider, next)
  }

  function endDrag(): void {
    draggingId = null
    overId = null
    armedId = null
  }

  /**
   * The keyboard route, which exists because the Move up/down buttons no longer
   * do. Dragging is a pointer gesture with no keyboard equivalent, so without
   * this a keyboard-only user could not reorder at all — and the buttons were
   * the only way they ever could.
   *
   * `Alt` is held so the bare arrow keys keep moving focus through the list.
   */
  function handleKey(event: KeyboardEvent, id: string): void {
    if (!reorderable || !event.altKey) return
    const delta = event.key === 'ArrowUp' ? -1 : event.key === 'ArrowDown' ? 1 : 0
    if (delta === 0) return
    const ids = accounts.map((a) => a.account_id)
    const from = ids.indexOf(id)
    const next = moveTo(ids, from, from + delta)
    if (next === ids) return
    // Only once the move is real: an Alt+Down on the last row must still reach
    // the browser as an ordinary keystroke.
    event.preventDefault()
    onReorder(provider, next)
    const handle = handles[id]
    queueMicrotask(() => handle?.focus())
    // The keyed `{#each}` *moves* this button rather than recreating it, and a
    // node moved with `insertBefore` is removed and reinserted, which blurs it.
    // Without this, one Alt+Down works and the second has nothing focused to
    // act on. Held by reference rather than looked up by selector: an account
    // id is server-issued (`user-…` on the Codex side) and would need
    // `CSS.escape`, which jsdom does not implement — so a selector would also
    // put this line beyond the reach of its own test.
  }
</script>

<ul class="rows">
  <!-- Keyed by the (provider, account_id) pair, never by the bare id or by
       index: `accounts://changed` replaces this array wholesale, an index key
       would move a half-typed label onto the wrong account, and a bare-id key
       collides — a Svelte `each_key_duplicate` error, not a silent mis-render —
       the moment two providers share an id. AGENTS.md: the primary key is the
       pair.

       The key stays the pair even though this list holds one provider: the
       component does not enforce that its `accounts` are all `provider`'s, and
       a key that assumed so would fail loudly only in the case it was meant to
       protect. -->
  {#each accounts as a, i (accountKey(a.account_id, a.provider))}
    {@const key = accountKey(a.account_id, a.provider)}
    {@const busy = refreshing[key] ?? false}
    {@const refreshBlocked = a.state.kind === 'auth_dead'}
    {@const remedyId = `refresh-remedy-${provider}-${i}`}
    <!-- The row's own provider, not the column's. They agree for every list
         `Settings.svelte` builds, but an accessible name is a claim about this
         account, and deriving it from a prop rather than from the row would
         make it a claim about where the row happened to be rendered. -->
    {@const rowName = providerName(a.provider)}
    <li
      class="row"
      class:dragging={draggingId === a.account_id}
      class:over={overId === a.account_id && draggingId !== a.account_id}
      draggable={reorderable && (armedId === a.account_id || draggingId === a.account_id)}
      on:dragstart={(e) => beginDrag(e, a.account_id)}
      on:dragover={(e) => dragOver(e, a.account_id)}
      on:drop={(e) => drop(e, a.account_id)}
      on:dragend={endDrag}
      on:dragleave={() => {
        if (overId === a.account_id) overId = null
      }}
    >
      <!-- A real button, not a decorative glyph: it is the keyboard's only way
           into reordering now, so it has to be reachable by Tab and it has to
           say what it does. The label names both gestures because neither is
           discoverable from a `⠿`. -->
      <button
        class="handle"
        type="button"
        bind:this={handles[a.account_id]}
        disabled={!reorderable}
        aria-label={`Reorder ${rowName} account ${a.label} — drag, or hold Alt and press the up or down arrow`}
        title={reorderable
          ? 'Drag to reorder, or Alt+↑ / Alt+↓'
          : 'Turn off Sort by soonest weekly reset to reorder by hand'}
        on:mousedown={() => (armedId = a.account_id)}
        on:keydown={(e) => handleKey(e, a.account_id)}
        on:mouseup={() => (armedId = null)}>⠿</button
      >
      <div class="ident">
        <!-- `value=` rather than `bind:value=`: binding would write through
             into the parent's array, so a rename the backend rejected would
             stay on screen anyway. The parent re-reads the list instead. -->
        <input
          class="label"
          type="text"
          aria-label={`Display name for ${rowName} account ${a.email}`}
          value={a.label}
          on:blur={(e) => onRename(a.account_id, a.provider, e.currentTarget.value)}
        />
        <!-- §9.3: labels and emails are display-only and may be duplicated.
             The product name is on the column heading now rather than on every
             row, so this line carries the email alone — which is still what
             tells two accounts of the same provider apart after a rename. -->
        <span class="meta">
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
        {#if !refreshBlocked && throttledUntil[key]}
          <span class="throttle" role="status">
            throttled, available after {untilHhMm(throttledUntil[key])}
          </span>
        {/if}
        {#if refreshBlocked}
          <span class="remedy" id={remedyId}>
            Re-login with Add {rowName} account below.
          </span>
        {/if}
      </div>
      <!-- Glyphs rather than words, and the `aria-label`s keep the sentences
           the words used to be. The row is half a window wide now, and three
           text buttons on it wrapped onto their own line; the accessible names
           are unchanged, so nothing that read them before reads less. The
           refresh glyph is the widget's `↻` deliberately — the two controls do
           the same thing and must look like it. -->
      <div class="actions">
        <button
          class="icon"
          class:busy
          type="button"
          aria-label={`${busy ? 'Refreshing' : 'Refresh'} ${rowName} account ${a.label}`}
          aria-describedby={refreshBlocked ? remedyId : undefined}
          aria-busy={busy}
          title={busy ? 'Refreshing…' : 'Refresh now'}
          disabled={busy || refreshBlocked}
          on:click={() => refresh(a)}>↻</button
        >
        <button
          class="icon danger"
          type="button"
          aria-label={`Remove ${rowName} account ${a.label}`}
          title="Remove"
          on:click={() => onRemove(a.account_id, a.provider)}>✕</button
        >
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
  /* A grid, not the flex row this was: at half the window's width the three
     text buttons wrapped to a second line, and `flex-wrap` then let a long
     email push them there too. The middle track is `minmax(0, 1fr)` so the
     email ellipsises instead of widening the row. */
  .row { display: grid; grid-template-columns: auto minmax(0, 1fr) auto;
         align-items: center; gap: .5em; padding: .5em 0;
         border-bottom: 1px solid rgba(148, 163, 184, .25); }
  /* The row being dragged stays visible but recedes; the row under the pointer
     shows where the drop lands. Both are opacity and a border — not colour —
     because §8.2 reserves the colour channel for severity and warnings. */
  .row.dragging { opacity: .4; }
  .row.over { border-bottom-color: currentColor; box-shadow: inset 0 2px 0 currentColor; }
  /* `align-self: stretch` makes the whole left edge of the row the grab target
     rather than the glyph's own box. Measured: the glyph alone came to
     12.8×18.2px, against 22.1px square for the icon buttons beside it — the
     smallest target in the row was the one the row's main new gesture depends
     on. Stretched it is the row's full height. */
  .handle { align-self: stretch; display: flex; align-items: center;
            justify-content: center; min-width: 1.7em;
            background: none; border: none; color: inherit; opacity: .55;
            cursor: grab; font-size: 14px; line-height: 1; padding: 0; }
  .handle:hover:not(:disabled) { opacity: .9; }
  .handle:active:not(:disabled) { cursor: grabbing; }
  .handle:disabled { cursor: default; opacity: .25; }
  .ident { display: flex; flex-direction: column; gap: .2em; min-width: 0; }
  .label { font: inherit; font-weight: 600; padding: .2em .35em; width: 100%;
           box-sizing: border-box; }
  .meta { display: flex; align-items: baseline; gap: .45em; min-width: 0; }
  .email { font-size: 11px; opacity: .7; overflow: hidden; text-overflow: ellipsis;
           white-space: nowrap; }
  /* Deliberately not `.warn`'s amber: a throttle is expected behaviour, not a
     failure. Same size as `.email` so the row keeps one secondary tier.
     No `nowrap`/`ellipsis` pair here, unlike `.email` above: `.ident` is
     `min-width: 0`, so clipping this line would cut the clock time off the end
     — the one piece of it the user needs. Wrapping is the safe overflow. */
  .throttle { font-size: 11px; opacity: .85; }
  .remedy { font-size: 11px; color: #f87171; }
  .actions { display: flex; gap: .15em; }
  /* Sized from the glyph rather than from text: 1.7em square keeps the pointer
     target close to the 24px minimum at this font size, which a bare glyph with
     no padding would fall well under. */
  .icon { font: inherit; font-size: 13px; line-height: 1;
          min-width: 1.7em; min-height: 1.7em; padding: 0; cursor: pointer;
          background: none; border: 1px solid rgba(148, 163, 184, .35);
          border-radius: 4px; color: inherit; }
  .icon:hover:not(:disabled) { border-color: currentColor; }
  .icon:disabled { cursor: default; opacity: .5; }
  .icon.busy { animation: spin 900ms linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  /* The spin is the only sign a press on a row with no numbers landed, so
     reduced motion substitutes a dim rather than removing the feedback. Same
     treatment as the widget's own refresh glyph. */
  @media (prefers-reduced-motion: reduce) {
    .icon.busy { animation: none; opacity: .5; }
  }
  .icon:focus-visible,
  .handle:focus-visible,
  .label:focus-visible { outline: 2px solid currentColor; outline-offset: 2px; }
  .danger { color: #f87171; }
</style>
