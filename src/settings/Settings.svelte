<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import type { UnlistenFn } from '@tauri-apps/api/event'
  import { openUrl } from '@tauri-apps/plugin-opener'
  import AccountList from './AccountList.svelte'
  import { queriesPerDay } from '../lib/format'
  import {
    beginLogin,
    getSettings,
    lastResponse,
    listAccounts,
    onAccountsChanged,
    onAuthFailed,
    refreshAccount,
    removeAccount,
    renameAccount,
    reorderAccounts,
    setSettings,
    storeStatus,
    unlockSecrets,
  } from '../lib/ipc'
  import type { AccountView, RawResponse, SettingsView, StoreStatus } from '../lib/types'

  /**
   * The settings window owns every command; `AccountList` only reports clicks.
   *
   * **This component must never call `setWidgetVisible` and must never register
   * a `visibilitychange` or `pageshow` handler.** Both windows load the same
   * document, so such a listener would report *this* window's visibility into
   * the widget's single polling gate — and closing the settings window is a
   * hide (`src-tauri/src/main.rs`), so closing it would stop the widget
   * polling. `src/main.ts` keeps that wiring inside its widget branch for the
   * same reason.
   */
  let accounts: AccountView[] = []
  let error: string | null = null

  let view: SettingsView | null = null
  let intervalSecs: number | null = null

  let status: StoreStatus | null = null
  let passphrase = ''
  let busy = false

  let selected = ''
  let captured: RawResponse | null = null
  /**
   * Which account `captured` belongs to; `null` until something has been
   * loaded. A single `captured === null` cannot tell "not loaded yet" from
   * "loaded, and the answer was null", and collapsing the two tells the user an
   * account has never polled before they have pressed anything — the
   * confidently-wrong display CLAUDE.md calls this product's worst failure
   * mode. Keying it by uuid rather than using a bare boolean also drops a body
   * belonging to the previously selected account.
   */
  let loadedFor: string | null = null
  $: loaded = selected !== '' && loadedFor === selected
  $: dailyCalls = queriesPerDay(intervalSecs, accounts.length)

  let unlisteners: UnlistenFn[] = []
  let destroyed = false

  async function pullAccounts(): Promise<void> {
    try {
      accounts = await listAccounts()
    } catch (e) {
      // A failed read is not a reason to blank the list; the widget branch of
      // src/main.ts set that rule and it holds here for the same reason.
      error = String(e)
    }
  }

  async function refreshStatus(): Promise<void> {
    try {
      status = await storeStatus()
    } catch (e) {
      error = String(e)
    }
  }

  /** Reports a command failure instead of letting the click vanish. */
  async function guard(run: () => Promise<unknown>): Promise<void> {
    try {
      await run()
      error = null
    } catch (e) {
      error = String(e)
    }
  }

  onMount(() => {
    void pullAccounts()
    void refreshStatus()
    void (async () => {
      try {
        view = await getSettings()
        intervalSecs = view.poll_interval_secs
      } catch (e) {
        error = String(e)
      }
    })()
    void (async () => {
      // Login finishes in the background, so without these two subscriptions a
      // completed login never reaches this window.
      const fns = [
        await onAccountsChanged(() => void pullAccounts()),
        await onAuthFailed((message) => {
          error = message
        }),
      ]
      // Closing this window is a hide, not a destroy
      // (`src-tauri/src/main.rs`), so leaked subscriptions accumulate for the
      // life of the process. If destruction won the race against `listen`,
      // release them here — `onDestroy` has already run and saw an empty array.
      if (destroyed) fns.forEach((fn) => fn())
      else unlisteners = fns
    })()
  })

  onDestroy(() => {
    destroyed = true
    unlisteners.forEach((fn) => fn())
    unlisteners = []
  })

  async function addAccount(): Promise<void> {
    // No local "pending" flag. The Rust side is the single-flight
    // (`begin_login` answers `a login is already in progress`), and a second
    // disabled state here would be the two-sources-disagree hazard §7.1 exists
    // to prevent — with the extra failure that success arrives on
    // `accounts://changed`, so a flag cleared only on `auth://failed` would
    // disable the button for the life of the process.
    try {
      await openUrl(await beginLogin())
      error = null
    } catch (e) {
      error = String(e)
    }
  }

  function rename(uuid: string, label: string): void {
    const current = accounts.find((a) => a.uuid === uuid)
    // Every blur fires this handler, including one that changed nothing.
    if (current === undefined || current.label === label) return
    void guard(() => renameAccount(uuid, label))
  }

  function move(uuid: string, delta: number): void {
    const from = accounts.findIndex((a) => a.uuid === uuid)
    const to = from + delta
    if (from < 0 || to < 0 || to >= accounts.length) return
    // The command takes the whole rearranged array, not a pair: `reorder`
    // rewrites `sort_order` from the order it is given.
    const uuids = accounts.map((a) => a.uuid)
    uuids.splice(to, 0, ...uuids.splice(from, 1))
    void guard(() => reorderAccounts(uuids))
  }

  function refresh(uuid: string): void {
    // `refresh_account` emits `usage://updated`, which only the widget listens
    // for, so this window re-reads the list itself.
    void guard(async () => {
      await refreshAccount(uuid)
      await pullAccounts()
    })
  }

  async function applyInterval(): Promise<void> {
    if (view === null || !view.writable) return
    if (intervalSecs === null) return // an emptied field is not a request
    try {
      // The Rust side clamps to §6.1's floor and answers with what it actually
      // applied. Writing that answer back is what makes the floor visible.
      view = await setSettings(intervalSecs)
      intervalSecs = view.poll_interval_secs
      error = null
    } catch (e) {
      error = String(e)
      // A refused value must not stay on screen looking applied.
      intervalSecs = view.poll_interval_secs
    }
  }

  async function unlock(): Promise<void> {
    if (busy || passphrase === '') return
    // Opening derives an Argon2id key (64 MiB, t=3) and takes about 1.4 s in a
    // debug build; every repeat click costs another blocking thread.
    busy = true
    try {
      status = await unlockSecrets(passphrase)
      error = null
    } catch (e) {
      error = String(e)
    } finally {
      // Both paths, so a rejected passphrase does not stay in the DOM.
      busy = false
      passphrase = ''
    }
  }

  async function reloadRaw(): Promise<void> {
    if (selected === '') return
    const uuid = selected
    try {
      captured = await lastResponse(uuid)
      loadedFor = uuid
      error = null
    } catch (e) {
      error = String(e)
    }
  }
</script>

<main class="settings">
  <h1>quota-board</h1>
  {#if error}
    <p class="warn" role="alert">{error}</p>
  {/if}

  <section>
    <h2>Accounts</h2>
    <AccountList {accounts} onRemove={(uuid) => void guard(() => removeAccount(uuid))}
                 onRename={rename} onMove={move} onRefresh={refresh} />
    {#if accounts.length === 0}
      <p class="hint">No accounts yet.</p>
    {/if}
    <button on:click={addAccount}>Add account</button>
    <!-- Reworded from the note on `pkce::begin` in
         `crates/core/src/auth/pkce.rs`. The two must not drift: if that comment
         changes, change this sentence. -->
    <p class="hint">
      Anthropic runs no third-party OAuth client registration program, so this
      reuses Claude Code's own public client. The consent screen will therefore
      show <strong>"Claude Code"</strong>.
    </p>
  </section>

  <section>
    <h2>Polling interval</h2>
    {#if view}
      <label for="poll-interval">Polling interval (seconds)</label>
      <input
        id="poll-interval"
        type="number"
        min={view.min_interval_secs}
        max={view.max_interval_secs}
        step="30"
        disabled={!view.writable}
        bind:value={intervalSecs}
        on:change={applyInterval}
      />
      <!-- The bounds come from `SettingsView`, never from a number written
           here: a literal would drift from `PollPolicy::MIN_INTERVAL_SECS`. -->
      <span class="hint">
        roughly {dailyCalls} queries per day (minimum {view.min_interval_secs} s)
      </span>
      {#if view.warning}<p class="warn">{view.warning}</p>{/if}
      {#if !view.writable}
        <p class="warn">
          The settings file cannot be written by this build, so the interval
          cannot be changed here.
        </p>
      {/if}
    {/if}
  </section>

  <section>
    <h2>Token store</h2>
    {#if status}
      <p class="note">{status.description}</p>
      <!-- The form's visibility is decided by `kind`, never by
           `fallback_file_exists`: on a missing file any passphrase opens an
           empty store and writes nothing, so that flag is still false right
           after the first successful unlock. It chooses the wording only. -->
      {#if status.kind === 'keychain'}
        <p class="note">Tokens are held in the OS keychain, which unlocks at login.</p>
      {:else if status.kind === 'keychain_locked'}
        <p class="warn">
          A keychain exists on this machine but did not answer. Unlock it in the
          OS and restart quota-board — a passphrase here would open a
          different, empty store.
        </p>
      {:else}
        <p class="warn">
          Values will not update until the passphrase is entered after each boot.
        </p>
        {#if !status.fallback_file_exists}
          <p class="warn">
            No encrypted store exists yet. The passphrase you enter now creates
            one — there is no way to recover it later, and accounts added before
            this will need to be added again.
          </p>
        {/if}
        <label for="passphrase">Passphrase</label>
        <input id="passphrase" type="password" bind:value={passphrase} disabled={busy} />
        <button on:click={unlock} disabled={busy || passphrase === ''}>
          {status.fallback_file_exists ? 'Unlock' : 'Set a passphrase'}
        </button>
      {/if}
    {/if}
  </section>

  <section>
    <h2>Debug</h2>
    <p class="hint">
      The body is reparsed and reserialized, so key order is normalized. Values
      that look like tokens or email addresses, and monetary amounts, are masked
      when the response is captured — not when it is displayed. A 2xx response
      that is not JSON is never captured, so the previous capture stays; that is
      what the capture time below is for.
    </p>
    <label for="debug-account">Account</label>
    <select id="debug-account" bind:value={selected}>
      <option value="">—</option>
      {#each accounts as a (a.uuid)}
        <option value={a.uuid}>{a.label} ({a.email})</option>
      {/each}
    </select>
    <button on:click={reloadRaw}>Reload</button>

    <!-- Four mutually exclusive branches. Merging any two of them would report
         a fact that has not been established. -->
    {#if accounts.length === 0}
      <p class="hint">No accounts yet, so there is nothing to inspect.</p>
    {:else if !loaded}
      <p class="hint">Select an account and press Reload.</p>
    {:else if captured === null}
      <p class="hint">This account has not been polled successfully since the app started.</p>
    {:else}
      <p class="note">
        HTTP {captured.status} · captured {captured.captured_at}{captured.truncated
          ? ' · truncated at 64 KiB'
          : ''}
      </p>
      <pre>{captured.body}</pre>
    {/if}
  </section>
</main>

<style>
  /* Everything is scoped under `.settings`. Svelte bundles all component styles
     into one stylesheet that **both** windows load, whether or not this
     component ever mounts, so a `:global(body)`, `:global(html)` or
     `:global(:root)` rule here would paint the transparent widget window —
     which is exactly what src/app.css's own comment forbids. */
  .settings {
    font: 13px/1.5 system-ui, sans-serif;
    color: #e5e7eb;
    background: #14141a;
    min-height: 100vh;
    padding: 1em 1.25em 2em;
    box-sizing: border-box;
  }
  .settings h1 { font-size: 15px; margin: 0 0 1em; }
  .settings h2 { font-size: 12px; text-transform: uppercase; letter-spacing: .06em;
                 opacity: .7; margin: 0 0 .5em; }
  .settings section { margin-bottom: 1.75em; }
  .settings label { display: block; font-size: 11px; opacity: .8; margin-bottom: .25em; }
  .settings input, .settings select, .settings button { font: inherit; }
  .settings input[type='number'] { width: 7em; padding: .25em .35em; }
  .settings input[type='password'] { width: 16em; padding: .25em .35em; }
  .settings button { padding: .3em .7em; cursor: pointer; }
  .settings button:disabled { cursor: default; opacity: .5; }
  .hint { font-size: 11px; opacity: .7; margin: .5em 0 0; }
  .note { font-size: 11px; opacity: .85; margin: .5em 0 0; }
  .warn { font-size: 11px; color: #fbbf24; margin: .5em 0 0; }
  /* Selectable on purpose: copying this into an issue is the panel's reason to
     exist, which is also why the masking behind it is more aggressive than
     anywhere else in the app. */
  .settings pre {
    max-height: 18em; overflow: auto; user-select: text;
    background: rgba(0, 0, 0, .35); padding: .5em; font-size: 11px;
    white-space: pre-wrap; word-break: break-all;
  }
</style>
