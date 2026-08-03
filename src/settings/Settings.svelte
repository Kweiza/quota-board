<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import type { UnlistenFn } from '@tauri-apps/api/event'
  import { openUrl } from '@tauri-apps/plugin-opener'
  import AccountList from './AccountList.svelte'
  import { queriesPerDay } from '../lib/format'
  import {
    accountsWarning,
    beginLogin,
    getAutostart,
    getSettings,
    lastResponse,
    listAccounts,
    onAccountsChanged,
    onAuthFailed,
    onManualFallback,
    refreshAccount,
    removeAccount,
    renameAccount,
    reorderAccounts,
    setAutostart,
    setSettings,
    storeStatus,
    submitManualCode,
    unlockSecrets,
  } from '../lib/ipc'
  import type {
    AccountView,
    AutostartView,
    LoginUrls,
    ManualFallback,
    RawResponse,
    SettingsView,
    StoreStatus,
  } from '../lib/types'

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
  /**
   * §6.4's refusal, per account: uuid → the instant a manual refresh may next
   * fire. Not in `error`, because that banner is `warn` and reports failures —
   * a refusal is §6.2's server-ordered wait being obeyed, which is the rate
   * limiter working, and it is per-account, which a single line above the list
   * cannot express.
   *
   * **Only the server refuses now.** §6.1's client-side floor used to refuse
   * presses as well and was by far the commoner cause of this note; §6.4
   * dropped it, so a note here means a 429 was received and `Retry-After` has
   * not run out. Rarer, and correspondingly more worth saying.
   *
   * Written by a press on that row's own button, from the answer to that press.
   * **Never treated as still true past its own `until`.** The note is a
   * present-tense claim, this window is hidden rather than destroyed
   * (`src-tauri/src/main.rs`'s close handler), so the component outlives any
   * one visit: without an expiry, pressing Refresh, closing Settings and
   * reopening it tomorrow still shows "available after 09:05". That is the
   * defect this session already fixed three times over — a line that stayed
   * after the state it described was gone.
   *
   * Dropping an expired note is **not** the same as announcing availability.
   * The server can re-throttle on the very next request, and the polling loop
   * keeps making requests while the note is on screen, so a note that *claimed*
   * budget at the old instant would be CLAUDE.md's confidently-wrong display.
   * Removing it claims nothing: the press stays the only moment the answer is
   * known, and silence is the honest state between presses.
   */
  let throttledUntil: Record<string, string> = {}

  /** Fires once per live note, at its own `until`, and removes just that one. */
  let expiryTimers: Record<string, ReturnType<typeof setTimeout>> = {}

  function forgetThrottle(uuid: string): void {
    clearTimeout(expiryTimers[uuid])
    delete expiryTimers[uuid]
    if (!(uuid in throttledUntil)) return
    const next = { ...throttledUntil }
    delete next[uuid]
    throttledUntil = next
  }

  function rememberThrottle(uuid: string, until: string): void {
    clearTimeout(expiryTimers[uuid])
    const next = { ...throttledUntil }
    next[uuid] = until
    throttledUntil = next
    // `setTimeout` saturates above ~24.8 days; an `until` that far out would
    // fire immediately and retire a note that is still true. `record_throttle`
    // caps every wait at one hour, so this only guards a malformed value.
    const ms = new Date(until).getTime() - Date.now()
    if (Number.isFinite(ms) && ms > 0 && ms < 2_147_483_647) {
      expiryTimers[uuid] = setTimeout(() => forgetThrottle(uuid), ms)
    } else {
      forgetThrottle(uuid)
    }
  }

  let view: SettingsView | null = null
  let intervalSecs: number | null = null

  /** §11.3. `null` until the first read answers; never assumed either way. */
  let autostart: AutostartView | null = null

  async function toggleAutostart(e: Event): Promise<void> {
    // Captured before the first await: `currentTarget` is null once the event
    // has finished dispatching, and the catch below needs the element.
    const box = e.currentTarget as HTMLInputElement
    const wanted = box.checked
    try {
      // The answer is what the OS reports afterwards, not what was asked for.
      autostart = await setAutostart(wanted)
      error = null
      // Corrected by hand on **this** path too, not only on refusal. When the
      // OS declines quietly the answer comes back equal to the value already
      // rendered, so `checked={autostart.enabled}` writes nothing — and the box
      // keeps the position the click gave it while the state says the opposite.
      // Measured: the test for this failed against a version that only fixed
      // the catch.
      box.checked = autostart.enabled
    } catch (err) {
      error = String(err)
      // A refused change must not stay on screen looking applied. **The DOM has
      // to be corrected by hand**: the click moved the checkbox itself, and
      // re-rendering `checked={autostart.enabled}` from a value that has not
      // changed writes nothing, so the box would keep the position the user
      // put it in while the state says otherwise. Measured — the test for this
      // failed against a version that reassigned a fresh object instead.
      box.checked = autostart?.enabled ?? false
      // `autostart` is deliberately left alone: the command failed, so nothing
      // is known about the OS state that was not known before it was called.
    }
  }

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
      // Retire notes for accounts that are gone. `account.uuid` is the stable
      // primary key (§9.3), so removing an account and adding the same one back
      // reuses its uuid — without this, a refusal from an earlier session
      // reappears on a fresh row, quoting a wall clock the user never saw.
      // Only on a successful read: the `catch` below deliberately keeps the
      // last good list, and reconciling against a list we failed to fetch would
      // clear every note instead.
      const live = new Set(accounts.map((a) => a.uuid))
      Object.keys(throttledUntil)
        .filter((uuid) => !live.has(uuid))
        .forEach(forgetThrottle)
    } catch (e) {
      // A failed read is not a reason to blank the list; the widget branch of
      // src/main.ts set that rule and it holds here for the same reason.
      error = String(e)
    }
  }

  /**
   * §9.1's file could not be read. Kept out of `error`: that banner reports a
   * failed action, and this is a standing condition the user has to fix on
   * disk. It also must not be cleared by the next successful command.
   */
  let accountsProblem: string | null = null

  async function pullAccountsProblem(): Promise<void> {
    try {
      accountsProblem = await accountsWarning()
    } catch (e) {
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
    void pullAccountsProblem()
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
      try {
        autostart = await getAutostart()
      } catch (e) {
        error = String(e)
      }
    })()
    void (async () => {
      // Login finishes in the background, so without these two subscriptions a
      // completed login never reaches this window.
      const fns = [
        await onAccountsChanged(() => {
          // An `accounts://changed` means an account mutation *succeeded*, so
          // it retires whatever error is on screen. `guard()` only clears the
          // banner for click-driven commands; without this, the refusal from a
          // second "Add account" click survives the login the user then
          // completed in the browser — the account appears in the list and the
          // widget while the banner still says a login is in progress.
          //
          // Cleared synchronously, before the awaited re-read: an
          // `auth://failed` arriving afterwards sets the banner again and must
          // win, and a clear deferred behind `pullAccounts` would stomp it.
          // The two events do not race for one outcome — they report different
          // ones.
          error = null
          // The login is over, however it finished, so the paste form goes with
          // it — leaving it up would invite a code for a login that is done.
          fallback = null
          void pullAccounts()
        }),
        await onAuthFailed((message) => {
          error = message
        }),
        // The other two of §10.3's four loopback failures: both are seen only
        // by the background task, and neither ends the login.
        await onManualFallback((f) => {
          fallback = f
          error = null
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
    // Same reason the unlisteners are released here: closing this window is a
    // hide, not a destroy, so anything left armed outlives every visit.
    Object.values(expiryTimers).forEach(clearTimeout)
    expiryTimers = {}
  })

  async function addAccount(provider: 'anthropic' | 'openai'): Promise<void> {
    // No local "pending" flag. The Rust side is the single-flight
    // (`begin_login` answers `a login is already in progress`), and a second
    // disabled state here would be the two-sources-disagree hazard §7.1 exists
    // to prevent — with the extra failure that success arrives on
    // `accounts://changed`, so a flag cleared only on `auth://failed` would
    // disable the button for the life of the process.
    let urls: LoginUrls
    try {
      urls = await beginLogin(provider)
    } catch (e) {
      // `begin_login` refused outright — a login is already in progress, or the
      // authorize URL is misconfigured (§10.2). There is no manual URL to fall
      // back to, because none was built.
      error = String(e)
      return
    }
    error = null

    // Two of §10.3's four loopback failures are visible only here, and the Rust
    // side never learns about either, so neither can arrive as an event.
    if (urls.loopback === null) {
      fallback = {
        url: urls.manual,
        reason: 'no local port could be opened for the browser to reply to',
      }
      return
    }
    try {
      await openUrl(urls.loopback)
    } catch (e) {
      fallback = { url: urls.manual, reason: `the browser could not be opened (${String(e)})` }
    }
  }

  /**
   * §10.3's paste path, offered only once the loopback half cannot finish.
   *
   * Not an `error`: this is a login that can still succeed, and putting it in
   * the warning banner would say the opposite. The banner stays for things that
   * are actually over.
   */
  let fallback: ManualFallback | null = null
  let pasted = ''
  let submitting = false

  async function submitCode(): Promise<void> {
    if (submitting || pasted.trim() === '') return
    submitting = true
    try {
      await submitManualCode(pasted)
      error = null
      pasted = ''
      // The block itself is cleared by `accounts://changed`, which is also what
      // re-reads the list — the login is not finished until that arrives.
    } catch (e) {
      // Every refusal from `submit_manual_code` is a different sentence naming
      // what to do next, so it is shown as-is.
      error = String(e)
    } finally {
      submitting = false
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
      const state = await refreshAccount(uuid)
      // Observed: "Refresh now does not work — the capture time never
      // changes." The cause then was §6.1's client-side floor, which §6.4 has
      // since dropped; what remains is §6.2's server-ordered wait, and §6.4
      // still requires reporting when it will be available. The command does:
      // it answers `Throttled { until }`. Discarding that answer was the whole
      // defect — the early return never touches the scheduler, so the
      // `list_accounts` below reports the account's ordinary state and the
      // refusal is unrecoverable once this value is dropped.
      //
      // Both helpers assign a fresh object rather than mutating: legacy-mode
      // reactivity is driven by the assignment, so an in-place write would not
      // repaint.
      if (state.kind === 'throttled') rememberThrottle(uuid, state.until)
      else forgetThrottle(uuid)
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
  <h1>Quota Board</h1>
  {#if error}
    <p class="warn" role="alert">{error}</p>
  {/if}
  <!-- Above the account list on purpose: the list below it is empty, and
       without this line that emptiness reads as "you have no accounts". -->
  {#if accountsProblem}
    <p class="warn" role="alert">
      {accountsProblem}. Nothing will be written to that file until it is
      repaired or removed, so your accounts are not lost — but they cannot be
      shown, and adding one now would fail.
    </p>
  {/if}

  <section>
    <h2>Accounts</h2>
    <AccountList {accounts} {throttledUntil}
                 onRemove={(uuid) => void guard(() => removeAccount(uuid))}
                 onRename={rename} onMove={move} onRefresh={refresh} />
    {#if accounts.length === 0}
      <p class="hint">No accounts yet.</p>
    {/if}
    <button type="button" on:click={() => addAccount('anthropic')}>Add Claude account</button>
    <button type="button" on:click={() => addAccount('openai')}>Add Codex account</button>

    <!-- docs/design.md §10.3. Shown only after the automatic half has given up;
         until then this whole block is absent, which is the decision recorded
         in the plan (a permanently visible "can't open a browser?" disclosure
         would be clutter for everyone who never needs it). -->
    {#if fallback}
      {@const fb = fallback}
      <div class="fallback">
        <p class="warn">{fb.reason}.</p>
        <p class="hint">
          Open the link below in any browser — it does not have to be this
          machine — approve there, then paste the <code>code#state</code> line
          the page shows you.
        </p>
        <!-- Selectable, and that is the point: the case this exists for is a
             machine that cannot open a browser at all, where a button is
             useless and copying the address elsewhere is the only way through.
             The button is for the narrower case where a browser exists but
             could not be launched automatically. -->
        <p class="url">{fb.url}</p>
        <button on:click={() => void openUrl(fb.url)}>Open in browser</button>
        <label for="manual-code">Code from the page</label>
        <input
          id="manual-code"
          placeholder="code#state"
          bind:value={pasted}
          disabled={submitting}
        />
        <button on:click={submitCode} disabled={submitting || pasted.trim() === ''}>
          Submit
        </button>
      </div>
    {/if}
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

  <!-- docs/design.md §11.3. LaunchAgent on macOS, XDG autostart on Linux, and
       a per-user HKCU Run entry on Windows — never HKLM, so no elevation. -->
  <section>
    <h2>Start at login</h2>
    {#if autostart}
      <label for="autostart">Launch Quota Board when I log in</label>
      <input
        id="autostart"
        type="checkbox"
        checked={autostart.enabled}
        disabled={!autostart.writable}
        on:change={toggleAutostart}
      />
      {#if !autostart.writable}
        <p class="warn">
          This is a development build, so this cannot be changed here — it would
          register the build directory rather than an installed app.
        </p>
      {/if}
    {/if}
  </section>

  <section>
    <h2>Token store</h2>
    {#if status}
      <p class="note">{status.description}</p>
      <!-- One branch per `StoreKind`, plus a fallback. The form's visibility is
           decided by `kind`, never by `fallback_file_exists`: on a missing file
           any passphrase opens an empty store and writes nothing, so that flag
           is still false right after the first successful unlock — it chooses
           the wording only. `encrypted_file` therefore cannot share a branch
           with `no_backend`, which is how the shipped window came to tell a
           user who had just unlocked the store that no store existed yet and
           that values would not update. -->
      {#if status.kind === 'keychain'}
        <p class="note">Tokens are held in the OS keychain, which unlocks at login.</p>
      {:else if status.kind === 'encrypted_file'}
        <p class="note">
          The encrypted store is open, so values update normally. It has to be
          unlocked again after each boot.
        </p>
      {:else if status.kind === 'keychain_locked'}
        <p class="warn">
          A keychain exists on this machine but did not answer. Unlock it in the
          OS and restart Quota Board — a passphrase here would open a
          different, empty store.
        </p>
      {:else if status.kind === 'no_backend'}
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
      {:else}
        <!-- A `StoreKind` variant added on the Rust side must not render an
             empty section here: silence in this panel reads as "the token store
             is fine", which is CLAUDE.md's never-degrade-silently rule applied
             to UI state. It says what it does not know instead. -->
        <p class="warn">
          This build does not recognize the token store state the backend
          reported, so it cannot say whether values will update or how to unlock
          the store. Update Quota Board.
        </p>
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
  .fallback { margin-top: .75em; padding: .6em .7em; border-radius: 6px;
              background: rgba(255, 255, 255, .04); }
  /* `user-select: text` is load-bearing, not cosmetic — see the note above the
     element. `break-all` because an authorize URL is one long unbreakable run
     and would otherwise push this panel wider than the window. */
  .settings .url { user-select: text; font-size: 11px; margin: .5em 0;
                   font-family: ui-monospace, monospace; word-break: break-all;
                   background: rgba(0, 0, 0, .35); padding: .4em; border-radius: 4px; }
  .settings .fallback input { width: 100%; box-sizing: border-box; padding: .25em .35em;
                              margin-bottom: .5em; }
  /* Selectable on purpose: copying this into an issue is the panel's reason to
     exist, which is also why the masking behind it is more aggressive than
     anywhere else in the app. */
  .settings pre {
    max-height: 18em; overflow: auto; user-select: text;
    background: rgba(0, 0, 0, .35); padding: .5em; font-size: 11px;
    white-space: pre-wrap; word-break: break-all;
  }
</style>
