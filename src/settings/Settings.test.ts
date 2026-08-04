import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { emit } from '@tauri-apps/api/event'
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks'
import { tick } from 'svelte'
import { afterEach, describe, expect, it } from 'vitest'
import Settings from './Settings.svelte'
import { accountKey } from '../lib/types'
import type {
  AccountState,
  AccountView,
  AutostartView,
  LoginUrls,
  RawResponse,
  SettingsView,
  StoreStatus,
} from '../lib/types'

type IpcCall = { cmd: string; args: Record<string, unknown> }

interface Backend {
  accounts?: AccountView[]
  /**
   * What `refresh_account` answers, one entry per call; the last entry repeats
   * once the list runs out. A list rather than a single value because §6.4's
   * refusal is an `Ok` answer, not a rejection, so "refused, then allowed" is
   * an ordinary two-call sequence and no other field could express it.
   */
  refreshStates?: AccountState[]
  /** What `get_settings` answers with. */
  settings?: SettingsView
  /** What `set_settings` answers with — the value the backend *applied*. */
  applied?: SettingsView
  status?: StoreStatus
  /** What `unlock_secrets` answers with — the store that is now open. */
  unlocked?: StoreStatus
  /** Rejects `begin_login` with this message, as the Rust single-flight does. */
  loginError?: string
  /** What `begin_login` answers with. §10.3 returns both URLs. */
  loginUrls?: LoginUrls
  /** Rejects `submit_manual_code` with this message. */
  submitError?: string
  /** What `get_autostart` answers with. §11.3. */
  autostart?: AutostartView
  /** Rejects `set_autostart` with this message, as a debug build does. */
  autostartError?: string
  /**
   * What `set_autostart` answers with, regardless of what was asked. §11.3's
   * command reports the state the OS has *afterwards*, and the two can
   * disagree — an enable that the OS quietly declined comes back disabled.
   */
  autostartApplied?: AutostartView
  raw?: RawResponse | null
}

const account = (uuid: string, label: string, email: string): AccountView => ({
  account_id: uuid,
  provider: 'anthropic',
  label,
  email,
  state: { kind: 'loading' },
})

const two = [
  account('uuid-work', 'Work', 'work@example.com'),
  account('uuid-home', 'Personal', 'home@example.com'),
]

const settings = (secs: number, writable = true): SettingsView => ({
  poll_interval_secs: secs,
  min_interval_secs: 180,
  max_interval_secs: 86400,
  warning: null,
  writable,
})

const store = (kind: StoreStatus['kind'], exists: boolean): StoreStatus => ({
  description: 'a token store',
  kind,
  fallback_file_exists: exists,
})

/**
 * Drives the component through the real `@tauri-apps/api` invoke path, so the
 * assertions are about what the window actually asks the backend for. Anything
 * unnamed answers `null`.
 *
 * `shouldMockEvents` makes `listen`/`emit` round-trip inside the mock
 * (src/lib/ipc.test.ts:283-291 uses it for the same reason), so a test can
 * deliver `accounts://changed` and `auth://failed` the way the backend does.
 * It also means the event plugin's own invokes bypass this callback and are
 * therefore absent from the recorded calls — no assertion here names them.
 */
function mockBackend(b: Backend = {}): IpcCall[] {
  const calls: IpcCall[] = []
  let refreshes = 0
  mockIPC((cmd, args) => {
    calls.push({ cmd, args: (args ?? {}) as Record<string, unknown> })
    switch (cmd) {
      case 'list_accounts':
        return b.accounts ?? []
      case 'refresh_account': {
        // The real command always answers with a state, never with null.
        const states = b.refreshStates ?? [{ kind: 'loading' } as AccountState]
        return states[Math.min(refreshes++, states.length - 1)]
      }
      case 'get_settings':
        return b.settings ?? settings(300)
      case 'set_settings':
        return b.applied ?? b.settings ?? settings(300)
      case 'store_status':
        return b.status ?? store('keychain', false)
      case 'unlock_secrets':
        return b.unlocked ?? store('encrypted_file', true)
      case 'begin_login':
        // A Tauri command error arrives as the serialized message, not an
        // `Error`; the window renders it with `String(e)`.
        if (b.loginError !== undefined) return Promise.reject(b.loginError)
        return (
          b.loginUrls ?? {
            loopback: 'https://claude.com/cai/oauth/authorize?redirect_uri=loopback',
            manual: 'https://claude.com/cai/oauth/authorize?redirect_uri=manual',
          }
        )
      case 'submit_manual_code':
        if (b.submitError !== undefined) return Promise.reject(b.submitError)
        return null
      case 'get_autostart':
        return b.autostart ?? { enabled: false, writable: true }
      case 'set_autostart':
        if (b.autostartError !== undefined) return Promise.reject(b.autostartError)
        return (
          b.autostartApplied ?? {
            enabled: (args as { enabled?: boolean } | undefined)?.enabled ?? false,
            writable: true,
          }
        )
      case 'last_response':
        return b.raw ?? null
      default:
        return null
    }
  }, { shouldMockEvents: true })
  return calls
}

/**
 * Runs every pending microtask, then Svelte's flush.
 *
 * Needed to assert that something did **not** happen: a state change deferred
 * behind an awaited command lands in a microtask, and `findBy*` resolves on its
 * first look — early enough to miss it. The `setTimeout` is a macrotask, so it
 * runs after the whole microtask queue has drained. Measured: without this the
 * ordering test below passes against a window that clears the banner after
 * `list_accounts` resolves, which is the defect it names.
 */
async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0))
  await tick()
}

/**
 * Blocks until the window's `onMount` event subscriptions are really live.
 *
 * `listen` resolves asynchronously and the component subscribes inside an
 * unawaited `onMount` chain, so an `emit` sent before that lands reaches
 * nobody — and a test asserting "the banner is gone" would then pass against a
 * window that never received the event. Re-emitting inside `waitFor` is the
 * only observable signal there is: `accounts://changed` makes the window
 * re-read the account list.
 */
async function whenSubscribed(calls: IpcCall[]): Promise<void> {
  const before = calls.filter((c) => c.cmd === 'list_accounts').length
  await waitFor(async () => {
    await emit('accounts://changed')
    expect(calls.filter((c) => c.cmd === 'list_accounts').length).toBeGreaterThan(before)
  })
}

afterEach(() => {
  // `cleanup()` **before** `clearMocks()`, and explicitly rather than left to
  // testing-library's auto-cleanup. Destroying the component runs its
  // `onDestroy` unlisten, which needs
  // `window.__TAURI_EVENT_PLUGIN_INTERNALS__.unregisterListener` — and
  // `clearMocks` deletes it (@tauri-apps/api/mocks.js). The auto-cleanup hook
  // is registered first and therefore runs *after* this one, so the shipped
  // order in src/lib/ipc.test.ts would make every unlisten throw. Measured: that
  // does not report as a failure — the summary reads all-passed with
  // `Errors N errors` beside it and exit code 1.
  cleanup()
  clearMocks()
  document.body.innerHTML = ''
})

describe('Settings polling interval', () => {
  it('the interval field shows the value the backend actually applied, not the one typed', async () => {
    // §6.1's floor is the whole reason this control exists in this shape: the
    // backend clamps and answers with what it applied, and writing that answer
    // back is what makes the clamp visible instead of silent.
    const calls = mockBackend({ settings: settings(300), applied: settings(180) })
    render(Settings)

    const field = (await screen.findByLabelText('Polling interval (seconds)')) as HTMLInputElement
    await waitFor(() => expect(field.value).toBe('300'))

    // `bind:value` listens for `input`; the command is sent on `change`, so a
    // keystroke does not fire one command per digit.
    await fireEvent.input(field, { target: { value: '60' } })
    await fireEvent.change(field)

    expect(calls.filter((c) => c.cmd === 'set_settings')).toEqual([
      { cmd: 'set_settings', args: { pollIntervalSecs: 60 } },
    ])
    await waitFor(() => expect(field.value).toBe('180'))
  })

  it('disables the interval field when the settings file is not writable', async () => {
    // A settings file from a format version this build cannot interpret is
    // read-only; `set_settings` refuses. Offering a save that is guaranteed to
    // fail is worse than showing the reason up front.
    const view = settings(300, false)
    view.warning = 'the settings file was written by a newer version'
    const calls = mockBackend({ settings: view })
    render(Settings)

    const field = (await screen.findByLabelText('Polling interval (seconds)')) as HTMLInputElement
    expect(field.disabled).toBe(true)
    expect(screen.getByText('the settings file was written by a newer version')).toBeTruthy()
    await fireEvent.change(field)
    expect(calls.filter((c) => c.cmd === 'set_settings')).toEqual([])
  })
})

describe('Settings error banner', () => {
  it('clears the banner when accounts://changed says a mutation succeeded', async () => {
    // Observed: "Add account" clicked twice reports the Rust single-flight's
    // refusal, the user then completes that login in the browser, the account
    // appears — and the orange banner stays on screen for the life of the
    // window. `guard()` clears the banner for click-driven commands; nothing
    // cleared it for a success that arrives asynchronously, by event.
    const calls = mockBackend({ loginError: 'a login is already in progress' })
    render(Settings)
    // Before the click: this helper emits the very event under test.
    await whenSubscribed(calls)

    await fireEvent.click(await screen.findByRole('button', { name: 'Add Claude account' }))
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(screen.getByText('a login is already in progress')).toBeTruthy()

    await emit('accounts://changed')

    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
  })

  it('lets an auth://failed that arrives after the change still show its error', async () => {
    // The two events do not race for the same outcome, so the clear must be
    // synchronous with the event's arrival. Clearing it *after* an awaited
    // `list_accounts` instead would stomp a failure reported in between, and
    // the window would then be silent about a login that died.
    const calls = mockBackend()
    render(Settings)
    await whenSubscribed(calls)

    // Delivered back to back, as a login that emitted both would deliver them:
    // the mock runs each listener synchronously inside `emit`.
    await Promise.all([emit('accounts://changed'), emit('auth://failed', 'the login timed out')])
    await settle()

    expect(screen.getByText('the login timed out')).toBeTruthy()
    expect(screen.getByRole('alert')).toBeTruthy()
  })
})

/**
 * Two buttons rather than a picker (Task 8): the whole flow is two clicks and
 * a browser round trip, and a select that must be set before the button is one
 * more state to get wrong. What matters here is only that each button tells
 * the core which provider it is adding — `begin_login`'s own behaviour is
 * covered by the tests above and in `crates/core`.
 */
describe('Settings add account buttons', () => {
  it('asks the core which provider is being added', async () => {
    const calls = mockBackend({ loginUrls: { loopback: null, manual: 'x' } })

    render(Settings)
    await fireEvent.click(await screen.findByRole('button', { name: /add codex account/i }))

    expect(calls).toContainEqual({ cmd: 'begin_login', args: { provider: 'openai' } })
  })

  it('asks the core for the Claude provider when that button is pressed', async () => {
    const calls = mockBackend({ loginUrls: { loopback: null, manual: 'x' } })

    render(Settings)
    await fireEvent.click(await screen.findByRole('button', { name: /add claude account/i }))

    expect(calls).toContainEqual({ cmd: 'begin_login', args: { provider: 'anthropic' } })
  })
})

describe('Settings manual refresh', () => {
  /**
   * **Always in the future**, because that is the command's contract:
   * `Scheduler::state` yields `Throttled { until }` only through
   * `throttled_until.filter(|t| *t > now)`, so one reaching this window can
   * never already have passed. A fixed literal here was a fixture that the real
   * API cannot produce, and it went red the moment the window learned to retire
   * an expired note.
   *
   * The expected wall clock is derived from the same `Date`, so this stays
   * deterministic and zone-independent — `untilHhMm` is deliberately local-time
   * (§7.1), so a UTC literal would assert the machine's zone instead.
   */
  const untilIn = (minutes: number): { iso: string; hhmm: string } => {
    const d = new Date(Date.now() + minutes * 60_000)
    const hh = String(d.getHours()).padStart(2, '0')
    const mm = String(d.getMinutes()).padStart(2, '0')
    return { iso: d.toISOString(), hhmm: `${hh}:${mm}` }
  }

  const refreshButtons = async (): Promise<HTMLElement[]> => {
    // The rows only exist after the awaited `list_accounts` resolves.
    await waitFor(() =>
      expect(screen.getAllByRole('button', { name: 'Refresh now' })).toHaveLength(two.length),
    )
    return screen.getAllByRole('button', { name: 'Refresh now' })
  }

  it('says when a refused Refresh now becomes available, on the row that was refused', async () => {
    // Observed: "Refresh now does not work. I press it and the capture time
    // never changes. Only the polling interval changes it." The cause then was
    // §6.1's client-side floor, refusing the button for 180 of every 300
    // seconds; §6.4 has since dropped it, and §6.2's server-ordered wait is now
    // the only refusal — rarer, and reported the same way. `refresh_account`
    // does report it, as `Throttled { until }`; this window discarded the
    // return value, so the press was silent. Re-reading the list cannot recover
    // it either: the command returns early *without touching the scheduler*.
    const t = untilIn(3)
    mockBackend({ accounts: two, refreshStates: [{ kind: 'throttled', until: t.iso }] })
    render(Settings)

    const buttons = await refreshButtons()
    await fireEvent.click(buttons[1])

    const note = await screen.findByText(`throttled, available after ${t.hhmm}`)
    // Per row, not per window: with three accounts a single line above the
    // list cannot say which press was refused.
    expect(note.closest('li')?.textContent).toContain('home@example.com')
    expect(screen.getAllByText(/throttled, available after/)).toHaveLength(1)
    // Not the `warn` banner. A throttle is the rate limiter working as
    // designed, and labelling expected behaviour an error is its own kind of
    // confidently wrong.
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('retires the refusal once the time it named has passed', async () => {
    // The note is a present-tense claim and this window is hidden rather than
    // destroyed, so without an expiry it outlives every visit: press Refresh,
    // close Settings, reopen tomorrow, and the row still says "available after
    // 09:05". That is the same defect this session fixed three times over.
    //
    // Removing it is not the same as announcing availability — the automatic
    // poll stamps `last_attempt_at` too, so the real floor has moved. Silence
    // is the honest state between presses.
    // Seconds, not the usual minutes: the component arms a real `setTimeout`
    // from the answer, and this test is about it being armed at all. The
    // rendered HH:MM is whatever minute that lands in.
    const soon = new Date(Date.now() + 1_200)
    mockBackend({
      accounts: two,
      refreshStates: [{ kind: 'throttled', until: soon.toISOString() }],
    })
    render(Settings)

    const buttons = await refreshButtons()
    await fireEvent.click(buttons[0])
    expect(await screen.findByText(/throttled, available after/)).toBeTruthy()

    await waitFor(() => expect(screen.queryByText(/throttled, available after/)).toBeNull(), {
      timeout: 4000,
      interval: 100,
    })
  }, 6000)

  it('does not resurrect a refusal on an account that was removed and added back', async () => {
    // `account_id` is stable across a rename (§9.3), so removing an account
    // and adding the same one back reuses it. A note keyed by uuid and never
    // reconciled would reappear on a fresh row, quoting a wall clock from a
    // session the user does not remember.
    const t = untilIn(30)
    const calls = mockBackend({
      accounts: two,
      refreshStates: [{ kind: 'throttled', until: t.iso }],
    })
    render(Settings)

    const buttons = await refreshButtons()
    await fireEvent.click(buttons[0])
    expect(await screen.findByText(`throttled, available after ${t.hhmm}`)).toBeTruthy()

    // Remove it, then add the SAME uuid back. Removing alone proves nothing:
    // the row disappears with the account, so the note is invisible either way
    // and the assertion passes against a window that never forgot it —
    // measured, the first version of this test stayed green with the
    // reconciliation deleted. The resurrection is the defect.
    const removed = two.shift() as AccountView
    try {
      await whenSubscribed(calls)
      await waitFor(() => expect(screen.getAllByRole('button', { name: 'Refresh now' }))
        .toHaveLength(1))

      two.unshift(removed)
      await whenSubscribed(calls)
      await waitFor(() => expect(screen.getAllByRole('button', { name: 'Refresh now' }))
        .toHaveLength(2))
      expect(screen.queryByText(/throttled, available after/)).toBeNull()
    } finally {
      if (!two.some((a) => a.account_id === removed.account_id)) two.unshift(removed)
    }
  })

  it('drops the refusal from the row as soon as a later press actually fires', async () => {
    // The note is cleared by the answer to a press, never by a timer reaching
    // `until`: `Scheduler::begin_poll` stamps `last_attempt_at` for the
    // automatic poll too, so the floor moves forward while the note is on
    // screen and a self-clearing note would offer budget nobody checked for.
    const first = untilIn(4)
    mockBackend({
      accounts: two,
      refreshStates: [
        { kind: 'throttled', until: first.iso },
        { kind: 'ok', windows: [], extra: null, fetched_at: '2026-07-31T09:05:00Z' },
      ],
    })
    render(Settings)

    const buttons = await refreshButtons()
    await fireEvent.click(buttons[0])
    expect(await screen.findByText(`throttled, available after ${first.hhmm}`)).toBeTruthy()

    await fireEvent.click(buttons[0])
    await waitFor(() => expect(screen.queryByText(/throttled, available after/)).toBeNull())
    // A press that fired is not a failure either.
    expect(screen.queryByRole('alert')).toBeNull()
  })
})

describe('Settings token store', () => {
  it('the passphrase button says Set a passphrase when no fallback file exists', async () => {
    // The first passphrase *creates* the store, so it cannot be verified and a
    // typo is permanent. The wording is the only warning the user gets. Both
    // halves are `no_backend` — the wording is keyed on the file, but whether
    // the form is offered at all is keyed on the kind.
    const first = mockBackend({ status: store('no_backend', false) })
    const view = render(Settings)
    expect(await screen.findByRole('button', { name: 'Set a passphrase' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Unlock' })).toBeNull()
    expect(first.some((c) => c.cmd === 'store_status')).toBe(true)
    view.unmount()

    mockBackend({ status: store('no_backend', true) })
    render(Settings)
    expect(await screen.findByRole('button', { name: 'Unlock' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Set a passphrase' })).toBeNull()
  })

  it('an unlocked encrypted store stops offering the form and stops claiming values are stale', async () => {
    // Observed on §9.2's fallback path: after a successful unlock the header
    // said `encrypted file (passphrase)` while the same screen still said
    // values would not update until a passphrase was entered, still said no
    // store existed yet, and still offered the form. `fallback_file_exists` is
    // genuinely still false here — an empty store writes no file until the
    // first `put` — so only `kind` can tell "locked" from "open".
    mockBackend({ status: store('no_backend', false), unlocked: store('encrypted_file', false) })
    render(Settings)

    const field = await screen.findByLabelText('Passphrase')
    await fireEvent.input(field, { target: { value: 'a passphrase' } })
    await fireEvent.click(screen.getByRole('button', { name: 'Set a passphrase' }))

    await waitFor(() => expect(screen.queryByLabelText('Passphrase')).toBeNull())
    expect(screen.queryByRole('button', { name: 'Set a passphrase' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Unlock' })).toBeNull()
    expect(screen.queryByText(/Values will not update until the passphrase/)).toBeNull()
    expect(screen.queryByText(/No encrypted store exists yet/)).toBeNull()
    expect(screen.getByText(/The encrypted store is open/)).toBeTruthy()
  })

  it('names a store kind it does not recognize instead of rendering an empty section', async () => {
    // CLAUDE.md's never-degrade-silently rule applies to UI state: a `StoreKind`
    // variant added later must not make this section render nothing at all,
    // which would read as "the token store is fine".
    mockBackend({ status: store('vault_of_the_future' as StoreStatus['kind'], false) })
    render(Settings)

    expect(await screen.findByText(/does not recognize/)).toBeTruthy()
    expect(screen.queryByLabelText('Passphrase')).toBeNull()
  })

  it('offers no passphrase form for a merely locked keychain', async () => {
    // §9.2: a passphrase here would open a different, empty store, and every
    // account would then classify AUTH_DEAD and be quarantined.
    mockBackend({ status: store('keychain_locked', true) })
    render(Settings)
    expect(await screen.findByText(/Unlock it in the OS/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Unlock' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Set a passphrase' })).toBeNull()
  })
})

describe('Settings debug panel', () => {
  // `<option value>` is `accountKey(account_id, provider)` (§9.3), not the
  // bare id — every account fixture in this file is `'anthropic'`, so that is
  // the provider half here.
  const selectAccount = async (uuid: string): Promise<void> => {
    const key = accountKey(uuid, 'anthropic')
    const select = (await screen.findByLabelText('Account')) as HTMLSelectElement
    // The options only exist after the awaited `list_accounts` resolves, and
    // assigning a value with no matching `<option>` is silently dropped — the
    // "nothing selected" branch would then render and a named assertion would
    // pass against the wrong thing.
    await waitFor(() => expect(select.options.length).toBe(two.length + 1))
    await fireEvent.change(select, { target: { value: key } })
    expect(select.value).toBe(key)
  }

  it('an account with no retained body says so instead of rendering empty', async () => {
    mockBackend({ accounts: two, raw: null })
    render(Settings)
    await selectAccount('uuid-home')

    await fireEvent.click(screen.getByRole('button', { name: 'Reload' }))
    expect(
      await screen.findByText(
        'This account has not been polled successfully since the app started.',
      ),
    ).toBeTruthy()
  })

  it('does not claim an account has never been polled before Reload is pressed', async () => {
    // "not loaded yet" and "loaded, and the answer was null" are different
    // facts. Collapsing them into one `captured === null` tells the user their
    // account has never polled before they have pressed anything — the
    // confidently-wrong display CLAUDE.md calls this product's worst failure.
    mockBackend({ accounts: two, raw: null })
    render(Settings)
    await selectAccount('uuid-home')

    expect(
      screen.queryByText('This account has not been polled successfully since the app started.'),
    ).toBeNull()
    expect(screen.getByText('Select an account and press Reload.')).toBeTruthy()
  })

  /**
   * `remove_account_for` calls `forget_raw` precisely so that a deleted
   * account's body stops being readable. Nothing reconciled `selected` or
   * `loadedFor` against the account list, so the webview undid that: the row
   * vanished from the list while its captured body stayed on screen, with no
   * user action in between.
   */
  it('drops a removed account\'s captured body instead of leaving it on screen', async () => {
    const raw: RawResponse = {
      captured_at: '2026-08-03T09:00:00Z',
      status: 200,
      truncated: false,
      body: '{"marker":"THE-REMOVED-ACCOUNTS-BODY"}',
    }
    const backend: Backend = { accounts: [...two], raw }
    const calls = mockBackend(backend)
    render(Settings)
    await selectAccount('uuid-home')
    await fireEvent.click(screen.getByRole('button', { name: 'Reload' }))
    expect(await screen.findByText(/THE-REMOVED-ACCOUNTS-BODY/)).toBeTruthy()

    // The removal the widget really performs: the account leaves the list and
    // the backend announces it.
    backend.accounts = two.filter((a) => a.account_id !== 'uuid-home')
    await whenSubscribed(calls)

    await waitFor(() =>
      expect(screen.queryByText(/THE-REMOVED-ACCOUNTS-BODY/)).toBeNull(),
    )
    // And the panel says what is true afterwards, rather than the "has not
    // been polled" claim it has no basis for — nothing is selected any more.
    expect(screen.getByText('Select an account and press Reload.')).toBeTruthy()
  })

  it('marks a truncated body as truncated rather than showing it as whole', async () => {
    const raw: RawResponse = {
      captured_at: '2026-07-31T09:00:00Z',
      status: 200,
      truncated: true,
      body: '{"five_hour":{"utilization":41}}',
    }
    mockBackend({ accounts: two, raw })
    render(Settings)
    await selectAccount('uuid-work')

    await fireEvent.click(screen.getByRole('button', { name: 'Reload' }))
    expect(await screen.findByText(/truncated at 64 KiB/)).toBeTruthy()
    expect(screen.getByText('{"five_hour":{"utilization":41}}')).toBeTruthy()
  })

  /**
   * The actual collision `accountKey` exists for: two accounts sharing an id
   * under different providers. Keying the `<option>` `{#each}` by
   * `a.account_id` alone would make Svelte throw `each_key_duplicate` at
   * render time — this test's `render()` call is where that would surface —
   * and reloading the Codex option must send `last_response` *its* provider,
   * not silently resolve to whichever account the bare id matches first.
   */
  it('offers two distinct options, and reloads with the selected one\'s own provider, for accounts sharing an id', async () => {
    const claude: AccountView = {
      account_id: 'same-id',
      provider: 'anthropic',
      label: 'Claude',
      email: 'claude@example.com',
      state: { kind: 'loading' },
    }
    const codex: AccountView = {
      account_id: 'same-id',
      provider: 'openai',
      label: 'Codex',
      email: 'codex@example.com',
      state: { kind: 'loading' },
    }
    const calls = mockBackend({ accounts: [claude, codex], raw: null })
    render(Settings)

    const select = (await screen.findByLabelText('Account')) as HTMLSelectElement
    await waitFor(() => expect(select.options.length).toBe(3))
    const values = Array.from(select.options, (o) => o.value)
    expect(new Set(values).size).toBe(3)

    await fireEvent.change(select, { target: { value: accountKey('same-id', 'openai') } })
    await fireEvent.click(screen.getByRole('button', { name: 'Reload' }))

    await waitFor(() => expect(calls.some((c) => c.cmd === 'last_response')).toBe(true))
    const sent = calls.find((c) => c.cmd === 'last_response')
    expect(sent?.args).toEqual({ uuid: 'same-id', provider: 'openai' })
  })
})

/**
 * docs/design.md §10.3. The paste path is offered **only** once the loopback
 * half cannot finish, so every one of these starts from a window that is not
 * showing it.
 */
describe('Settings manual login fallback', () => {
  const MANUAL = 'https://claude.com/cai/oauth/authorize?redirect_uri=manual'

  /**
   * `whenSubscribed` only proves `accounts://changed` is live, and the window
   * awaits its three `listen` calls in order — so this one can still be
   * unsubscribed at that point. Re-emitting until the block appears is the same
   * shape `whenSubscribed` itself uses, for the same reason.
   */
  async function whenFallbackDelivered(reason: string): Promise<void> {
    await waitFor(async () => {
      await emit('auth://manual-fallback', { url: MANUAL, reason })
      expect(screen.getByText(new RegExp(reason))).toBeTruthy()
    })
  }

  it('shows nothing about pasting until the loopback path gives up', async () => {
    mockBackend()
    render(Settings)
    await settle()
    expect(screen.queryByLabelText('Code from the page')).toBeNull()
  })

  /**
   * The two background failures — no reply, or an unreadable one — arrive as
   * `auth://manual-fallback`. The reason is shown verbatim because it is the
   * only thing telling the user why they are suddenly copying a link.
   */
  it('offers the link and a paste box when the background half gives up', async () => {
    const calls = mockBackend()
    render(Settings)
    await whenSubscribed(calls)

    await whenFallbackDelivered('no reply arrived')

    expect(screen.getByText(MANUAL)).toBeTruthy()
    expect(screen.getByLabelText('Code from the page')).toBeTruthy()
  })

  /**
   * A bind failure never reaches Rust's event path — `begin_login` reports it
   * in its own answer — so this must not wait for an event that will not come.
   */
  it('offers the paste path immediately when no loopback port could be bound', async () => {
    mockBackend({ loginUrls: { loopback: null, manual: MANUAL } })
    render(Settings)
    await settle()

    await fireEvent.click(screen.getByText('Add Claude account'))
    await settle()

    expect(screen.getByText(MANUAL)).toBeTruthy()
    expect(screen.getByText(/no local port/)).toBeTruthy()
  })

  it('sends the pasted line to the backend verbatim', async () => {
    const calls = mockBackend({ loginUrls: { loopback: null, manual: MANUAL } })
    render(Settings)
    await settle()
    await fireEvent.click(screen.getByText('Add Claude account'))
    await settle()

    await fireEvent.input(screen.getByLabelText('Code from the page'), {
      target: { value: 'the-code#the-state' },
    })
    await fireEvent.click(screen.getByText('Submit'))
    await settle()

    const sent = calls.find((c) => c.cmd === 'submit_manual_code')
    expect(sent?.args.pasted).toBe('the-code#the-state')
  })

  /**
   * The login is over however it finished, so the form goes with it. Left up,
   * it invites a code for a login that no longer exists — which the backend
   * would then refuse as belonging to an older attempt.
   */
  it('retires the paste form once the login lands', async () => {
    const calls = mockBackend()
    render(Settings)
    await whenSubscribed(calls)

    await whenFallbackDelivered('no reply arrived')
    expect(screen.getByLabelText('Code from the page')).toBeTruthy()

    await emit('accounts://changed')
    await settle()
    expect(screen.queryByLabelText('Code from the page')).toBeNull()
  })

  /**
   * A refusal is not the end of the attempt: the user may have mistyped, and
   * making them fetch the URL again would be the fix that costs more than the
   * fault.
   */
  it('keeps the form up when the backend refuses the code', async () => {
    mockBackend({
      loginUrls: { loopback: null, manual: MANUAL },
      submitError: 'that code belongs to an older login attempt',
    })
    render(Settings)
    await settle()
    await fireEvent.click(screen.getByText('Add Claude account'))
    await settle()

    await fireEvent.input(screen.getByLabelText('Code from the page'), {
      target: { value: 'stale#code' },
    })
    await fireEvent.click(screen.getByText('Submit'))
    await settle()

    expect(screen.getByText(/older login attempt/)).toBeTruthy()
    expect(screen.getByLabelText('Code from the page')).toBeTruthy()
  })
})

/** docs/design.md §11.3. */
describe('Settings start at login', () => {
  it('shows the state the backend reports, not a guess', async () => {
    mockBackend({ autostart: { enabled: true, writable: true } })
    render(Settings)
    await settle()
    expect((screen.getByLabelText(/Launch Quota Board/) as HTMLInputElement).checked).toBe(true)
  })

  it('sends the new value', async () => {
    const calls = mockBackend({ autostart: { enabled: false, writable: true } })
    render(Settings)
    await settle()

    await fireEvent.click(screen.getByLabelText(/Launch Quota Board/))
    await settle()

    expect(calls.find((c) => c.cmd === 'set_autostart')?.args.enabled).toBe(true)
  })

  /**
   * §11.3's command answers with what the OS reports *afterwards*, which is not
   * always what was asked for. The window has to render that answer — showing
   * the click instead would tell the user autostart is on when the OS declined
   * it, which is the confidently-wrong display CLAUDE.md forbids.
   *
   * The mock deliberately disagrees with the request: a test where the answer
   * matches the click cannot tell the two apart, and an earlier version of this
   * one could not.
   */
  it('renders the answer the backend gave, not the click that was made', async () => {
    mockBackend({
      autostart: { enabled: false, writable: true },
      autostartApplied: { enabled: false, writable: true },
    })
    render(Settings)
    await settle()

    await fireEvent.click(screen.getByLabelText(/Launch Quota Board/))
    await settle()

    expect((screen.getByLabelText(/Launch Quota Board/) as HTMLInputElement).checked).toBe(false)
  })

  /**
   * §11.3's pitfall: the plugin resolves its target with `current_exe()`, so a
   * development build would register the build directory. The control is
   * disabled and says why, rather than offering a toggle that always fails.
   */
  it('disables the control and explains itself in a development build', async () => {
    mockBackend({ autostart: { enabled: false, writable: false } })
    render(Settings)
    await settle()

    expect((screen.getByLabelText(/Launch Quota Board/) as HTMLInputElement).disabled).toBe(true)
    expect(screen.getByText(/development build/)).toBeTruthy()
  })

  /**
   * The click already moved the DOM checkbox. Re-rendering from an unchanged
   * object would not move it back, so a refused change would sit there looking
   * applied — the confidently-wrong display CLAUDE.md forbids, in miniature.
   */
  it('puts the box back when the backend refuses', async () => {
    mockBackend({
      autostart: { enabled: false, writable: true },
      autostartError: 'this is a development build',
    })
    render(Settings)
    await settle()

    await fireEvent.click(screen.getByLabelText(/Launch Quota Board/))
    await settle()

    expect((screen.getByLabelText(/Launch Quota Board/) as HTMLInputElement).checked).toBe(false)
    expect(screen.getByText(/development build/)).toBeTruthy()
  })
})
