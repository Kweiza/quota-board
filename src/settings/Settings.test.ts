import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { emit } from '@tauri-apps/api/event'
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks'
import { tick } from 'svelte'
import { afterEach, describe, expect, it } from 'vitest'
import Settings from './Settings.svelte'
import type { AccountView, RawResponse, SettingsView, StoreStatus } from '../lib/types'

type IpcCall = { cmd: string; args: Record<string, unknown> }

interface Backend {
  accounts?: AccountView[]
  /** What `get_settings` answers with. */
  settings?: SettingsView
  /** What `set_settings` answers with — the value the backend *applied*. */
  applied?: SettingsView
  status?: StoreStatus
  /** What `unlock_secrets` answers with — the store that is now open. */
  unlocked?: StoreStatus
  /** Rejects `begin_login` with this message, as the Rust single-flight does. */
  loginError?: string
  raw?: RawResponse | null
}

const account = (uuid: string, label: string, email: string): AccountView => ({
  uuid,
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
  mockIPC((cmd, args) => {
    calls.push({ cmd, args: (args ?? {}) as Record<string, unknown> })
    switch (cmd) {
      case 'list_accounts':
        return b.accounts ?? []
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
        return 'https://claude.ai/oauth/authorize?code_challenge=x'
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

    await fireEvent.click(await screen.findByRole('button', { name: 'Add account' }))
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
  const selectAccount = async (uuid: string): Promise<void> => {
    const select = (await screen.findByLabelText('Account')) as HTMLSelectElement
    // The options only exist after the awaited `list_accounts` resolves, and
    // assigning a value with no matching `<option>` is silently dropped — the
    // "nothing selected" branch would then render and a named assertion would
    // pass against the wrong thing.
    await waitFor(() => expect(select.options.length).toBe(two.length + 1))
    await fireEvent.change(select, { target: { value: uuid } })
    expect(select.value).toBe(uuid)
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
})
