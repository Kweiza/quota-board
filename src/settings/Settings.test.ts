import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks'
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
 * unnamed — `plugin:event|listen` in particular — answers `null`, which is what
 * the mocked event plugin expects.
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
      case 'last_response':
        return b.raw ?? null
      default:
        return null
    }
  })
  return calls
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

describe('Settings token store', () => {
  it('the passphrase button says Set a passphrase when no fallback file exists', async () => {
    // The first passphrase *creates* the store, so it cannot be verified and a
    // typo is permanent. The wording is the only warning the user gets.
    const first = mockBackend({ status: store('no_backend', false) })
    const view = render(Settings)
    expect(await screen.findByRole('button', { name: 'Set a passphrase' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Unlock' })).toBeNull()
    expect(first.some((c) => c.cmd === 'store_status')).toBe(true)
    view.unmount()

    mockBackend({ status: store('encrypted_file', true) })
    render(Settings)
    expect(await screen.findByRole('button', { name: 'Unlock' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Set a passphrase' })).toBeNull()
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
