import { emit } from '@tauri-apps/api/event'
import { clearMocks, mockIPC, mockWindows } from '@tauri-apps/api/mocks'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
// Imported at module scope on purpose. `getCurrentWindow()` reads
// `window.__TAURI_INTERNALS__.metadata` and throws outside a Tauri webview, so
// if it were ever hoisted back out of the mousedown handler this import alone
// would fail the whole file — which is the failure `npm run dev` in a plain
// browser would otherwise hit.
import {
  beginLogin,
  enableDrag,
  isSettingsWindow,
  lastResponse,
  onAccountsChanged,
  onAuthFailed,
  openSettings,
  refreshAccount,
  renameAccount,
  reorderAccounts,
  setSettings,
} from './ipc'
import type { RawResponse, SettingsView } from './types'

/**
 * Records every IPC command the real `@tauri-apps/api` code path emits, so the
 * assertions below are about observable behaviour rather than about a hand
 * written stub of the API. `labels` is what `get_all_windows` answers with.
 */
function recordIpc(labels: string[]): Array<{ cmd: string; label: unknown }> {
  const calls: Array<{ cmd: string; label: unknown }> = []
  mockIPC((cmd, args) => {
    calls.push({ cmd, label: (args as { label?: unknown } | undefined)?.label })
    if (cmd === 'plugin:window|get_all_windows') return labels
    return null
  })
  return calls
}

type IpcCall = { cmd: string; args: Record<string, unknown> }

/**
 * A second recorder, deliberately **not** a widening of `recordIpc`: the three
 * `describe` blocks below assert on exact arrays of `{ cmd, label }`, so giving
 * that helper a whole-`args` field would rewrite assertions this step does not
 * own. The command wrappers are contracts about argument *shape*, which is the
 * one thing `recordIpc` throws away.
 */
function recordArgs(reply: (cmd: string) => unknown = () => null): IpcCall[] {
  const calls: IpcCall[] = []
  mockIPC((cmd, args) => {
    calls.push({ cmd, args: (args ?? {}) as Record<string, unknown> })
    return reply(cmd)
  })
  return calls
}

/** A card with a gear inside it, matching the widget's real structure. */
function card(): { el: HTMLElement; gear: HTMLButtonElement } {
  const el = document.createElement('div')
  el.innerHTML = '<div class="titlebar"><button class="gear">⚙</button></div><span>work@example.com</span>'
  document.body.appendChild(el)
  return { el, gear: el.querySelector('button')! }
}

/**
 * `detail` defaults to 0 on a synthetic event. A real primary click reports 1,
 * and a test built on the default would assert against an event no user can
 * produce.
 */
function mousedown(on: Element, buttons: number): void {
  on.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, buttons, detail: 1 }))
}

afterEach(() => {
  clearMocks()
  document.body.innerHTML = ''
  vi.restoreAllMocks()
})

describe('isSettingsWindow', () => {
  const at = (search: string): boolean => {
    window.history.replaceState(null, '', `/${search}`)
    return isSettingsWindow()
  }

  it('is true for the settings window URL declared in tauri.conf.json', () => {
    expect(at('?window=settings')).toBe(true)
  })

  it('is false with no query string, which is how the widget window loads', () => {
    expect(at('')).toBe(false)
  })

  it('is false for any other value of the parameter', () => {
    expect(at('?window=widget')).toBe(false)
  })

  it('finds the parameter wherever it sits, not only first', () => {
    expect(at('?debug=1&window=settings')).toBe(true)
  })
})

describe('enableDrag', () => {
  beforeEach(() => {
    mockWindows('widget')
  })

  it('starts dragging the current window on a primary press', () => {
    const calls = recordIpc(['widget', 'settings'])
    const { el } = card()
    enableDrag(el)

    mousedown(el, 1)

    expect(calls).toEqual([{ cmd: 'plugin:window|start_dragging', label: 'widget' }])
  })

  it('drags when the press lands on ordinary card content, not just the titlebar', () => {
    const calls = recordIpc(['widget'])
    const { el } = card()
    enableDrag(el)

    mousedown(el.querySelector('span')!, 1)

    expect(calls.map((c) => c.cmd)).toEqual(['plugin:window|start_dragging'])
  })

  // The whole card is draggable, so without this guard the gear would begin a
  // drag and macOS could swallow the button release that makes it a click —
  // and the gear is the only route into the settings window (docs/design.md
  // §8.4).
  it('does not start a drag when the press lands on a control', () => {
    const calls = recordIpc(['widget'])
    const { el, gear } = card()
    enableDrag(el)

    mousedown(gear, 1)

    expect(calls).toEqual([])
  })

  // A secondary press is a context-menu gesture. docs/design.md §8.3 is
  // explicit that only `buttons === 1` drags.
  it('does not start a drag on a secondary press', () => {
    const calls = recordIpc(['widget'])
    const { el } = card()
    enableDrag(el)

    mousedown(el, 2)

    expect(calls).toEqual([])
  })

  it('does not start a drag when a second button is held down with the primary', () => {
    const calls = recordIpc(['widget'])
    const { el } = card()
    enableDrag(el)

    mousedown(el, 3)

    expect(calls).toEqual([])
  })

  it('stops dragging once destroyed', () => {
    const calls = recordIpc(['widget'])
    const { el } = card()
    const handle = enableDrag(el)

    handle.destroy()
    mousedown(el, 1)

    expect(calls).toEqual([])
  })

  it('touches no Tauri API until a press arrives, so a plain browser can load the page', () => {
    clearMocks()
    const { el } = card()
    expect(() => enableDrag(el).destroy()).not.toThrow()
  })
})

describe('openSettings', () => {
  it('finds the settings window, then shows and focuses it, in that order', async () => {
    const calls = recordIpc(['widget', 'settings'])

    await openSettings()

    expect(calls).toEqual([
      { cmd: 'plugin:window|get_all_windows', label: undefined },
      { cmd: 'plugin:window|show', label: 'settings' },
      { cmd: 'plugin:window|set_focus', label: 'settings' },
    ])
  })

  it('never acts on the widget window by mistake', async () => {
    const calls = recordIpc(['widget', 'settings'])

    await openSettings()

    expect(calls.filter((c) => c.label === 'widget')).toEqual([])
  })

  // Unreachable while both windows are declared in tauri.conf.json. It is
  // logged rather than ignored so that deleting the declaration cannot make
  // the gear fail in silence.
  it('warns instead of failing silently when the window is not declared', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const calls = recordIpc(['widget'])

    await expect(openSettings()).resolves.toBeUndefined()

    expect(warn).toHaveBeenCalledOnce()
    expect(calls.map((c) => c.cmd)).toEqual(['plugin:window|get_all_windows'])
  })
})

/**
 * `mockIPC` runs the wrapper only — no `#[tauri::command]` body executes here,
 * so none of this stands in for the Rust-side tests. What it pins is the two
 * halves of the contract a webview can get wrong silently: the command name and
 * the argument shape. A misspelled key reaches the user as a command that
 * rejects at runtime with nothing on the JS side to catch it.
 */
describe('command wrappers', () => {
  it('beginLogin invokes the begin_login command with the requested provider and returns the URL', async () => {
    const url = 'https://claude.ai/oauth/authorize?code_challenge=abc'
    const calls = recordArgs((cmd) => (cmd === 'begin_login' ? url : null))

    await expect(beginLogin('openai')).resolves.toBe(url)

    expect(calls).toEqual([{ cmd: 'begin_login', args: { provider: 'openai' } }])
  })

  // Tauri v2 maps a camelCase key on this side onto the snake_case parameter of
  // the command. This is the only multi-word argument the settings window
  // sends, so it is the only place that mapping is exercised at all.
  it('setSettings sends the interval under the camelCase key Tauri maps', async () => {
    const view: SettingsView = {
      poll_interval_secs: 300,
      min_interval_secs: 180,
      max_interval_secs: 3600,
      warning: null,
      writable: true,
    }
    const calls = recordArgs((cmd) => (cmd === 'set_settings' ? view : null))

    await expect(setSettings(300)).resolves.toEqual(view)

    expect(calls).toEqual([{ cmd: 'set_settings', args: { pollIntervalSecs: 300 } }])
  })

  /**
   * §9.3: the primary key is the pair, so a refresh press has to name which
   * provider's account it means — the fourth command this same rule binds,
   * alongside remove/rename/reorder.
   */
  it('refreshAccount sends the uuid and the provider, in that shape', async () => {
    const calls = recordArgs((cmd) => (cmd === 'refresh_account' ? { kind: 'loading' } : null))

    await refreshAccount('acct-1', 'openai')

    expect(calls).toEqual([{ cmd: 'refresh_account', args: { uuid: 'acct-1', provider: 'openai' } }])
  })

  it('renameAccount sends the uuid, the provider and the label, in that shape', async () => {
    const calls = recordArgs()

    await renameAccount('acct-1', 'openai', 'Work')

    expect(calls).toEqual([
      { cmd: 'rename_account', args: { uuid: 'acct-1', provider: 'openai', label: 'Work' } },
    ])
  })

  /**
   * §9.3: the primary key is the pair, so the wire has to carry the provider
   * for every key in a reorder, not just the id half.
   */
  it('reorderAccounts sends each account as a (provider, id) pair', async () => {
    const calls = recordArgs()

    await reorderAccounts([
      { account_id: 'acct-2', provider: 'openai' },
      { account_id: 'acct-1', provider: 'anthropic' },
    ])

    expect(calls).toEqual([
      {
        cmd: 'reorder_accounts',
        args: {
          keys: [
            { account_id: 'acct-2', provider: 'openai' },
            { account_id: 'acct-1', provider: 'anthropic' },
          ],
        },
      },
    ])
  })

  it('lastResponse returns the captured response keyed by uuid', async () => {
    const captured: RawResponse = {
      captured_at: '2026-07-31T09:00:00Z',
      status: 200,
      truncated: false,
      body: '{"five_hour":{"utilization":42}}',
    }
    const calls = recordArgs((cmd) => (cmd === 'last_response' ? captured : null))

    await expect(lastResponse('acct-1')).resolves.toEqual(captured)

    expect(calls).toEqual([{ cmd: 'last_response', args: { uuid: 'acct-1' } }])
  })

  // `null` means "nothing captured for this account yet", which the debug panel
  // renders differently from an empty body. A `??` default anywhere on this
  // path would erase that distinction — CLAUDE.md's never-demote rule.
  it('lastResponse passes a null capture through unchanged', async () => {
    recordArgs()

    await expect(lastResponse('acct-1')).resolves.toBeNull()
  })
})

describe('event subscriptions', () => {
  /**
   * `shouldMockEvents` makes `listen`/`emit` round-trip inside the mock, so
   * these assert delivery rather than inspecting the arguments of
   * `plugin:event|listen`. A wrapper subscribed to the wrong event name then
   * fails by receiving nothing, which is exactly how it would fail in the app.
   */
  const withEvents = (): void => {
    mockIPC(() => null, { shouldMockEvents: true })
  }

  // The refresh path that does not traverse the poll loop's visibility gate.
  // Until this task nothing listened for `accounts://changed` at all, so
  // "add an account and see it in the widget" rested on WKWebView's
  // `visibilityState` behaviour.
  it('onAccountsChanged subscribes to the event the commands emit', async () => {
    withEvents()
    const fn = vi.fn()
    await onAccountsChanged(fn)

    await emit('accounts://changed')

    expect(fn).toHaveBeenCalledOnce()
  })

  it('onAuthFailed hands the callback the message, not the event envelope', async () => {
    withEvents()
    const fn = vi.fn()
    await onAuthFailed(fn)

    await emit('auth://failed', 'the login timed out')

    expect(fn).toHaveBeenCalledExactlyOnceWith('the login timed out')
  })
})
