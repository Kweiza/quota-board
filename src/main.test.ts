import { clearMocks, mockIPC, mockWindows } from '@tauri-apps/api/mocks'
import type { LogicalSize } from '@tauri-apps/api/dpi'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * `src/main.ts` is the entry point: it does its work at import time, so every
 * test here drives it with `vi.resetModules()` + a dynamic `import()` rather
 * than by calling anything. That is also why the whole module is imported
 * through the real `@tauri-apps/api` mock seam instead of a hand written stub —
 * the two branch conditions it takes (`isSettingsWindow()`, `inTauri()`) both
 * read real globals.
 */
type IpcCall = { cmd: string; args: Record<string, unknown> }

/** The events `listen()` has been asked for, in order. */
function listenedEvents(calls: IpcCall[]): unknown[] {
  return calls.filter((c) => c.cmd === 'plugin:event|listen').map((c) => c.args.event)
}

function mockBackend(accounts: unknown[] = []): IpcCall[] {
  const calls: IpcCall[] = []
  mockIPC((cmd, args) => {
    calls.push({ cmd, args: (args ?? {}) as Record<string, unknown> })
    switch (cmd) {
      case 'list_accounts':
        return accounts
      case 'get_settings':
        return {
          poll_interval_secs: 300,
          min_interval_secs: 180,
          max_interval_secs: 86400,
          warning: null,
          writable: true,
          auto_sort: false,
        }
      case 'store_status':
        return { description: 'a token store', kind: 'keychain', fallback_file_exists: false }
      default:
        return null
    }
  })
  return calls
}

/** Every `ResizeObserver` callback `followContentHeight` registered. */
let observed: Array<() => void> = []

/** Routes the document to one of the two windows, the way tauri.conf.json does. */
function route(which: 'widget' | 'settings'): HTMLElement {
  window.history.replaceState({}, '', which === 'settings' ? '/?window=settings' : '/')
  const target = document.createElement('div')
  target.id = 'app'
  document.body.appendChild(target)
  return target
}

beforeEach(() => {
  vi.resetModules()
  // jsdom implements neither, and `followContentHeight` observes the mount
  // target inside a Tauri webview. Stubbed rather than skipped so the widget
  // branch under test is the shipped one.
  observed = []
  vi.stubGlobal(
    'ResizeObserver',
    class {
      constructor(private readonly cb: () => void) {}
      observe(): void {
        // Captured rather than dropped: `followContentHeight` pushes the
        // window's *width* back now, so the callback is the only place the
        // two-column width is decided and a stub that swallowed it would leave
        // that decision untested.
        observed.push(this.cb)
      }
      unobserve(): void {}
      disconnect(): void {}
    },
  )
})

afterEach(() => {
  // `clearMocks()` deletes `__TAURI_EVENT_PLUGIN_INTERNALS__`, which a mounted
  // component's `onDestroy` unlisten needs. Nothing here unmounts, so the order
  // that matters is only that the next test starts from a clean document.
  clearMocks()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
  window.history.replaceState({}, '', '/')
})

describe('main.ts widget branch', () => {
  it('refreshes on accounts://changed as well as usage://updated', async () => {
    // The path that does not go through the poll gate. `usage://updated` only
    // arrives from a poll, and the poll is gated on the widget being visible —
    // which a login clears, because it sends the user to a browser. Without
    // this listener, "add an account and it appears" depends on that gate.
    const calls = mockBackend()
    mockWindows('widget')
    route('widget')

    await import('./main')

    expect(listenedEvents(calls)).toEqual(['usage://updated', 'accounts://changed'])
    expect(calls.some((c) => c.cmd === 'list_accounts')).toBe(true)
  })

  it('mounts the widget, not the settings window', async () => {
    const calls = mockBackend()
    mockWindows('widget')
    const target = route('widget')

    await import('./main')

    expect(target.querySelector('.widget')).toBeTruthy()
    // §6.3's report is registered in this branch and only this branch.
    expect(calls.some((c) => c.cmd === 'set_widget_visible')).toBe(true)
  })

  /**
   * docs/design.md §8.1. The width is no longer a constant, and the only place
   * it is decided is this callback — so a widget that had grown a second
   * provider's column while the window stayed 280px wide would show two
   * columns squeezed to 130px each, every bar row wrapped, with nothing in the
   * suite objecting.
   */
  describe('window sizing', () => {
    const account = (provider: string) => ({
      account_id: `${provider}-1`,
      provider,
      label: provider,
      email: `${provider}@example.com`,
      state: { kind: 'loading' },
    })

    /** jsdom lays nothing out, so the height has to come from somewhere. */
    function stubHeight(px: number): void {
      vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
        height: px,
        width: 0,
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      })
    }

    /**
     * `setSize` sends a `Size` wrapping the `LogicalSize` itself, and `mockIPC`
     * hands over the live object rather than its serialized form — so the
     * assertion reaches through `value.size` instead of matching a plain
     * `{ width, height }`. `type` is asserted alongside: a `PhysicalSize` would
     * satisfy the numbers and still be the wrong size on any display whose
     * scale factor is not 1.
     */
    const sizes = (calls: IpcCall[]): unknown[] =>
      calls
        .filter((c) => c.cmd.endsWith('set_size'))
        .map((c) => {
          const size = (c.args.value as { size: LogicalSize }).size
          return { type: size.type, width: size.width, height: size.height }
        })

    it('keeps the single-column width while only one provider has accounts', async () => {
      const calls = mockBackend([account('anthropic')])
      mockWindows('widget')
      route('widget')
      stubHeight(140)

      await import('./main')
      await vi.waitFor(() => expect(observed.length).toBeGreaterThan(0))
      for (const fire of observed) fire()

      expect(sizes(calls).length).toBeGreaterThan(0)
      for (const size of sizes(calls)) {
        expect(size).toEqual({ type: 'Logical', width: 280, height: 140 })
      }
    })

    it('widens to the two-column width once both providers have accounts', async () => {
      const calls = mockBackend([account('anthropic'), account('openai')])
      mockWindows('widget')
      route('widget')
      stubHeight(180)

      await import('./main')
      // The list has to have landed first: the width is a function of it, and
      // firing the observer before `list_accounts` resolves would measure the
      // empty widget and prove nothing.
      await vi.waitFor(() => {
        expect(calls.some((c) => c.cmd === 'list_accounts')).toBe(true)
        expect(observed.length).toBeGreaterThan(0)
      })
      for (const fire of observed) fire()

      const last = sizes(calls).at(-1)
      expect(last).toEqual({ type: 'Logical', width: 520, height: 180 })
    })
  })

  it('leaves the loading state only after the first account reads complete', async () => {
    mockBackend()
    mockWindows('widget')
    const target = route('widget')

    await import('./main')

    await vi.waitFor(() =>
      expect(target.textContent).toContain('Add a Claude or Codex account in Settings'),
    )
    expect(target.textContent).not.toContain('Loading accounts…')
  })
})

describe('main.ts settings branch', () => {
  it('mounts the settings view rather than placeholder text', async () => {
    mockBackend()
    mockWindows('settings')
    const target = route('settings')

    await import('./main')

    expect(target.textContent).not.toContain('Task 18')
    // The section headings the settings window owns; a placeholder has none.
    expect(target.textContent).toContain('Accounts')
    expect(target.textContent).toContain('Token store')
  })

  it('never reports this window visibility into the widget polling gate', async () => {
    // Both windows load index.html, and closing the settings window is a hide.
    // A `set_widget_visible` from here would stop the widget polling the moment
    // settings is closed.
    //
    // Asserted through spies on the two registrations rather than by
    // dispatching the events: `vi.resetModules()` gives each test a fresh
    // module, but the *document* is shared, so a listener the widget branch
    // registered in an earlier test is still attached and would answer a
    // dispatch here. Measured — it reported four `set_widget_visible` calls for
    // an already-correct settings branch. The spies only see this test's calls.
    const calls = mockBackend()
    const onDocument = vi.spyOn(document, 'addEventListener')
    const onWindow = vi.spyOn(window, 'addEventListener')
    mockWindows('settings')
    route('settings')

    await import('./main')

    expect(calls.filter((c) => c.cmd === 'set_widget_visible')).toEqual([])
    expect(onDocument.mock.calls.map((c) => c[0])).not.toContain('visibilitychange')
    expect(onWindow.mock.calls.map((c) => c[0])).not.toContain('pageshow')
  })
})
