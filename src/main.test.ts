import { clearMocks, mockIPC, mockWindows } from '@tauri-apps/api/mocks'
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

function mockBackend(): IpcCall[] {
  const calls: IpcCall[] = []
  mockIPC((cmd, args) => {
    calls.push({ cmd, args: (args ?? {}) as Record<string, unknown> })
    switch (cmd) {
      case 'list_accounts':
        return []
      case 'get_settings':
        return {
          poll_interval_secs: 300,
          min_interval_secs: 180,
          max_interval_secs: 86400,
          warning: null,
          writable: true,
        }
      case 'store_status':
        return { description: 'a token store', kind: 'keychain', fallback_file_exists: false }
      default:
        return null
    }
  })
  return calls
}

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
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe(): void {}
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
