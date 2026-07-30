import { clearMocks, mockIPC, mockWindows } from '@tauri-apps/api/mocks'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
// Imported at module scope on purpose. `getCurrentWindow()` reads
// `window.__TAURI_INTERNALS__.metadata` and throws outside a Tauri webview, so
// if it were ever hoisted back out of the mousedown handler this import alone
// would fail the whole file — which is the failure `npm run dev` in a plain
// browser would otherwise hit.
import { enableDrag, isSettingsWindow, openSettings } from './ipc'

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
