import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { WebviewWindow } from '@tauri-apps/api/webviewWindow'
import type { AccountView } from './types'

/**
 * Manual dragging. `data-tauri-drag-region` is deliberately not used:
 * (a) in v2 the attribute applies only to the element it is on, so every child
 *     would need its own copy;
 * (b) it has a built-in double-click-to-maximize that cannot be turned off, and
 *     `maximizable: false` does not work on Linux, so the widget could maximize;
 * (c) it breaks under the isolation pattern.
 * docs/design.md §8.3.
 */
export function enableDrag(el: HTMLElement): { destroy(): void } {
  const onMouseDown = (e: MouseEvent) => {
    // Primary button only. On mousedown `buttons` already includes the button
    // being pressed, so 1 means "primary, alone".
    if (e.buttons !== 1) return
    // A drag started on a control must not swallow that control's click.
    if ((e.target as HTMLElement).closest('button, a, input')) return
    // Resolved here rather than at module scope: `getCurrentWindow()` reads
    // `__TAURI_INTERNALS__` and throws outside a Tauri webview, which would
    // break `npm run dev` in a plain browser and every test that imports this.
    // Not awaited on purpose: awaiting first would end the user-gesture turn.
    void getCurrentWindow().startDragging()
  }

  el.addEventListener('mousedown', onMouseDown)
  return {
    destroy() {
      el.removeEventListener('mousedown', onMouseDown)
    },
  }
}

export async function openSettings(): Promise<void> {
  // getByLabel is async. Dropping the await yields a truthy Promise and the
  // null check below silently stops working.
  const existing = await WebviewWindow.getByLabel('settings')
  if (!existing) {
    // Both windows are declared in tauri.conf.json, so this is unreachable in
    // practice. Logged rather than ignored so a config change cannot make the
    // gear fail in silence.
    console.warn('settings window not found')
    return
  }
  await existing.show()
  await existing.setFocus()
}

export function isSettingsWindow(): boolean {
  return new URLSearchParams(location.search).get('window') === 'settings'
}

/** True inside a Tauri webview. `npm run dev` in a plain browser is not. */
export function inTauri(): boolean {
  return '__TAURI_INTERNALS__' in window
}

export const listAccounts = (): Promise<AccountView[]> => invoke('list_accounts')

export const setWidgetVisible = (visible: boolean): Promise<void> =>
  invoke('set_widget_visible', { visible })

export const onUsageUpdated = (fn: () => void): Promise<UnlistenFn> =>
  listen('usage://updated', fn)
