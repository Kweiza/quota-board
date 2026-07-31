import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { WebviewWindow } from '@tauri-apps/api/webviewWindow'
import type {
  AccountState,
  AccountView,
  AutostartView,
  LoginUrls,
  ManualFallback,
  RawResponse,
  SettingsView,
  StoreStatus,
} from './types'

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

export const refreshAccount = (uuid: string): Promise<AccountState> =>
  invoke('refresh_account', { uuid })

export const beginLogin = (): Promise<LoginUrls> => invoke('begin_login')

/** §10.3's paste path. Rejects with a sentence meant for the user. */
export const submitManualCode = (pasted: string): Promise<void> =>
  invoke('submit_manual_code', { pasted })

/** docs/design.md §11.3. */
export const getAutostart = (): Promise<AutostartView> => invoke('get_autostart')

/** Answers with the state the OS reports afterwards, which can differ. */
export const setAutostart = (enabled: boolean): Promise<AutostartView> =>
  invoke('set_autostart', { enabled })

export const removeAccount = (uuid: string): Promise<void> =>
  invoke('remove_account', { uuid })

export const renameAccount = (uuid: string, label: string): Promise<void> =>
  invoke('rename_account', { uuid, label })

export const reorderAccounts = (uuids: string[]): Promise<void> =>
  invoke('reorder_accounts', { uuids })

export const storeStatus = (): Promise<StoreStatus> => invoke('store_status')

export const unlockSecrets = (passphrase: string): Promise<StoreStatus> =>
  invoke('unlock_secrets', { passphrase })

export const getSettings = (): Promise<SettingsView> => invoke('get_settings')

/**
 * The argument key is camelCase: Tauri v2 maps a camelCase key on the JS side
 * onto the snake_case parameter of the command. The three wrappers above ship
 * only single-word arguments, so nothing else in this file demonstrates it.
 */
export const setSettings = (pollIntervalSecs: number): Promise<SettingsView> =>
  invoke('set_settings', { pollIntervalSecs })

/**
 * docs/design.md §5.5's retained body, for the settings window's debug panel.
 * `null` means nothing has been captured for this account yet — **do not
 * coerce it**; the panel renders the two differently.
 */
export const lastResponse = (uuid: string): Promise<RawResponse | null> =>
  invoke('last_response', { uuid })

/**
 * The refresh path that does **not** depend on the visibility gate. The four
 * mutating commands emit this, and until now nothing listened for it: the
 * widget refreshes on `usage://updated`, whose poll-loop emitter is behind
 * `due()`'s own `!self.visible` early return — cited by name rather than by
 * line, because this task inserts code above it — and `begin_login`
 * structurally sends the user to a browser, which is exactly the stimulus that
 * clears that gate.
 */
export const onAccountsChanged = (fn: () => void): Promise<UnlistenFn> =>
  listen('accounts://changed', fn)

/** §10.3's flow completes in the background, so its failures arrive here. */
export const onAuthFailed = (fn: (message: string) => void): Promise<UnlistenFn> =>
  listen<string>('auth://failed', (e) => fn(e.payload))

/**
 * The loopback half gave up but the login can still be finished by hand.
 *
 * Distinct from `onAuthFailed` on purpose: this is not a dead login, and
 * reporting it as one would hide the half that still works. Only the two
 * background failures arrive here — a bind that never happened and an `openUrl`
 * that threw are seen by the webview itself, which already holds `manual`.
 */
export const onManualFallback = (fn: (f: ManualFallback) => void): Promise<UnlistenFn> =>
  listen<ManualFallback>('auth://manual-fallback', (e) => fn(e.payload))
