import { mount } from 'svelte'
import { getCurrentWindow, LogicalSize } from '@tauri-apps/api/window'
// Keep this import. The reset it carries is what keeps the widget inside its
// own window; dropping it silently widens the document past 280px.
import './app.css'
import Widget from './widget/Widget.svelte'
import {
  inTauri,
  isSettingsWindow,
  listAccounts,
  onUsageUpdated,
  openSettings,
  setWidgetVisible,
} from './lib/ipc'
import { widgetProps } from './lib/props.svelte'

/** docs/design.md §8.1: "Fixed width of about 280px; height follows content." */
const WIDGET_WIDTH = 280

/**
 * The window cannot measure the DOM, so the view measures itself and pushes
 * the height back. `StateFlags::SIZE` is deliberately off in
 * `src-tauri/src/main.rs`: a restored height would fight this on every launch.
 */
function followContentHeight(root: HTMLElement): void {
  // Absent when the page is opened in a plain browser, e.g. `npm run dev`.
  if (!('__TAURI_INTERNALS__' in window)) return
  const appWindow = getCurrentWindow()
  // Both windows load the same document, so this stays even now that the
  // settings route no longer reaches here: only the widget window may be
  // resized to widget dimensions.
  if (appWindow.label !== 'widget') return

  new ResizeObserver(() => {
    const height = Math.ceil(root.getBoundingClientRect().height)
    if (height > 0) void appWindow.setSize(new LogicalSize(WIDGET_WIDTH, height))
  }).observe(root)
}

/**
 * A click on a remedy must not vanish silently while its owner task is
 * outstanding. **Neither remedy is Task 17's.** Re-login is Task 18's
 * `begin_login`, and Task 18 also owns the unlock prompt — it is the only task
 * with a settings surface to put a passphrase field on (§9.2 asks for one on
 * every run of the fallback store). If Task 18 does not take the unlock prompt,
 * the button must be removed rather than left dead: §7.1 makes that click the
 * only remedy `SECRETS_LOCKED` carries.
 */
function pending(what: string): void {
  console.warn(`quoata-board: ${what} is not wired up yet`)
}

const target = document.getElementById('app')!

// Both windows load index.html; the query string in tauri.conf.json is what
// tells them apart. An if/else rather than a ternary because only one branch
// takes props (docs/design.md §8.4).
if (isSettingsWindow()) {
  // Task 18 mounts the real settings view here. Until then the window is
  // routed and visibly identifiable, so the gear can be verified end to end.
  target.textContent = 'Settings (Task 18)'
} else {
  // The gear is the only route into the settings window (§8.4), so this
  // wiring is what makes that window reachable at all.
  widgetProps.onOpenSettings = () => void openSettings()
  widgetProps.onRelogin = (uuid: string) => pending(`re-login for account ${uuid} (Task 18)`)
  widgetProps.onUnlock = (uuid: string) =>
    pending(`unlocking the token store for account ${uuid} (Task 18)`)

  // `props: widgetProps`, never `{ ...widgetProps }`: a spread copies the
  // values out of the `$state` proxy and the widget stops reacting to any
  // later assignment.
  mount(Widget, { target, props: widgetProps })

  followContentHeight(target)

  async function pull(): Promise<void> {
    try {
      widgetProps.accounts = await listAccounts()
    } catch (e) {
      // A failed command is not a reason to blank the widget: the last list
      // stays on screen. Never demote to an empty or zero state.
      console.error('quoata-board: list_accounts failed', e)
    }
  }

  if (inTauri()) {
    void pull()
    void onUsageUpdated(() => void pull())

    // §6.3. Registered inside the widget branch only. Both windows load
    // index.html (tauri.conf.json), so a listener at module scope would report
    // the *settings* window's visibility into the widget's single gate — and
    // src-tauri/src/main.rs makes hiding the settings window its normal
    // condition, so closing settings would stop the widget polling.
    const report = () => void setWidgetVisible(document.visibilityState === 'visible')
    document.addEventListener('visibilitychange', report)
    // The initial state too, not only the transitions: the widget starts with
    // `visible: false` in tauri.conf.json and is shown from setup().
    report()
  }
}
