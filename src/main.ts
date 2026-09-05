import { mount } from 'svelte'
import { getCurrentWindow, LogicalSize } from '@tauri-apps/api/window'
// Keep this import. The reset it carries is what keeps the widget inside its
// own window; dropping it silently makes the document 8px wider than whichever
// width `widgetWidth` asked for.
import './app.css'
import Widget from './widget/Widget.svelte'
import Settings from './settings/Settings.svelte'
import {
  accountsWarning,
  inTauri,
  isSettingsWindow,
  listAccounts,
  onAccountsChanged,
  onUsageUpdated,
  openSettings,
  refreshAccount,
  setWidgetVisible,
} from './lib/ipc'
import { widgetWidth } from './lib/layout'
import { widgetProps } from './lib/props.svelte'
import type { Provider } from './lib/types'

/**
 * How often the widget re-reports its visibility (§6.3). The Rust side cannot
 * recover from a lost "visible" report on its own, so this bounds that failure
 * to one interval instead of forever. Well inside §6.1's 180-second polling
 * floor, so recovering costs at most one skipped cycle.
 */
const VISIBILITY_HEARTBEAT_MS = 30_000

/**
 * The window cannot measure the DOM, so the view measures itself and pushes
 * its size back. `StateFlags::SIZE` is deliberately off in
 * `src-tauri/src/main.rs`: a restored size would fight this on every launch.
 *
 * **The width is pushed back too, and it is not a constant any more** —
 * docs/design.md §8.1 widens the card to two columns once both providers have
 * an account. It is read from `widgetProps.accounts` rather than passed in,
 * because this observer outlives every account-list read: the same reactive
 * object the widget renders from is the one that decides how wide it must be,
 * so the two cannot answer differently.
 *
 * The re-measure that follows a width change comes for free: setting the size
 * reflows the document, which fires this observer again with the height the
 * new width actually produced. `Widget.svelte`'s `min-width` is what keeps
 * that second pass from being a visible jump — the document already laid
 * itself out at the wider size before the window caught up.
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
    if (height > 0) {
      void appWindow.setSize(new LogicalSize(widgetWidth(widgetProps.accounts), height))
    }
  }).observe(root)
}

const target = document.getElementById('app')!

// Both windows load index.html; the query string in tauri.conf.json is what
// tells them apart. An if/else rather than a ternary because only one branch
// takes props (docs/design.md §8.4).
if (isSettingsWindow()) {
  // Nothing else belongs in this branch. In particular no visibility
  // reporting: both windows load index.html, and reporting this window's
  // visibility into the widget's single gate would stop the widget polling the
  // moment settings is closed (see the widget branch below).
  mount(Settings, { target })
} else {
  // The gear is the only route into the settings window (§8.4), so this
  // wiring is what makes that window reachable at all.
  widgetProps.onOpenSettings = () => void openSettings()
  // §7.1 makes these clicks the only remedy AUTH_DEAD and SECRETS_LOCKED
  // carry. Both lead to the settings window rather than acting here: the
  // re-login needs the consent-screen note beside it (§10.2) and the unlock
  // needs a passphrase field, and neither belongs in a 280px widget. It also
  // keeps `opener:allow-open-url` in one capability instead of two —
  // `src-tauri/capabilities/widget.json` grants it to nobody.
  widgetProps.onRelogin = () => void openSettings()
  widgetProps.onUnlock = () => void openSettings()

  // §6.4's manual refresh, and the one handler that acts here instead of
  // deferring to the settings window: there is nothing to ask the user, and
  // sending them to another window to press a button is the friction this
  // control removes.
  //
  // `pull()` runs whatever the command answered, and that is not redundant with
  // `usage://updated`. A press the server has throttled (§6.2) returns the
  // current state early without polling and therefore without emitting, so the
  // event alone would leave the row unchanged with no sign the press was heard.
  //
  // The promise is returned, not `void`-ed: `AccountRow` awaits it to keep its
  // button disabled for the duration, and the press can wait on §6.1's global
  // permit. A failure is logged and swallowed — never allowed to reject into
  // the row, which would leave the button disabled forever.
  widgetProps.onRefresh = async (uuid: string, provider: Provider) => {
    try {
      await refreshAccount(uuid, provider)
    } catch (e) {
      console.error('quota-board: refresh_account failed', e)
    }
    // `pull` is a hoisted function declaration below; this closure only runs
    // once the user presses the button.
    await pull()
  }

  // `props: widgetProps`, never `{ ...widgetProps }`: a spread copies the
  // values out of the `$state` proxy and the widget stops reacting to any
  // later assignment.
  mount(Widget, { target, props: widgetProps })

  followContentHeight(target)

  async function pull(): Promise<void> {
    let accountsRead = false
    try {
      widgetProps.accounts = await listAccounts()
      accountsRead = true
    } catch (e) {
      // A failed command is not a reason to blank the widget: the last list
      // stays on screen. Never demote to an empty or zero state.
      console.error('quota-board: list_accounts failed', e)
    }
    try {
      // Read after the list, and separately: an empty list is only meaningful
      // once this says whether it is empty because there is nothing yet or
      // because the file could not be read.
      widgetProps.warning = await accountsWarning()
      // Empty is a claim, so expose it only after both halves of the read have
      // answered. A warning still wins in Widget when it is present.
      if (accountsRead) widgetProps.accountsLoaded = true
    } catch (e) {
      console.error('quota-board: accounts_warning failed', e)
    }
  }

  if (inTauri()) {
    void pull()
    void onUsageUpdated(() => void pull())
    // The path that does not go through the poll gate. `usage://updated` only
    // arrives from a poll, and `due()` returns nothing while the widget is
    // hidden — see `due()`'s own `!self.visible` early return, cited by name
    // because this task inserts code above it. That is the state a login leaves
    // the widget in, because it sends the user to a browser.
    void onAccountsChanged(() => void pull())

    // §6.3. Registered inside the widget branch only. Both windows load
    // index.html (tauri.conf.json), so a listener at module scope would report
    // the *settings* window's visibility into the widget's single gate — and
    // src-tauri/src/main.rs makes hiding the settings window its normal
    // condition, so closing settings would stop the widget polling.
    //
    // **A heartbeat, not just edges, and this is load-bearing.** The Rust side
    // ANDs this report with the window's own state, and nothing over there can
    // clear a stale `false` — showing the window does not undo it. So a single
    // dropped or rejected invoke would pin polling off permanently and
    // silently, leaving the widget displaying its last values forever. Re-
    // reporting on an interval bounds that to one interval. The failure is also
    // logged rather than swallowed: `void` on a rejected promise is exactly how
    // this would have gone unnoticed.
    const report = () =>
      setWidgetVisible(document.visibilityState === 'visible').catch((e: unknown) =>
        console.error('quota-board: set_widget_visible failed', e),
      )
    document.addEventListener('visibilitychange', report)
    // `pageshow` covers a restore from the back/forward cache, where
    // `visibilitychange` may not fire.
    window.addEventListener('pageshow', report)
    // Well under the 180-second polling floor, so a recovered report costs at
    // most one skipped cycle.
    setInterval(report, VISIBILITY_HEARTBEAT_MS)
    // The initial state too, not only the transitions: the widget starts with
    // `visible: false` in tauri.conf.json and is shown from setup().
    report()
  }
}
