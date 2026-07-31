import { flushSync, mount, unmount } from 'svelte'
import { afterEach, describe, expect, it } from 'vitest'
import Widget from '../widget/Widget.svelte'
import { widgetProps } from './props.svelte'
import type { AccountView } from './types'

/**
 * The whole data path of Task 17 rests on one mechanism: `pull()` assigns to
 * `widgetProps.accounts` **after** the component is mounted, and the widget
 * re-renders. Nothing else in the app forces a re-render — there is no
 * remount, no store subscription, no polling of the props object.
 *
 * That mechanism is easy to break in three ways that every other gate passes:
 * renaming `props.svelte.ts` to `props.ts` (runes stop compiling and the
 * bundle gets a bare `$state(...)` call), replacing the proxy with a plain
 * object literal, or spreading it at the mount site (`{ ...widgetProps }`
 * copies the values out of the proxy). Measured with this repo's svelte
 * 5.56.8: a plain object left the DOM reading "Add an account in Settings"
 * after the same assignment, while the proxy rendered the account.
 */
const account = (label: string): AccountView => ({
  uuid: 'u1',
  label,
  email: label,
  state: {
    kind: 'ok',
    credit: null,
    fetched_at: new Date().toISOString(),
    windows: [
      {
        window_id: 'five_hour',
        label: '5h',
        percent: 20,
        resets_at: new Date(Date.now() + 3_600_000).toISOString(),
        scope: null,
      },
    ],
  },
})

afterEach(() => {
  // The proxy is a module singleton, so each test has to hand it back empty.
  widgetProps.accounts = []
  document.body.innerHTML = ''
})

describe('widgetProps', () => {
  it('re-renders the mounted widget when accounts are assigned after mount', () => {
    const target = document.createElement('div')
    document.body.appendChild(target)
    const app = mount(Widget, { target, props: widgetProps })

    expect(target.textContent).toContain('Add an account in Settings')

    widgetProps.accounts = [account('work@example.com')]
    flushSync()

    expect(target.textContent).toContain('work@example.com')
    expect(target.textContent).not.toContain('Add an account in Settings')
    unmount(app)
  })

  it('keeps re-rendering on every later assignment, not just the first', () => {
    const target = document.createElement('div')
    document.body.appendChild(target)
    const app = mount(Widget, { target, props: widgetProps })

    widgetProps.accounts = [account('first@example.com')]
    flushSync()
    widgetProps.accounts = [account('second@example.com')]
    flushSync()

    expect(target.textContent).toContain('second@example.com')
    expect(target.textContent).not.toContain('first@example.com')
    unmount(app)
  })

  it('starts empty so a webview that never reaches the core shows no fabricated account', () => {
    // The fixture this replaced rendered three convincing fake accounts. An
    // empty start is what makes a broken IPC path visibly broken.
    expect(widgetProps.accounts).toEqual([])
  })
})
