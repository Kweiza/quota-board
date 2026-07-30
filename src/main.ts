import { mount } from 'svelte'
import { getCurrentWindow, LogicalSize } from '@tauri-apps/api/window'
// Keep this import. The reset it carries is what keeps the widget inside its
// own window; dropping it silently widens the document past 280px.
import './app.css'
import Widget from './widget/Widget.svelte'
import type { AccountView } from './lib/types'

/** docs/design.md §8.1: "Fixed width of about 280px; height follows content." */
const WIDGET_WIDTH = 280

/**
 * Placeholder state until Task 17 streams the real thing from the core. It
 * mirrors the §8.1 mockup on purpose — two windows, then three, then a stale
 * account with no weekly window — so the layout can be checked against it.
 */
function fixture(): AccountView[] {
  const now = Date.now()
  const inMinutes = (mins: number) => new Date(now + mins * 60_000).toISOString()
  const window_ = (id: string, label: string, percent: number, mins: number) => ({
    window_id: id,
    label,
    percent,
    resets_at: inMinutes(mins),
    scope: null,
  })

  return [
    {
      uuid: '00000000-0000-4000-8000-000000000001',
      label: 'work@example.com',
      state: {
        kind: 'ok',
        fetched_at: new Date(now).toISOString(),
        windows: [
          window_('five_hour', '5h', 72, 83),
          window_('seven_day', '7d', 41, 6480),
        ],
      },
    },
    {
      uuid: '00000000-0000-4000-8000-000000000002',
      label: 'personal@example.com',
      state: {
        kind: 'ok',
        fetched_at: new Date(now).toISOString(),
        windows: [
          window_('five_hour', '5h', 18, 125),
          window_('weekly:Opus', 'weekly (Opus)', 91, 4560),
          window_('weekly:Sonnet', 'weekly (Sonnet)', 27, 4560),
        ],
      },
    },
    {
      uuid: '00000000-0000-4000-8000-000000000003',
      label: 'side@example.com',
      state: {
        kind: 'stale',
        fetched_at: new Date(now - 12 * 60_000).toISOString(),
        windows: [window_('five_hour', '5h', 38, 47)],
      },
    },
  ]
}

/**
 * The window cannot measure the DOM, so the view measures itself and pushes
 * the height back. `StateFlags::SIZE` is deliberately off in
 * `src-tauri/src/main.rs`: a restored height would fight this on every launch.
 */
function followContentHeight(root: HTMLElement): void {
  // Absent when the page is opened in a plain browser, e.g. `npm run dev`.
  if (!('__TAURI_INTERNALS__' in window)) return
  const appWindow = getCurrentWindow()
  // The settings window shares this entry point until Task 16 routes it, and
  // it must not be resized to widget dimensions.
  if (appWindow.label !== 'widget') return

  new ResizeObserver(() => {
    const height = Math.ceil(root.getBoundingClientRect().height)
    if (height > 0) void appWindow.setSize(new LogicalSize(WIDGET_WIDTH, height))
  }).observe(root)
}

const target = document.getElementById('app')!

const app = mount(Widget, {
  target,
  props: { accounts: fixture() },
})

followContentHeight(target)

export default app
