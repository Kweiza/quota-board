import { render, screen } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import AccountRow from './AccountRow.svelte'
import type { AccountView } from '../lib/types'

const NOW = new Date('2026-07-29T12:00:00Z')

const win = (id: string, label: string, pct: number) => ({
  window_id: id,
  label,
  percent: pct,
  resets_at: '2026-07-29T13:23:00Z',
  scope: null,
})

function view(state: AccountView['state']): AccountView {
  return { uuid: 'u1', label: 'work@example.com', email: 'work@example.com', state }
}

const ok = (windows: ReturnType<typeof win>[], fetchedAt = NOW.toISOString()) =>
  view({ kind: 'ok', windows, fetched_at: fetchedAt })

describe('AccountRow bars', () => {
  it('draws one bar when the account reports one window', () => {
    render(AccountRow, { account: ok([win('five_hour', '5h', 20)]), now: NOW })
    expect(screen.getAllByRole('meter')).toHaveLength(1)
  })

  it('draws one bar per window when the account reports three', () => {
    const windows = [
      win('five_hour', '5h', 20),
      win('weekly:Opus', 'weekly (Opus)', 55),
      win('weekly:Sonnet', 'weekly (Sonnet)', 12),
    ]
    render(AccountRow, { account: ok(windows), now: NOW })
    expect(screen.getAllByRole('meter')).toHaveLength(3)
    expect(screen.getByText('weekly (Opus)')).toBeTruthy()
  })

  it('renders the label the core actually sends, verbatim', () => {
    render(AccountRow, { account: ok([win('weekly:Fable', 'weekly (Fable)', 33)]), now: NOW })
    expect(screen.getByLabelText('weekly (Fable)')).toBeTruthy()
  })

  it('reports the percent on the meter so the bar glyphs are not the only source', () => {
    render(AccountRow, { account: ok([win('five_hour', '5h', 72)]), now: NOW })
    expect(screen.getByRole('meter').getAttribute('aria-valuenow')).toBe('72')
    expect(screen.getByText('72%')).toBeTruthy()
  })

  it('fills the bar in proportion to the percent', () => {
    render(AccountRow, { account: ok([win('five_hour', '5h', 70)]), now: NOW })
    const glyphs = screen.getByRole('meter').textContent ?? ''
    expect(glyphs.split('').filter((c) => c === '█')).toHaveLength(7)
    expect(glyphs).toHaveLength(10)
  })

  it('colours the bar by severity', () => {
    render(AccountRow, { account: ok([win('five_hour', '5h', 91)]), now: NOW })
    expect(screen.getByRole('meter').className).toContain('red')
  })

  it('says so when no weekly window is reported', () => {
    render(AccountRow, { account: ok([win('five_hour', '5h', 20)]), now: NOW })
    expect(screen.getByText('weekly not reported')).toBeTruthy()
  })

  it('does not say that when a weekly window is present', () => {
    render(AccountRow, { account: ok([win('weekly:Opus', 'weekly (Opus)', 55)]), now: NOW })
    expect(screen.queryByText('weekly not reported')).toBeNull()
  })
})

describe('AccountRow states', () => {
  it('shows a stale value together with its age', () => {
    const fetched = new Date(NOW.getTime() - 12 * 60_000).toISOString()
    render(AccountRow, {
      account: view({ kind: 'stale', windows: [win('five_hour', '5h', 20)], fetched_at: fetched }),
      now: NOW,
    })
    expect(screen.getByText('12m ago')).toBeTruthy()
    expect(screen.getAllByRole('meter')).toHaveLength(1)
  })

  it('keeps the bar colour at full strength on a stale row', () => {
    const fetched = new Date(NOW.getTime() - 12 * 60_000).toISOString()
    const { unmount } = render(AccountRow, {
      account: view({ kind: 'stale', windows: [win('five_hour', '5h', 91)], fetched_at: fetched }),
      now: NOW,
    })
    expect(screen.getByRole('meter').className).toContain('red')
    expect(screen.getByRole('meter').className).not.toContain('dim')
    // A class list cannot see a dim applied in CSS. `css: true` in
    // vitest.config.ts makes the scoped stylesheet real, so compare what the
    // cascade actually resolves to against the same bar on a fresh row.
    const staleBar = getComputedStyle(screen.getByRole('meter'))
    const stale = { opacity: staleBar.opacity, color: staleBar.color }
    unmount()

    render(AccountRow, { account: ok([win('five_hour', '5h', 91)]), now: NOW })
    const freshBar = getComputedStyle(screen.getByRole('meter'))
    expect(stale).toEqual({ opacity: freshBar.opacity, color: freshBar.color })
    expect(stale.opacity).toBe('1')
  })

  it('dims every text element of a stale row', () => {
    const fetched = new Date(NOW.getTime() - 12 * 60_000).toISOString()
    const opacities = (root: HTMLElement) =>
      Object.fromEntries(
        (['.name', '.label', '.pct', '.reset'] as const).map((sel) => [
          sel,
          Number(getComputedStyle(root.querySelector(sel) as HTMLElement).opacity),
        ]),
      )

    const staleRow = render(AccountRow, {
      account: view({ kind: 'stale', windows: [win('five_hour', '5h', 38)], fetched_at: fetched }),
      now: NOW,
    })
    const stale = opacities(staleRow.container)
    staleRow.unmount()

    const freshRow = render(AccountRow, { account: ok([win('five_hour', '5h', 38)]), now: NOW })
    const fresh = opacities(freshRow.container)

    for (const sel of ['.name', '.label', '.pct', '.reset']) {
      // An earlier rule set .7 on elements whose own base was .75 and .7, which
      // dimmed nothing; §7.1 requires a stale value to read as stale.
      expect(stale[sel], `${sel} must dim when the row goes stale`).toBeLessThan(fresh[sel])
      // ...but not past legibility: over the worst-case composited background
      // rgb(48,48,52), .4 is where #e5e7eb falls to the 3:1 floor.
      expect(stale[sel], `${sel} must stay legible`).toBeGreaterThanOrEqual(0.4)
    }
  })

  it('offers re-login on auth_dead and calls back when clicked', async () => {
    const calls: string[] = []
    render(AccountRow, {
      account: view({ kind: 'auth_dead' }),
      now: NOW,
      onRelogin: () => calls.push('relogin'),
    })
    expect(screen.queryAllByRole('meter')).toHaveLength(0)
    const button = screen.getByRole('button', { name: 're-login required' })
    button.click()
    expect(calls).toEqual(['relogin'])
  })

  it('offers unlock on secrets_locked and calls back when clicked', () => {
    const calls: string[] = []
    render(AccountRow, {
      account: view({ kind: 'secrets_locked' }),
      now: NOW,
      onUnlock: () => calls.push('unlock'),
    })
    const button = screen.getByRole('button', { name: 'unlock' })
    button.click()
    expect(calls).toEqual(['unlock'])
  })

  it('reports unknown_shape as unknown, never as a number', () => {
    render(AccountRow, { account: view({ kind: 'unknown_shape' }), now: NOW })
    expect(screen.getByText('unknown')).toBeTruthy()
    expect(screen.queryByText(/\d+\s*%/)).toBeNull()
    expect(screen.queryAllByRole('meter')).toHaveLength(0)
  })

  it('reports throttled with a fixed-format wall clock, not a locale string', () => {
    render(AccountRow, { account: view({ kind: 'throttled', until: '2026-07-29T14:05:00Z' }), now: NOW })
    expect(screen.getByText(/^throttled, after \d{2}:\d{2}$/)).toBeTruthy()
    expect(screen.queryAllByRole('meter')).toHaveLength(0)
  })

  it('distinguishes loading, network and auth_expired from each other', () => {
    const texts = (['loading', 'network', 'auth_expired'] as const).map((kind) => {
      const { unmount } = render(AccountRow, { account: view({ kind }), now: NOW })
      const text = document.body.textContent ?? ''
      const own = text.replace('work@example.com', '').trim()
      unmount()
      return own
    })
    expect(new Set(texts).size).toBe(3)
  })

  it('never renders a number for a state that carries no data', () => {
    const kinds = ['loading', 'auth_expired', 'auth_dead', 'secrets_locked', 'unknown_shape', 'network'] as const
    for (const kind of kinds) {
      const { unmount } = render(AccountRow, { account: view({ kind }), now: NOW })
      expect(screen.queryByText(/\d+\s*%/)).toBeNull()
      expect(screen.queryAllByRole('meter')).toHaveLength(0)
      unmount()
    }
  })
})
