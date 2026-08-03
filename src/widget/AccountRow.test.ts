import { render, screen, waitFor } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import AccountRow from './AccountRow.svelte'
import type { AccountView } from '../lib/types'

const NOW = new Date('2026-07-29T12:00:00Z')
const OLD = new Date(NOW.getTime() - 12 * 60_000).toISOString()

const win = (id: string, label: string, pct: number) => ({
  window_id: id,
  label,
  percent: pct,
  resets_at: '2026-07-29T13:23:00Z',
  scope: null,
})

/**
 * The general fixture: every field defaults to the Claude row this file has
 * always tested, and a caller overrides only what a given test is about.
 * `view()` below is the special case that predates Task 9 — kept so the ~30
 * call sites across this file that only ever varied `state` do not all have to
 * learn about `provider`.
 */
function acct(overrides: Partial<AccountView> = {}): AccountView {
  return {
    account_id: 'u1',
    provider: 'anthropic',
    label: 'work@example.com',
    email: 'work@example.com',
    state: { kind: 'loading' },
    ...overrides,
  }
}

function view(state: AccountView['state']): AccountView {
  return acct({ state })
}

const ok = (windows: ReturnType<typeof win>[], fetchedAt = NOW.toISOString()) =>
  view({ kind: 'ok', windows, extra: null, fetched_at: fetchedAt })

describe('AccountRow provider', () => {
  it('marks a Codex row so it cannot be confused with a Claude one', () => {
    render(AccountRow, { account: acct({ provider: 'openai', label: 'work' }) })
    // `toHaveTextContent` needs `@testing-library/jest-dom`, which this project
    // does not depend on — every other assertion in this file reads
    // `.textContent` directly (see `AccountRow bars` above), so this matches
    // rather than adding a new dependency for one assertion.
    expect(screen.getByTitle('Codex').textContent).toBe('CX')
  })

  /// The note serves design.md §5.3's read order, which has no Codex counterpart.
  /// Left ungated it appears on every Codex row, always.
  it('does not tell a Codex row that weekly is not reported', () => {
    render(AccountRow, {
      account: acct({
        provider: 'openai',
        state: { kind: 'ok', windows: [win('primary', '7d', 0)], extra: null, fetched_at: NOW.toISOString() },
      }),
    })
    expect(screen.queryByText(/weekly not reported/i)).toBeNull()
  })

  it('still tells a Claude row that weekly is not reported', () => {
    render(AccountRow, {
      account: acct({
        provider: 'anthropic',
        state: { kind: 'ok', windows: [win('five_hour', '5h', 10)], extra: null, fetched_at: NOW.toISOString() },
      }),
    })
    expect(screen.getByText(/weekly not reported/i)).toBeTruthy()
  })

  /// AccountRow.svelte's CSS comment records the bug this prevents: `.amounts`
  /// was left out of the stale list and money rendered at full strength inside an
  /// otherwise dimmed row. The badge is the same class of element.
  it('dims the badge on a stale row', () => {
    const { container } = render(AccountRow, {
      account: acct({
        provider: 'openai',
        state: { kind: 'stale', windows: [], extra: null, fetched_at: OLD },
      }),
    })
    const badge = container.querySelector('.badge')!
    expect(getComputedStyle(badge).opacity).not.toBe('1')
  })
})

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
      account: view({ kind: 'stale', windows: [win('five_hour', '5h', 20)], extra: null, fetched_at: fetched }),
      now: NOW,
    })
    expect(screen.getByText('12m ago')).toBeTruthy()
    expect(screen.getAllByRole('meter')).toHaveLength(1)
  })

  it('keeps the bar colour at full strength on a stale row', () => {
    const fetched = new Date(NOW.getTime() - 12 * 60_000).toISOString()
    const { unmount } = render(AccountRow, {
      account: view({ kind: 'stale', windows: [win('five_hour', '5h', 91)], extra: null, fetched_at: fetched }),
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
      account: view({ kind: 'stale', windows: [win('five_hour', '5h', 38)], extra: null, fetched_at: fetched }),
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

describe('AccountRow refresh', () => {
  /**
   * Every state carries the button, and the ones with no numbers to show carry
   * it for the strongest reason: `network` and `throttled` are precisely the
   * rows worth retrying. Hiding the control there would withhold it exactly
   * when it is wanted, and the only other "Refresh now" in the app is two
   * clicks and a second window away.
   */
  const EVERY_STATE: AccountView['state'][] = [
    { kind: 'ok', windows: [win('five_hour', '5h', 20)], extra: null, fetched_at: NOW.toISOString() },
    { kind: 'stale', windows: [win('five_hour', '5h', 20)], extra: null, fetched_at: NOW.toISOString() },
    { kind: 'loading' },
    { kind: 'throttled', until: '2026-07-29T14:05:00Z' },
    { kind: 'auth_expired' },
    { kind: 'auth_dead' },
    { kind: 'oauth_not_allowed' },
    { kind: 'secrets_locked' },
    { kind: 'unknown_shape' },
    { kind: 'network' },
  ]

  it('offers a refresh button whatever the row is showing', () => {
    for (const state of EVERY_STATE) {
      const { unmount } = render(AccountRow, { account: view(state), now: NOW })
      // `auth_dead` and `secrets_locked` draw their own buttons, so this is
      // matched by accessible name rather than by role alone. The name is the
      // settings window's wording verbatim: one control, one label.
      expect(
        screen.getByRole('button', { name: 'Refresh now' }),
        `${state.kind} must offer a refresh`,
      ).toBeTruthy()
      unmount()
    }
  })

  it('reports the click to the parent', () => {
    let calls = 0
    render(AccountRow, {
      account: ok([win('five_hour', '5h', 20)]),
      now: NOW,
      onRefresh: () => {
        calls += 1
      },
    })
    screen.getByRole('button', { name: 'Refresh now' }).click()
    expect(calls).toBe(1)
  })

  /**
   * `refresh_account` now waits for §6.1's global permit instead of giving up
   * when the polling loop holds it, so a press can legitimately take a while.
   * On a row with nothing else to show — `network`, `loading` — an undisabled
   * button gives no sign the click landed at all, which is the same
   * press-does-nothing defect §6.4's note was added to fix in the settings
   * window. The guard also stops a second press queueing a second poll behind
   * the first.
   */
  it('disables the button until the refresh it started finishes', async () => {
    let release = (): void => {}
    const pending = new Promise<void>((resolve) => {
      release = resolve
    })
    let starts = 0
    render(AccountRow, {
      account: view({ kind: 'network' }),
      now: NOW,
      onRefresh: () => {
        starts += 1
        return pending
      },
    })
    const button = screen.getByRole('button', { name: 'Refresh now' }) as HTMLButtonElement

    button.click()
    await waitFor(() => expect(button.disabled).toBe(true))
    button.click()
    expect(starts, 'a second press must not start a second refresh').toBe(1)

    release()
    await waitFor(() => expect(button.disabled).toBe(false))
  })

  /**
   * The stale row dims its text (§7.3), and this button is deliberately not
   * part of that: staleness is the state in which the user most wants to press
   * it, so dimming the one remedy the row offers points the affordance the
   * wrong way.
   */
  it('keeps the button at full strength on a stale row', () => {
    const opacity = (root: HTMLElement) =>
      getComputedStyle(root.querySelector('.refresh') as HTMLElement).opacity
    const fetched = new Date(NOW.getTime() - 12 * 60_000).toISOString()

    const staleRow = render(AccountRow, {
      account: view({ kind: 'stale', windows: [win('five_hour', '5h', 20)], extra: null, fetched_at: fetched }),
      now: NOW,
    })
    const stale = opacity(staleRow.container)
    staleRow.unmount()

    const freshRow = render(AccountRow, { account: ok([win('five_hour', '5h', 20)]), now: NOW })
    expect(stale).toBe(opacity(freshRow.container))
  })
})

/** The measured body: $22.31 spent against a $20.00 monthly limit. */
const CREDIT = {
  used_minor: 2231,
  limit_minor: 2000,
  currency: 'USD',
  exponent: 2,
  percent: 111.55,
}

describe('AccountRow credit line', () => {
  const withCredit = (credit: typeof CREDIT | null) =>
    view({
      kind: 'ok',
      windows: [win('five_hour', '5h', 20)],
      extra: credit ? { kind: 'credit', ...credit } : null,
      fetched_at: NOW.toISOString(),
    })

  it('renders the spend against the limit', () => {
    render(AccountRow, { account: withCredit(CREDIT), now: NOW })
    expect(screen.getByText('credits')).toBeTruthy()
    expect(screen.getByText('$22.31 / $20.00')).toBeTruthy()
  })

  /**
   * The whole reason `parse_credit` computes the percentage instead of reading
   * `spend.percent`: the response said 100 for this exact pair. 112 beside
   * "$22.31 / $20.00" is the only reading that is not self-contradictory.
   */
  it('shows the over-limit percentage rather than clamping it to 100', () => {
    render(AccountRow, { account: withCredit(CREDIT), now: NOW })
    expect(screen.getByText('112%')).toBeTruthy()
    expect(screen.queryByText('100%')).toBeNull()
  })

  it('colours an over-limit percentage red', () => {
    const { container } = render(AccountRow, { account: withCredit(CREDIT), now: NOW })
    const pct = container.querySelector('.credit-row .pct') as HTMLElement
    expect(pct.className).toContain('red')
  })

  /**
   * CLAUDE.md's never-demote-to-0% rule at the point the endpoint invites the
   * mistake: an account that never enabled credits still reports `used` $0.00
   * and `percent` 0, and `parse_credit` answers `null` for it. Nothing at all
   * must be drawn — not a zero, and not a "credits off" placeholder.
   */
  it('draws no credit line at all when the account has none', () => {
    const { container } = render(AccountRow, { account: withCredit(null), now: NOW })
    expect(container.querySelector('.credit-row')).toBeNull()
    expect(screen.queryByText('credits')).toBeNull()
  })

  it('dims the amounts when the row goes stale', () => {
    const fetched = new Date(NOW.getTime() - 12 * 60_000).toISOString()
    const read = (root: HTMLElement) =>
      Number(getComputedStyle(root.querySelector('.amounts') as HTMLElement).opacity)

    const staleRow = render(AccountRow, {
      account: view({
        kind: 'stale',
        windows: [win('five_hour', '5h', 20)],
        extra: { kind: 'credit', ...CREDIT },
        fetched_at: fetched,
      }),
      now: NOW,
    })
    const stale = read(staleRow.container)
    staleRow.unmount()

    const freshRow = render(AccountRow, { account: withCredit(CREDIT), now: NOW })
    expect(stale).toBeLessThan(read(freshRow.container))
  })
})
