import { render, screen, waitFor } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import AccountRow from './AccountRow.svelte'
import type { AccountView } from '../lib/types'

const NOW = new Date('2026-07-29T12:00:00Z')
const OLD = new Date(NOW.getTime() - 12 * 60_000).toISOString()

/**
 * `weekly` is explicit on every fixture because the parsers now always set it
 * (`UsageWindow::weekly`). Leaving it off models a window restored from a
 * snapshot cached before the field existed, which the last test in
 * "AccountRow weekly" is specifically about — so it must not be the default
 * here, or that test would be indistinguishable from the others.
 */
const win = (id: string, label: string, pct: number, weekly = false) => ({
  window_id: id,
  label,
  percent: pct,
  resets_at: '2026-07-29T13:23:00Z',
  scope: null,
  weekly,
})

/** A window whose weekliness was never recorded. See `win`. */
const unrecordedWin = (id: string, label: string, pct: number) => {
  const { weekly: _weekly, ...rest } = win(id, label, pct)
  return rest
}

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
  /**
   * The visible per-row badge moved to the column heading in `Widget.svelte`
   * (docs/design.md §8.1), where the product name is announced once as the
   * column's accessible name. What must **not** have moved is the name inside
   * each control's own accessible name: a screen-reader user landing on a
   * button still has to hear which service it acts on, and with the badge gone
   * these labels are the only place that says so.
   */
  it('keeps the product name in every control name now that the row badge is gone', () => {
    const same = { label: 'Work', email: 'same@example.com' }
    const claude = render(AccountRow, {
      account: acct({ ...same, provider: 'anthropic' }),
    })
    expect(screen.queryByLabelText('Provider: Claude')).toBeNull()
    expect(claude.container.querySelector('.badge')).toBeNull()
    expect(screen.getByRole('button', { name: 'Refresh Claude account Work' })).toBeTruthy()
    claude.unmount()

    render(AccountRow, { account: acct({ ...same, provider: 'openai' }) })
    expect(screen.queryByLabelText('Provider: Codex')).toBeNull()
    expect(screen.getByRole('button', { name: 'Refresh Codex account Work' })).toBeTruthy()
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
  /// otherwise dimmed row. `.age` is the same class of element, and it is now
  /// the only child of `.head` besides `.name` — this test replaces the one
  /// that watched `.badge`, which moved to the column heading.
  it('dims the age on a stale row', () => {
    const { container } = render(AccountRow, {
      account: acct({
        provider: 'openai',
        state: { kind: 'stale', windows: [], extra: null, fetched_at: OLD },
      }),
      now: NOW,
    })
    const age = container.querySelector('.age')!
    expect(age.textContent).toBe('12m ago')
    expect(getComputedStyle(age).opacity).not.toBe('1')
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

  it('renders every Codex bucket with its duration first', () => {
    const windows = [
      win('primary', '5h', 11),
      win('additional:codex_spark:primary', '1h · Codex Spark', 42),
      win('additional:codex_spark:secondary', '1d · Codex Spark', 7),
    ]
    render(AccountRow, {
      account: acct({
        provider: 'openai',
        state: { kind: 'ok', windows, extra: null, fetched_at: NOW.toISOString() },
      }),
      now: NOW,
    })

    expect(screen.getAllByRole('meter')).toHaveLength(3)
    expect(screen.getByText('1h · Codex Spark')).toBeTruthy()
    expect(screen.getByText('1d · Codex Spark')).toBeTruthy()
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
    render(AccountRow, { account: ok([win('weekly:Opus', 'weekly (Opus)', 55, true)]), now: NOW })
    expect(screen.queryByText('weekly not reported')).toBeNull()
  })

  /**
   * A snapshot cached before `UsageWindow.weekly` existed comes back with the
   * flag missing, and missing is **not** false: it means the weekliness was
   * never recorded. Claiming "weekly not reported" from that would be a
   * confidently-wrong display for the minutes between a restart and the first
   * poll — the failure mode AGENTS.md puts above every other.
   */
  it('makes no claim when the weekly flag was never recorded', () => {
    render(AccountRow, {
      account: view({
        kind: 'stale',
        windows: [unrecordedWin('five_hour', '5h', 20)],
        extra: null,
        fetched_at: OLD,
      }),
      now: NOW,
    })
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
    const button = screen.getByRole('button', { name: 'Re-login Claude account work@example.com' })
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
    const button = screen.getByRole('button', { name: 'Unlock Claude account work@example.com' })
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
   * Every recoverable state carries the button, and the ones with no numbers
   * to show carry it for the strongest reason: `network` and `throttled` are
   * precisely the rows worth retrying. `auth_dead` is covered separately: the
   * backend cannot retry a dead grant and the row already exposes re-login.
   */
  const RETRYABLE_STATES: AccountView['state'][] = [
    { kind: 'ok', windows: [win('five_hour', '5h', 20)], extra: null, fetched_at: NOW.toISOString() },
    { kind: 'stale', windows: [win('five_hour', '5h', 20)], extra: null, fetched_at: NOW.toISOString() },
    { kind: 'loading' },
    { kind: 'throttled', until: '2026-07-29T14:05:00Z' },
    { kind: 'auth_expired' },
    { kind: 'oauth_not_allowed' },
    { kind: 'secrets_locked' },
    { kind: 'unknown_shape' },
    { kind: 'network' },
  ]

  it('offers a refresh button for every state that the backend can retry', () => {
    for (const state of RETRYABLE_STATES) {
      const { unmount } = render(AccountRow, { account: view(state), now: NOW })
      // `secrets_locked` draws its own remedy button too, so this is matched by
      // accessible name rather than by role alone. The name is the settings
      // window's wording verbatim: one control, one label.
      expect(
        screen.getByRole('button', { name: 'Refresh Claude account work@example.com' }),
        `${state.kind} must offer a refresh`,
      ).toBeTruthy()
      unmount()
    }
  })

  it('offers re-login instead of a no-op refresh for auth_dead', () => {
    render(AccountRow, { account: view({ kind: 'auth_dead' }), now: NOW })

    expect(
      screen.queryByRole('button', { name: 'Refresh Claude account work@example.com' }),
    ).toBeNull()
    expect(
      screen.getByRole('button', { name: 'Re-login Claude account work@example.com' }),
    ).toBeTruthy()
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
    screen.getByRole('button', { name: 'Refresh Claude account work@example.com' }).click()
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
    const button = screen.getByRole('button', {
      name: 'Refresh Claude account work@example.com',
    }) as HTMLButtonElement

    button.click()
    await waitFor(() => expect(button.disabled).toBe(true))
    expect(button.getAttribute('aria-busy')).toBe('true')
    expect(button.getAttribute('aria-label')).toBe('Refreshing Claude account work@example.com')
    button.click()
    expect(starts, 'a second press must not start a second refresh').toBe(1)

    release()
    await waitFor(() => {
      expect(button.disabled).toBe(false)
      expect(button.getAttribute('aria-busy')).toBe('false')
      expect(button.getAttribute('aria-label')).toBe('Refresh Claude account work@example.com')
    })
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
   * AGENTS.md's never-demote-to-0% rule at the point the endpoint invites the
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

describe('AccountRow reset-credits line', () => {
  it('renders nothing when there are no reset credits', () => {
    const { container } = render(AccountRow, {
      account: acct({
        provider: 'openai',
        state: { kind: 'ok', windows: [], extra: null, fetched_at: NOW.toISOString() },
      }),
    })
    expect(screen.queryByText(/reset credits/i)).toBeNull()
    // Matches the parallel assertion in `AccountRow credit line`'s "draws no
    // credit line at all" test: text absence alone would still pass if the
    // component drew an empty `.credit-row` shell, which is exactly the kind
    // of silent-but-not-actually-silent regression a zero-noise rule exists
    // to prevent.
    expect(container.querySelector('.credit-row')).toBeNull()
  })

  it('shows both counts when they differ', () => {
    render(AccountRow, {
      account: acct({
        provider: 'openai',
        state: {
          kind: 'ok', windows: [], fetched_at: NOW.toISOString(),
          extra: { kind: 'reset_credits', available: 1, applicable: 0 },
        },
      }),
    })
    expect(screen.getByText(/1 \(0 applicable\)/)).toBeTruthy()
  })

  it('shows one count when they agree', () => {
    render(AccountRow, {
      account: acct({
        provider: 'openai',
        state: {
          kind: 'ok', windows: [], fetched_at: NOW.toISOString(),
          extra: { kind: 'reset_credits', available: 2, applicable: 2 },
        },
      }),
    })
    expect(screen.getByText('2')).toBeTruthy()
    expect(screen.queryByText(/applicable/)).toBeNull()
  })

  it('shows only the available count when applicability was not reported', () => {
    render(AccountRow, {
      account: acct({
        provider: 'openai',
        state: {
          kind: 'ok', windows: [], fetched_at: NOW.toISOString(),
          extra: { kind: 'reset_credits', available: 3, applicable: null },
        },
      }),
    })
    expect(screen.getByText('3')).toBeTruthy()
    expect(screen.queryByText(/applicable/)).toBeNull()
  })

  /**
   * `.account.stale :global(.amounts)` reaches `CreditLine`'s third column by
   * class name alone, with no `ResetCreditsLine`-specific rule — so this either
   * already works because the class name matches, or the dimming silently does
   * not reach a stale Codex row's figure, which is the exact bug `.amounts`
   * joined that selector's list to fix in the first place (see the CSS comment
   * above `.account.stale :global(.amounts)`). Confirmed rather than assumed.
   */
  it('dims the reset-credits figure on a stale row', () => {
    const read = (root: HTMLElement) =>
      Number(getComputedStyle(root.querySelector('.amounts') as HTMLElement).opacity)
    const fetched = new Date(NOW.getTime() - 12 * 60_000).toISOString()

    const staleRow = render(AccountRow, {
      account: acct({
        provider: 'openai',
        state: {
          kind: 'stale', windows: [], fetched_at: fetched,
          extra: { kind: 'reset_credits', available: 1, applicable: 0 },
        },
      }),
      now: NOW,
    })
    const stale = read(staleRow.container)
    staleRow.unmount()

    const freshRow = render(AccountRow, {
      account: acct({
        provider: 'openai',
        state: {
          kind: 'ok', windows: [], fetched_at: NOW.toISOString(),
          extra: { kind: 'reset_credits', available: 1, applicable: 0 },
        },
      }),
      now: NOW,
    })
    expect(stale).toBeLessThan(read(freshRow.container))
  })
})
