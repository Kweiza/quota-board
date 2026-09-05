import { render, screen } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import Widget from './Widget.svelte'
import type { AccountView } from '../lib/types'

/**
 * docs/design.md §9.1. An unreadable account file produces an empty list, and
 * the empty state's own invitation to add Claude or Codex — is then a
 * false statement to someone who has accounts the app could not load. It is the
 * confidently-wrong display AGENTS.md calls this product's worst failure mode,
 * so the two states are mutually exclusive rather than stacked.
 */
describe('Widget empty states', () => {
  it('shows loading until the first account read has completed', () => {
    render(Widget, { accounts: [], accountsLoaded: false, warning: null })
    expect(screen.getByRole('status').textContent).toBe('Loading accounts…')
    expect(screen.queryByText(/Add a Claude or Codex account/)).toBeNull()
  })

  it('invites either provider after a successful empty read', () => {
    render(Widget, { accounts: [], accountsLoaded: true, warning: null })
    expect(screen.getByText('Add a Claude or Codex account in Settings')).toBeTruthy()
  })

  it('lets a warning outrank both loading and the empty invitation', () => {
    render(Widget, {
      accounts: [],
      accountsLoaded: false,
      warning: 'your saved accounts could not be read, so it is not valid account JSON',
    })
    expect(screen.getByText(/could not be read/)).toBeTruthy()
    expect(screen.queryByText(/Loading accounts/)).toBeNull()
    expect(screen.queryByText(/Add a Claude or Codex account/)).toBeNull()
  })

  it('gives the glyph-only settings control an accessible name', () => {
    render(Widget, { accounts: [], accountsLoaded: true, warning: null })
    expect(screen.getByRole('button', { name: 'Settings' })).toBeTruthy()
  })
})

const two: AccountView[] = [
  {
    account_id: 'uuid-work',
    provider: 'anthropic',
    label: 'work',
    email: 'work@example.com',
    state: { kind: 'loading' },
  },
  {
    // A different provider from the row above on purpose: a test that gave
    // both rows the same provider could not tell "the right provider was
    // forwarded" from "some provider was forwarded" — see the assertion
    // below.
    account_id: 'uuid-home',
    provider: 'openai',
    label: 'home',
    email: 'home@example.com',
    state: { kind: 'loading' },
  },
]

describe('Widget refresh', () => {
  /**
   * The (account_id, provider) pair, never the index and never the label:
   * AGENTS.md makes the pair the primary key, and both other candidates are
   * wrong here — labels are user-editable and may be duplicated, and
   * `usage://updated` replaces the whole array so an index captured at render
   * time goes stale. Asserting on the *second* row is what makes a hard-wired
   * first id fail.
   */
  it('asks to refresh the row that was clicked, by its own id and provider', () => {
    const refreshed: Array<[string, string]> = []
    // A block body, not `(uuid, provider) => refreshed.push(...)`: `onRefresh`
    // returns `void | Promise<void>` because `AccountRow` awaits it, and that
    // union does not get the return-value-ignoring latitude a bare `void`
    // would.
    render(Widget, {
      accounts: two,
      warning: null,
      onRefresh: (uuid: string, provider: string) => {
        refreshed.push([uuid, provider])
      },
    })
    screen.getByRole('button', { name: 'Refresh Codex account home' }).click()
    expect(refreshed).toEqual([['uuid-home', 'openai']])
  })

  it('gives every retryable row its own button', () => {
    render(Widget, { accounts: two, warning: null })
    expect(screen.getAllByRole('button', { name: /^Refresh (Claude|Codex) account/ })).toHaveLength(2)
  })

  /**
   * The actual collision the (provider, account_id) key exists for: two
   * accounts sharing the same id. Keying the `{#each}` by `a.account_id`
   * alone would make Svelte throw `each_key_duplicate` at render time — not
   * merely mis-render, crash — so this test's `render()` call itself is
   * where a regression would show up, before any assertion runs.
   */
  it('renders two accounts sharing an id under different providers without a duplicate-key crash', () => {
    const sameId: AccountView[] = [
      {
        account_id: 'same-id',
        provider: 'anthropic',
        label: 'claude',
        email: 'claude@example.com',
        state: { kind: 'loading' },
      },
      {
        account_id: 'same-id',
        provider: 'openai',
        label: 'codex',
        email: 'codex@example.com',
        state: { kind: 'loading' },
      },
    ]
    render(Widget, { accounts: sameId, warning: null })
    expect(screen.getAllByRole('button', { name: /^Refresh (Claude|Codex) account/ })).toHaveLength(2)
  })
})

/**
 * docs/design.md §8.1's columns. The badge that used to name the provider on
 * every row is gone, so these headings are the only place the widget says which
 * service a set of bars belongs to — and the grouping is the whole reason the
 * card stopped growing straight down.
 */
describe('Widget columns', () => {
  const claude = (id: string): AccountView => ({
    account_id: id,
    provider: 'anthropic',
    label: id,
    email: `${id}@example.com`,
    state: { kind: 'loading' },
  })
  const codex = (id: string): AccountView => ({ ...claude(id), provider: 'openai' })

  it('puts Claude in the first column and Codex in the second', () => {
    const { container } = render(Widget, {
      accounts: [codex('c1'), claude('a1'), codex('c2')],
      warning: null,
    })
    const headings = Array.from(container.querySelectorAll('.col-head')).map((h) => h.textContent)
    // Claude first even though a Codex account is first in the array: §8.1
    // fixes the column order, and only the order *within* a column follows
    // `list_accounts`.
    expect(headings).toEqual(['Claude', 'Codex'])
  })

  /**
   * The product name has to reach assistive technology, and with the row badge
   * gone the column's accessible name is what carries it. `aria-labelledby` on
   * the section pointing at its own heading is what makes each column a named
   * region rather than an anonymous group of rows.
   */
  it('names each column for assistive technology', () => {
    render(Widget, { accounts: [claude('a1'), codex('c1')], warning: null })
    // `getByRole('region', { name })` is the assertion that matters: a
    // `section` is only exposed as a region once it has an accessible name, so
    // this fails both if the heading is missing and if `aria-labelledby` stops
    // resolving to it.
    expect(screen.getByRole('region', { name: 'Claude' })).toBeTruthy()
    expect(screen.getByRole('region', { name: 'Codex' })).toBeTruthy()
    expect(screen.getAllByRole('region')).toHaveLength(2)
  })

  it('renders one column, not an empty second one, when only one provider has accounts', () => {
    const { container } = render(Widget, { accounts: [claude('a1'), claude('a2')], warning: null })
    expect(Array.from(container.querySelectorAll('.col-head')).map((h) => h.textContent)).toEqual([
      'Claude',
    ])
    // The width follows from the same fact (`src/lib/layout.ts`), so a column
    // rendered empty here would also stretch the window to 520px for nothing.
    expect(container.querySelector('.widget.split')).toBeNull()
  })

  it('marks the card split only when both columns are present', () => {
    const single = render(Widget, { accounts: [claude('a1')], warning: null })
    expect(single.container.querySelector('.widget.split')).toBeNull()
    single.unmount()

    const both = render(Widget, { accounts: [claude('a1'), codex('c1')], warning: null })
    expect(both.container.querySelector('.widget.split')).toBeTruthy()
  })

  it('keeps the backend order inside a column', () => {
    render(Widget, { accounts: [claude('second'), claude('first')], warning: null })
    const names = screen
      .getAllByRole('button', { name: /^Refresh Claude account/ })
      .map((b) => b.getAttribute('aria-label'))
    // Not alphabetical on purpose: `list_accounts` has already applied either
    // the manual arrangement or §8.6's auto sort, and the widget must not have
    // a second opinion about it.
    expect(names).toEqual([
      'Refresh Claude account second',
      'Refresh Claude account first',
    ])
  })
})
