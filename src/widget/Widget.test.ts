import { render, screen } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import Widget from './Widget.svelte'
import type { AccountView } from '../lib/types'

/**
 * docs/design.md §9.1. An unreadable account file produces an empty list, and
 * the empty state's own sentence — "Add an account in Settings" — is then a
 * false statement to someone who has accounts the app could not load. It is the
 * confidently-wrong display CLAUDE.md calls this product's worst failure mode,
 * so the two states are mutually exclusive rather than stacked.
 */
describe('Widget empty states', () => {
  it('invites a first account when there simply are none', () => {
    render(Widget, { accounts: [], warning: null })
    expect(screen.getByText('Add an account in Settings')).toBeTruthy()
  })

  it('says why instead of inviting one when the file could not be read', () => {
    render(Widget, {
      accounts: [],
      warning: 'your saved accounts could not be read, so it is not valid account JSON',
    })
    expect(screen.getByText(/could not be read/)).toBeTruthy()
    expect(screen.queryByText('Add an account in Settings')).toBeNull()
  })
})

const two: AccountView[] = [
  { uuid: 'uuid-work', label: 'work', email: 'work@example.com', state: { kind: 'loading' } },
  { uuid: 'uuid-home', label: 'home', email: 'home@example.com', state: { kind: 'loading' } },
]

describe('Widget refresh', () => {
  /**
   * The uuid, never the index and never the label: CLAUDE.md makes
   * `account.uuid` the primary key, and both other candidates are wrong here —
   * labels are user-editable and may be duplicated, and `usage://updated`
   * replaces the whole array so an index captured at render time goes stale.
   * Asserting on the *second* row is what makes a hard-wired first uuid fail.
   */
  it('asks to refresh the row that was clicked', () => {
    const refreshed: string[] = []
    // A block body, not `(uuid) => refreshed.push(uuid)`: `onRefresh` returns
    // `void | Promise<void>` because `AccountRow` awaits it, and that union
    // does not get the return-value-ignoring latitude a bare `void` would.
    render(Widget, {
      accounts: two,
      warning: null,
      onRefresh: (uuid: string) => {
        refreshed.push(uuid)
      },
    })
    screen.getAllByRole('button', { name: 'Refresh now' })[1].click()
    expect(refreshed).toEqual(['uuid-home'])
  })

  it('gives every row its own button', () => {
    render(Widget, { accounts: two, warning: null })
    expect(screen.getAllByRole('button', { name: 'Refresh now' })).toHaveLength(2)
  })
})
