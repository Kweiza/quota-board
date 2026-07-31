import { render, screen } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import Widget from './Widget.svelte'

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
