import { render, screen } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import AccountList from './AccountList.svelte'
import type { AccountView } from '../lib/types'

/**
 * `AccountList` is display-only — it calls no IPC and only reports callbacks —
 * so it renders from plain props, exactly like `src/widget/AccountRow.svelte`.
 */
function account(accountId: string, label: string, email: string): AccountView {
  return { account_id: accountId, provider: 'anthropic', label, email, state: { kind: 'loading' } }
}

const two = [
  account('uuid-work', 'Work', 'work@example.com'),
  account('uuid-home', 'Personal', 'home@example.com'),
]

const labels = (): string[] =>
  (screen.getAllByLabelText('Display name') as HTMLInputElement[]).map((i) => i.value)

describe('AccountList', () => {
  it('renders one row per account, in the order given', () => {
    render(AccountList, { accounts: two })
    // The array order *is* the order: `AccountStore::list()` returns
    // `sort_order`, so any sorting here would silently override the order the
    // user set with the move buttons. 'Work' before 'Personal' is not
    // alphabetical on purpose.
    expect(labels()).toEqual(['Work', 'Personal'])
  })

  it('shows the email beside the label so two renamed accounts stay distinguishable', () => {
    // §9.3: the label is user-editable and may be duplicated, so the email is
    // the only thing left that tells these two rows apart.
    render(AccountList, {
      accounts: [
        account('uuid-work', 'Claude', 'work@example.com'),
        account('uuid-home', 'Claude', 'home@example.com'),
      ],
    })
    expect(labels()).toEqual(['Claude', 'Claude'])
    expect(screen.getByText('work@example.com')).toBeTruthy()
    expect(screen.getByText('home@example.com')).toBeTruthy()
  })

  it('reports the uuid, never the label, when a row is removed', () => {
    // CLAUDE.md: "The account primary key is `account.uuid`." `rename_account`
    // exists, so the label is neither stable nor unique.
    const removed: string[] = []
    render(AccountList, { accounts: two, onRemove: (uuid: string) => removed.push(uuid) })
    screen.getAllByRole('button', { name: 'Remove' })[1].click()
    expect(removed).toEqual(['uuid-home'])
  })

  it('asks to refresh the row that was clicked', () => {
    const refreshed: string[] = []
    render(AccountList, { accounts: two, onRefresh: (uuid: string) => refreshed.push(uuid) })
    screen.getAllByRole('button', { name: 'Refresh now' })[1].click()
    expect(refreshed).toEqual(['uuid-home'])
  })

  it('reports a move as a uuid and a direction, not as an index', () => {
    // The parent rebuilds the whole uuid array for `reorder_accounts`, so a row
    // that reported its own index would desynchronize the moment the list is
    // re-read after `accounts://changed`.
    const moves: Array<[string, number]> = []
    render(AccountList, {
      accounts: two,
      onMove: (uuid: string, delta: number) => moves.push([uuid, delta]),
    })
    screen.getAllByRole('button', { name: 'Move up' })[1].click()
    screen.getAllByRole('button', { name: 'Move down' })[0].click()
    expect(moves).toEqual([
      ['uuid-home', -1],
      ['uuid-work', 1],
    ])
  })
})
