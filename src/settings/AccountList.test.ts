import { render, screen } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import AccountList from './AccountList.svelte'
import type { AccountView } from '../lib/types'

/**
 * `AccountList` is display-only — it calls no IPC and only reports callbacks —
 * so it renders from plain props, exactly like `src/widget/AccountRow.svelte`.
 */
function account(
  accountId: string,
  label: string,
  email: string,
  provider: AccountView['provider'] = 'anthropic',
): AccountView {
  return { account_id: accountId, provider, label, email, state: { kind: 'loading' } }
}

/**
 * A different provider on the second row, on purpose: every callback below
 * now carries `provider` alongside the id (§9.3), and a test that gave both
 * rows the same provider could not tell "the right provider was forwarded"
 * from "some provider was forwarded".
 */
const two = [
  account('uuid-work', 'Work', 'work@example.com'),
  account('uuid-home', 'Personal', 'home@example.com', 'openai'),
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

  it('reports the id and provider, never the label, when a row is removed', () => {
    // CLAUDE.md: the primary key is the (provider, account_id) pair.
    // `rename_account` exists, so the label is neither stable nor unique, and
    // the id alone is not unique across providers.
    const removed: Array<[string, string]> = []
    render(AccountList, {
      accounts: two,
      onRemove: (accountId, provider) => removed.push([accountId, provider]),
    })
    screen.getAllByRole('button', { name: 'Remove' })[1].click()
    expect(removed).toEqual([['uuid-home', 'openai']])
  })

  it('asks to refresh the row that was clicked, by its id and provider', () => {
    const refreshed: Array<[string, string]> = []
    render(AccountList, {
      accounts: two,
      onRefresh: (accountId, provider) => refreshed.push([accountId, provider]),
    })
    screen.getAllByRole('button', { name: 'Refresh now' })[1].click()
    expect(refreshed).toEqual([['uuid-home', 'openai']])
  })

  it('reports a move as an id and provider, plus a direction, not as an index', () => {
    // The parent rebuilds the whole (provider, account_id) key array for
    // `reorder_accounts`, so a row that reported its own index would
    // desynchronize the moment the list is re-read after `accounts://changed`.
    const moves: Array<[string, string, number]> = []
    render(AccountList, {
      accounts: two,
      onMove: (accountId, provider, delta) => moves.push([accountId, provider, delta]),
    })
    screen.getAllByRole('button', { name: 'Move up' })[1].click()
    screen.getAllByRole('button', { name: 'Move down' })[0].click()
    expect(moves).toEqual([
      ['uuid-home', 'openai', -1],
      ['uuid-work', 'anthropic', 1],
    ])
  })

  /**
   * The actual collision the (provider, account_id) key exists for: two
   * accounts sharing the same id. Keying the `{#each}` by `a.account_id`
   * alone would make Svelte throw `each_key_duplicate` at render time — not
   * merely mis-render, crash — so this test's `render()` call itself is
   * where a regression would show up, before any assertion runs.
   */
  it('renders two accounts sharing an id under different providers as two distinct rows', () => {
    const claude = account('same-id', 'Claude one', 'claude@example.com', 'anthropic')
    const codex = account('same-id', 'Codex one', 'codex@example.com', 'openai')
    const removed: Array<[string, string]> = []
    render(AccountList, {
      accounts: [claude, codex],
      onRemove: (accountId, provider) => removed.push([accountId, provider]),
    })

    expect(labels()).toEqual(['Claude one', 'Codex one'])
    screen.getAllByRole('button', { name: 'Remove' })[1].click()
    expect(removed).toEqual([['same-id', 'openai']])
  })
})
