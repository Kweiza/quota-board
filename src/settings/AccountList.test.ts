import { fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import AccountList from './AccountList.svelte'
import { accountKey } from '../lib/types'
import type { AccountView, Provider } from '../lib/types'

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
 * carries `provider` alongside the id (§9.3), and a test that gave both rows
 * the same provider could not tell "the right provider was forwarded" from
 * "some provider was forwarded". `Settings.svelte` never builds a mixed column,
 * but the component derives each row's accessible name from that row rather
 * than from the `provider` prop, which is what makes this discrimination
 * possible at all.
 */
const two = [
  account('uuid-work', 'Work', 'work@example.com'),
  account('uuid-home', 'Personal', 'home@example.com', 'openai'),
]

const labels = (): string[] =>
  (screen.getAllByLabelText(/^Display name for /) as HTMLInputElement[]).map((i) => i.value)

const rows = (): HTMLElement[] => Array.from(document.querySelectorAll('li.row'))

/**
 * jsdom implements neither `DragEvent` nor `DataTransfer`, so the pointer path
 * is driven with plain events carrying a stand-in. The stand-in is the minimum
 * the component touches — `effectAllowed`, `dropEffect`, `setData` — so a
 * handler that started reading `getData` would fail here rather than pass on a
 * value jsdom happened to keep.
 */
function dragEvent(type: string): Event {
  const event = new Event(type, { bubbles: true, cancelable: true })
  Object.defineProperty(event, 'dataTransfer', {
    value: { effectAllowed: '', dropEffect: '', setData: () => {} },
  })
  return event
}

/** The handle press is what arms `draggable`; a drag that skips it is refused. */
async function dragRowOnto(from: HTMLElement, to: HTMLElement): Promise<void> {
  const handle = from.querySelector('button.handle') as HTMLElement
  await fireEvent.mouseDown(handle)
  from.dispatchEvent(dragEvent('dragstart'))
  to.dispatchEvent(dragEvent('dragover'))
  to.dispatchEvent(dragEvent('drop'))
}

describe('AccountList', () => {
  it('renders one row per account, in the order given', () => {
    render(AccountList, { accounts: two, provider: 'anthropic' })
    // The array order *is* the order: `list_accounts` returns either
    // `sort_order` or §8.6's auto sort, so any sorting here would be a second
    // opinion about an order the backend has already settled.
    // 'Work' before 'Personal' is not alphabetical on purpose.
    expect(labels()).toEqual(['Work', 'Personal'])
  })

  it('shows the email beside the label so two renamed accounts stay distinguishable', () => {
    // §9.3: the label is user-editable and may be duplicated, so the email is
    // the only thing left that tells these two rows apart.
    render(AccountList, {
      provider: 'anthropic',
      accounts: [
        account('uuid-work', 'Claude', 'work@example.com'),
        account('uuid-home', 'Claude', 'home@example.com'),
      ],
    })
    expect(labels()).toEqual(['Claude', 'Claude'])
    expect(screen.getByText('work@example.com')).toBeTruthy()
    expect(screen.getByText('home@example.com')).toBeTruthy()
  })

  /**
   * The per-row provider badge moved to the column heading in
   * `Settings.svelte` (§8.1), so the product name is no longer visible on the
   * row. Every control's accessible name still carries it, which is what keeps
   * "Remove" unambiguous when a Claude and a Codex account share a label and an
   * email — the case §9.3 says is possible because both are display-only.
   */
  it('keeps the full product name in every control name once the row badge is gone', () => {
    render(AccountList, {
      provider: 'anthropic',
      accounts: [
        account('claude-id', 'Work', 'same@example.com', 'anthropic'),
        account('codex-id', 'Work', 'same@example.com', 'openai'),
      ],
    })

    expect(screen.queryByLabelText('Provider: Claude')).toBeNull()
    for (const name of [
      'Display name for Claude account same@example.com',
      'Display name for Codex account same@example.com',
    ]) {
      expect(screen.getByRole('textbox', { name })).toBeTruthy()
    }
    for (const name of [
      'Remove Claude account Work',
      'Remove Codex account Work',
      'Refresh Claude account Work',
      'Refresh Codex account Work',
    ]) {
      expect(screen.getByRole('button', { name })).toBeTruthy()
    }
  })

  it('reports the id and provider, never the label, when a row is removed', () => {
    // AGENTS.md: the primary key is the (provider, account_id) pair.
    // `rename_account` exists, so the label is neither stable nor unique, and
    // the id alone is not unique across providers.
    const removed: Array<[string, string]> = []
    render(AccountList, {
      accounts: two,
      provider: 'anthropic',
      onRemove: (accountId, provider) => removed.push([accountId, provider]),
    })
    screen.getByRole('button', { name: 'Remove Codex account Personal' }).click()
    expect(removed).toEqual([['uuid-home', 'openai']])
  })

  it('asks to refresh the row that was clicked, by its id and provider', () => {
    const refreshed: Array<[string, string]> = []
    render(AccountList, {
      accounts: two,
      provider: 'anthropic',
      onRefresh: (accountId, provider) => {
        refreshed.push([accountId, provider])
      },
    })
    screen.getByRole('button', { name: 'Refresh Codex account Personal' }).click()
    expect(refreshed).toEqual([['uuid-home', 'openai']])
  })

  it('allows only one in-flight refresh per provider and account', async () => {
    let release = (): void => {}
    const pending = new Promise<void>((resolve) => {
      release = resolve
    })
    let starts = 0
    render(AccountList, {
      accounts: two,
      provider: 'anthropic',
      onRefresh: () => {
        starts += 1
        return pending
      },
    })
    const button = screen.getByRole('button', {
      name: 'Refresh Codex account Personal',
    }) as HTMLButtonElement

    button.click()
    await waitFor(() => {
      expect(button.disabled).toBe(true)
      expect(button.getAttribute('aria-busy')).toBe('true')
      expect(button.getAttribute('aria-label')).toBe('Refreshing Codex account Personal')
    })
    button.click()
    expect(starts).toBe(1)

    release()
    await waitFor(() => {
      expect(button.disabled).toBe(false)
      expect(button.getAttribute('aria-busy')).toBe('false')
    })
  })

  it('disables refresh for auth_dead and names the provider-specific re-login remedy', () => {
    const dead = account('dead-user', 'Work', 'same@example.com', 'openai')
    dead.state = { kind: 'auth_dead' }
    let refreshes = 0
    render(AccountList, {
      accounts: [dead],
      provider: 'openai',
      throttledUntil: {
        [accountKey(dead.account_id, dead.provider)]: '2099-01-01T00:00:00Z',
      },
      onRefresh: () => {
        refreshes += 1
      },
    })

    const button = screen.getByRole('button', {
      name: 'Refresh Codex account Work',
    }) as HTMLButtonElement
    expect(button.disabled).toBe(true)
    expect(screen.getByText('Re-login with Add Codex account below.')).toBeTruthy()
    expect(screen.queryByText(/throttled, available after/)).toBeNull()
    button.click()
    expect(refreshes).toBe(0)
  })

  describe('reordering', () => {
    const three: AccountView[] = [
      account('id-a', 'A', 'a@example.com'),
      account('id-b', 'B', 'b@example.com'),
      account('id-c', 'C', 'c@example.com'),
    ]

    /**
     * The column's whole order, as ids — never an index. The parent folds this
     * back into the full (provider, account_id) array, and an index captured at
     * render time goes stale the moment `accounts://changed` re-reads the list.
     */
    it('reports the column’s new id order after a drop', async () => {
      const orders: Array<[Provider, string[]]> = []
      render(AccountList, {
        accounts: three,
        provider: 'anthropic',
        onReorder: (provider, ids) => orders.push([provider, ids]),
      })

      await dragRowOnto(rows()[0], rows()[2])
      expect(orders).toEqual([['anthropic', ['id-b', 'id-c', 'id-a']]])
    })

    /**
     * A drop back onto the row's own position is not a change, and writing one
     * would rewrite `sort_order` on disk for nothing.
     */
    it('reports nothing when a row is dropped where it already was', async () => {
      let calls = 0
      render(AccountList, {
        accounts: three,
        provider: 'anthropic',
        onReorder: () => {
          calls += 1
        },
      })
      await dragRowOnto(rows()[1], rows()[1])
      expect(calls).toBe(0)
    })

    /**
     * The rename field lives inside the row. If the row were draggable at all
     * times, the press that places the caret in that field would start a drag
     * instead — so `dragstart` is refused unless it followed a press on the
     * handle.
     */
    it('refuses a drag that did not start on the handle, so the rename field stays usable', () => {
      let calls = 0
      render(AccountList, {
        accounts: three,
        provider: 'anthropic',
        onReorder: () => {
          calls += 1
        },
      })
      const [first, , third] = rows()
      // No mousedown on the handle: straight to dragstart, as a text selection
      // escaping the input would.
      first.dispatchEvent(dragEvent('dragstart'))
      third.dispatchEvent(dragEvent('dragover'))
      third.dispatchEvent(dragEvent('drop'))
      expect(calls).toBe(0)
    })

    /**
     * Removing the Move up/down buttons must not remove the only way a
     * keyboard-only user could ever reorder the list.
     */
    it('moves a row with Alt and an arrow key', async () => {
      const orders: string[][] = []
      render(AccountList, {
        accounts: three,
        provider: 'anthropic',
        onReorder: (_p, ids) => orders.push(ids),
      })
      const handle = screen.getByRole('button', {
        name: /^Reorder Claude account B/,
      })
      await fireEvent.keyDown(handle, { key: 'ArrowUp', altKey: true })
      await fireEvent.keyDown(handle, { key: 'ArrowDown', altKey: true })
      expect(orders).toEqual([
        ['id-b', 'id-a', 'id-c'],
        ['id-a', 'id-c', 'id-b'],
      ])
    })

    it('does nothing on a bare arrow key, which still belongs to focus movement', async () => {
      let calls = 0
      render(AccountList, {
        accounts: three,
        provider: 'anthropic',
        onReorder: () => {
          calls += 1
        },
      })
      const handle = screen.getByRole('button', { name: /^Reorder Claude account B/ })
      await fireEvent.keyDown(handle, { key: 'ArrowUp' })
      await fireEvent.keyDown(handle, { key: 'ArrowDown' })
      expect(calls).toBe(0)
    })

    it('does not move past either end of the column', async () => {
      let calls = 0
      render(AccountList, {
        accounts: three,
        provider: 'anthropic',
        onReorder: () => {
          calls += 1
        },
      })
      await fireEvent.keyDown(screen.getByRole('button', { name: /^Reorder Claude account A/ }), {
        key: 'ArrowUp',
        altKey: true,
      })
      await fireEvent.keyDown(screen.getByRole('button', { name: /^Reorder Claude account C/ }), {
        key: 'ArrowDown',
        altKey: true,
      })
      expect(calls).toBe(0)
    })

    /**
     * §8.6's auto sort owns the order while it is on, so the list on screen is
     * not the stored arrangement. A drop would either be discarded or would
     * overwrite the user's arrangement with a computed one they never chose;
     * the handle says so instead.
     */
    it('disables both reorder routes while auto sort owns the order', async () => {
      let calls = 0
      render(AccountList, {
        accounts: three,
        provider: 'anthropic',
        reorderable: false,
        onReorder: () => {
          calls += 1
        },
      })

      const handle = screen.getByRole('button', {
        name: /^Reorder Claude account B/,
      }) as HTMLButtonElement
      expect(handle.disabled).toBe(true)
      expect(handle.title).toContain('Turn off')

      await fireEvent.keyDown(handle, { key: 'ArrowUp', altKey: true })
      await dragRowOnto(rows()[0], rows()[2])
      expect(calls).toBe(0)
    })
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
      provider: 'anthropic',
      onRemove: (accountId, provider) => removed.push([accountId, provider]),
    })

    expect(labels()).toEqual(['Claude one', 'Codex one'])
    screen.getByRole('button', { name: 'Remove Codex account Codex one' }).click()
    expect(removed).toEqual([['same-id', 'openai']])
  })
})
