import { describe, expect, it } from 'vitest'
import {
  PROVIDER_DISPLAY,
  PROVIDER_ORDER,
  accountsOf,
  hasBothProviders,
  providerName,
} from './provider'
import type { AccountView, Provider } from './types'

describe('provider display metadata', () => {
  it('uses the two product names the UI presents at the same level', () => {
    expect(PROVIDER_DISPLAY).toEqual({
      anthropic: { name: 'Claude' },
      openai: { name: 'Codex' },
    })
  })

  it('resolves the wire values without exposing them as labels', () => {
    expect(providerName('anthropic')).toBe('Claude')
    expect(providerName('openai')).toBe('Codex')
  })
})

describe('per-provider splitting', () => {
  const acc = (account_id: string, provider: Provider): AccountView => ({
    account_id,
    provider,
    label: account_id,
    email: `${account_id}@example.com`,
    state: { kind: 'loading' },
  })

  it('puts Claude in the left column and Codex in the right', () => {
    expect(PROVIDER_ORDER).toEqual(['anthropic', 'openai'])
  })

  it('keeps the backend order inside a column instead of imposing its own', () => {
    // Deliberately interleaved and not alphabetical: whatever order
    // list_accounts answered with is the order, because it is the one that
    // already reflects either the manual arrangement or §8.6's auto sort.
    const accounts = [
      acc('c2', 'openai'),
      acc('a2', 'anthropic'),
      acc('c1', 'openai'),
      acc('a1', 'anthropic'),
    ]
    expect(accountsOf(accounts, 'anthropic').map((a) => a.account_id)).toEqual(['a2', 'a1'])
    expect(accountsOf(accounts, 'openai').map((a) => a.account_id)).toEqual(['c2', 'c1'])
  })

  it('reports two columns only when both providers have an account', () => {
    expect(hasBothProviders([])).toBe(false)
    expect(hasBothProviders([acc('a1', 'anthropic')])).toBe(false)
    expect(hasBothProviders([acc('c1', 'openai')])).toBe(false)
    expect(hasBothProviders([acc('a1', 'anthropic'), acc('c1', 'openai')])).toBe(true)
  })
})
