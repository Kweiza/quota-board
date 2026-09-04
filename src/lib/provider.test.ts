import { describe, expect, it } from 'vitest'
import { PROVIDER_DISPLAY, providerName } from './provider'

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
