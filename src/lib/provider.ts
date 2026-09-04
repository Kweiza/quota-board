import type { Provider } from './types'

/**
 * Product-facing provider metadata.
 *
 * The serialized values in `Provider` are storage and IPC words, not labels.
 * Keeping the display names here gives the widget, Settings, Debug and login
 * fallback one vocabulary instead of four maps that can drift independently.
 */
export const PROVIDER_DISPLAY = {
  anthropic: { name: 'Claude' },
  openai: { name: 'Codex' },
} satisfies Record<Provider, { name: string }>

export function providerName(provider: Provider): string {
  return PROVIDER_DISPLAY[provider].name
}
