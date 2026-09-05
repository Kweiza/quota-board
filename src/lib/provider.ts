import type { AccountView, Provider } from './types'

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

/**
 * Left column first, then right. docs/design.md §8.1 lays the widget out in
 * this order and §8.4 repeats it in Settings, so the two windows read it from
 * here rather than each spelling out a literal that could drift.
 */
export const PROVIDER_ORDER: Provider[] = ['anthropic', 'openai']

/**
 * The accounts of one provider, in the order the backend gave them.
 *
 * **A filter, never a sort.** `list_accounts` has already decided the order —
 * either the user's arrangement or §8.6's auto sort — and re-ordering here
 * would give the widget and Settings a second opinion about it, which is the
 * two-sources-disagree failure §9.3 keeps warning about.
 */
export function accountsOf(accounts: AccountView[], provider: Provider): AccountView[] {
  return accounts.filter((a) => a.provider === provider)
}

/**
 * Whether the two-column layout applies: both providers have at least one
 * account.
 *
 * With only one provider present the second column would be an empty box
 * taking half the widget, so §8.1 keeps the single-column 280px window for
 * that case — which is also every widget that existed before columns did.
 */
export function hasBothProviders(accounts: AccountView[]): boolean {
  return PROVIDER_ORDER.every((p) => accounts.some((a) => a.provider === p))
}
