export type Severity = 'green' | 'cyan' | 'yellow' | 'red'

export interface UsageWindow {
  window_id: string
  label: string
  percent: number
  resets_at: string
  scope: string | null
}

/**
 * Mirrors `CreditSpend` in `crates/core/src/model.rs`. Change both together.
 *
 * Amounts are **minor units** (cents at `exponent` 2) because the endpoint
 * sends them that way and never as a decimal; `formatMoney` does the division.
 *
 * `percent` is `used_minor / limit_minor` computed in Rust, **not** the
 * endpoint's `spend.percent`, and it **may exceed 100**. Both facts are
 * measured — see `parse_credit`'s doc comment.
 */
export interface CreditSpend {
  used_minor: number
  limit_minor: number
  currency: string
  exponent: number
  percent: number
}

/** Mirrors `ResetCredits` in `crates/core/src/model.rs`. Change both together. */
export interface ResetCredits {
  available: number
  /**
   * Measured 0 while `available` was 1, so the two are **not** interchangeable:
   * an account can hold a credit that does nothing for the limit it is hitting.
   * Null means the response omitted applicability; it is unknown, never zero.
   */
  applicable: number | null
}

/**
 * Mirrors `ExtraLine` in `crates/core/src/model.rs`, serialized with
 * `#[serde(tag = "kind", rename_all = "snake_case")]`.
 *
 * At most one line sits under a row's bars, and which kind it is follows from
 * the provider — an enum rather than two nullable fields, so the exclusivity is
 * not something a reader has to remember.
 */
export type ExtraLine =
  | ({ kind: 'credit' } & CreditSpend)
  | ({ kind: 'reset_credits' } & ResetCredits)

/**
 * Mirrors `Provider` in `crates/core/src/provider.rs`, serialized with
 * `#[serde(rename_all = "snake_case")]`. Change both together.
 *
 * These strings are **the wire form, not a display name** — the UI says
 * "Claude" and "Codex", which are product names rather than vendor ones, and
 * `provider.ts` maps one to the other for every view. A rename on the Rust
 * side that this file did not follow would leave that lookup `undefined` and
 * throw while rendering, which is a blank widget rather than a type error.
 * `provider_serializes_as_the_typescript_union_spells_it` pins the Rust half;
 * nothing in either test suite catches the drift on its own.
 */
export type Provider = 'anthropic' | 'openai'

/**
 * Mirrors `AccountState` in `crates/core/src/model.rs`, which is serialized
 * with `#[serde(tag = "kind", rename_all = "snake_case")]`. That module carries
 * the reciprocal note; the two must be changed together.
 *
 * `extra` is `null` for an account with nothing to show under its bars — an
 * Anthropic account with no spending limit, or a Codex account with no reset
 * credits. Both are the normal case, and neither is a zero. It is also null
 * for the whole first poll after a restart, because the snapshot cache
 * deliberately does not persist it.
 */
export type AccountState =
  | { kind: 'loading' }
  | { kind: 'ok'; windows: UsageWindow[]; extra: ExtraLine | null; fetched_at: string }
  | { kind: 'stale'; windows: UsageWindow[]; extra: ExtraLine | null; fetched_at: string }
  | { kind: 'throttled'; until: string }
  | { kind: 'auth_expired' }
  | { kind: 'auth_dead' }
  /**
   * The server is refusing OAuth for this account right now. Measured on a
   * real account 2026-08-01: a 403 carrying
   * `error.details.error_code = "oauth_not_allowed_for_organization"`.
   *
   * **Not permanent**, despite the wire code naming an organization — the case
   * observed was a lapsed subscription on an ordinary account, and the message
   * itself says "currently". So it carries no re-login affordance (which would
   * be refused) and no removal prompt: the account recovers by itself once the
   * cause is resolved, and the scheduler keeps retrying with backoff.
   */
  | { kind: 'oauth_not_allowed' }
  | { kind: 'secrets_locked' }
  | { kind: 'unknown_shape' }
  | { kind: 'network' }

export interface AccountView {
  /** Half of the primary key; `provider` is the other half. Not a UUID for every provider. */
  account_id: string
  provider: Provider
  label: string
  /** Display only. **Never used as a key** (§9.3). */
  email: string
  state: AccountState
}

/**
 * The primary key (§9.3) as one string. Svelte's keyed `{#each}` blocks and
 * maps like `Settings.svelte`'s `throttledUntil` need a single hashable key
 * rather than two values, and `account_id` alone is not unique across
 * providers. Mirrors `snapshots::cache_key` in `crates/core/src/snapshots.rs`
 * — same pairing, same reason: two providers may issue the same
 * `account_id`, and a bare id would treat them as one entry, colliding a
 * keyed `{#each}` and letting one account's note or capture stand in for the
 * other's.
 */
export function accountKey(accountId: string, provider: Provider): string {
  return `${provider}:${accountId}`
}

/**
 * Mirrors `StoreKind` in `src-tauri/src/state.rs`, which serializes with
 * `#[serde(rename_all = "snake_case")]`. docs/design.md §9.2 maps three
 * startup conditions to the same account state (`SECRETS_LOCKED`) but gives
 * them different remedies: unlock the OS keychain, unlock the selected
 * encrypted file, or create the first encrypted file. That is why this is a
 * discriminant and not a boolean. Change both sides together.
 */
export type StoreKind =
  | 'keychain'
  | 'encrypted_file'
  | 'encrypted_file_locked'
  | 'no_backend'
  | 'keychain_locked'

/** Mirrors `StoreStatus` in `src-tauri/src/commands.rs`. Change both together. */
export interface StoreStatus {
  /** `SecretStore::describe()`. Display only — **never branch on this string**. */
  description: string
  kind: StoreKind
  /** Whether §9.2's fallback file exists; the first passphrase creates it. */
  fallback_file_exists: boolean
}

/** Mirrors `SettingsView` in `src-tauri/src/commands.rs`. Change both together. */
export interface SettingsView {
  /** What the scheduler is actually running at, already clamped. */
  poll_interval_secs: number
  /** §6.1's floor, sent rather than duplicated here. */
  min_interval_secs: number
  max_interval_secs: number
  /** Why the stored settings were not used, if they were not. */
  warning: string | null
  /**
   * False when the settings file carries a format version this build cannot
   * interpret. `set_settings` refuses in that case rather than overwriting a
   * newer build's file, so the window disables the control instead of offering
   * a save that is guaranteed to fail.
   */
  writable: boolean
}

/**
 * Mirrors `RawResponse` in `crates/core/src/usage/raw.rs`, which derives
 * `Serialize` with its field names as written. Change both together.
 *
 * `body` is masked **in Rust, at capture** — the webview never receives an
 * unmasked one. `truncated` says the masked body was longer than
 * `MAX_BODY_BYTES`; showing a cut body as whole would be the confidently-wrong
 * display AGENTS.md forbids, so it is on the wire rather than inferred.
 */
export interface RawResponse {
  captured_at: string
  status: number
  truncated: boolean
  body: string
}

/** Mirrors tagged `LoginStart` in `src-tauri/src/commands.rs`. Change both together. */
export type LoginStart =
  | {
      /** Correlates this command result with the background auth events it starts. */
      attempt_id: number
      kind: 'claude_browser'
      /** Null when Claude's manual-paste route is the only available path. */
      loopback: string | null
      manual: string
    }
  | {
      attempt_id: number
      kind: 'codex_browser'
      authorize_url: string
    }
  | {
      attempt_id: number
      kind: 'codex_device'
      verification_url: string
      /** Intentionally displayed, but still a short-lived credential. */
      user_code: string
      expires_at: string
    }

/** Correlated payload of `auth://completed`. Mirrors Rust; change both together. */
export interface AuthCompleted {
  attempt_id: number
  provider: Provider
}

/** Correlated payload of `auth://failed`. Mirrors Rust; change both together. */
export interface AuthFailed {
  attempt_id: number
  provider: Provider
  /** Shown verbatim: it is written for the user, not for a log. */
  message: string
}

/** Mirrors `ManualFallback` in `src-tauri/src/commands.rs`. Change both together. */
export interface ManualFallback {
  attempt_id: number
  provider: 'anthropic'
  url: string
  /** Shown verbatim: it is written for the user, not for a log. */
  reason: string
}

/**
 * Mirrors `AutostartView` in `src-tauri/src/commands.rs`. Change both together.
 *
 * `writable` is false in a development build, where enabling would register the
 * build directory instead of an installed app (docs/design.md §11.3). Same
 * shape as `SettingsView.writable` and read the same way.
 */
export interface AutostartView {
  enabled: boolean
  writable: boolean
}
