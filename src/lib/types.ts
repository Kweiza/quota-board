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
   */
  applicable: number
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
 * Mirrors `StoreKind` in `src-tauri/src/state.rs`, which serializes with
 * `#[serde(rename_all = "snake_case")]`. docs/design.md §9.2 gives
 * `keychain_locked` and `no_backend` the same account state (`SECRETS_LOCKED`)
 * but **different remedies** — a passphrase opens a different, empty store on a
 * merely locked keychain — which is why this is a discriminant and not a
 * boolean. Change both sides together.
 */
export type StoreKind = 'keychain' | 'encrypted_file' | 'no_backend' | 'keychain_locked'

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
 * display CLAUDE.md forbids, so it is on the wire rather than inferred.
 */
export interface RawResponse {
  captured_at: string
  status: number
  truncated: boolean
  body: string
}

/**
 * Mirrors `LoginUrls` in `src-tauri/src/commands.rs`. Change both together.
 *
 * docs/design.md §10.3 builds both URLs for one login; they share the PKCE pair
 * and differ only in `redirect_uri`, so a code issued for either can be
 * exchanged. `loopback` is null when no local socket could be bound — not a
 * failure, just the automatic half being unavailable.
 */
export interface LoginUrls {
  loopback: string | null
  manual: string
}

/** Mirrors `ManualFallback` in `src-tauri/src/commands.rs`. Change both together. */
export interface ManualFallback {
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
