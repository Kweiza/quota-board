export type Severity = 'green' | 'cyan' | 'yellow' | 'red'

export interface UsageWindow {
  window_id: string
  label: string
  percent: number
  resets_at: string
  scope: string | null
}

/**
 * Mirrors `AccountState` in `crates/core/src/model.rs`, which is serialized
 * with `#[serde(tag = "kind", rename_all = "snake_case")]`. That module carries
 * the reciprocal note; the two must be changed together.
 */
export type AccountState =
  | { kind: 'loading' }
  | { kind: 'ok'; windows: UsageWindow[]; fetched_at: string }
  | { kind: 'stale'; windows: UsageWindow[]; fetched_at: string }
  | { kind: 'throttled'; until: string }
  | { kind: 'auth_expired' }
  | { kind: 'auth_dead' }
  | { kind: 'secrets_locked' }
  | { kind: 'unknown_shape' }
  | { kind: 'network' }

export interface AccountView {
  uuid: string
  label: string
  /** Display only. **Never used as a key** (§9.3) — the key is `uuid`. */
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
