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
  state: AccountState
}
