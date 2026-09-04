import type { Severity } from './types'

/**
 * docs/design.md §8.2. The same thresholds terminal statusline tools use.
 *
 * **Duplicated deliberately.** `Severity::from_percent` in
 * `crates/core/src/model.rs` carries the identical table and has its own test;
 * no single test can catch the two drifting apart, so change them together.
 *
 * `percent` is always finite: the Rust parser never fabricates a window, so a
 * missing or unparseable value arrives as an absent window rather than as a
 * number. See `crates/core/src/usage/parse.rs`.
 *
 * **It is not always 0-100.** A window's percentage is, but `CreditSpend.percent`
 * is `used / limit` and `parse_credit` deliberately does not clamp it — spending
 * past the monthly limit is the thing the credit line exists to show, and the
 * measured body had $22.31 against a $20.00 limit. Everything downstream must
 * cope: this function saturates at `red`, and `barWidth` clamps when it draws.
 */
export function severityOf(percent: number): Severity {
  if (percent >= 90) return 'red'
  if (percent >= 70) return 'yellow'
  if (percent >= 40) return 'cyan'
  return 'green'
}

export function barWidth(percent: number, cells: number): number {
  const clamped = Math.min(100, Math.max(0, percent))
  return Math.round((clamped / 100) * cells)
}

/** docs/design.md §7.3. A stale value is never rendered without its age. */
export function relativeAge(fetchedAt: Date, now: Date): string {
  const secs = Math.floor((now.getTime() - fetchedAt.getTime()) / 1000)
  if (secs < 60) return 'just now'
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

/**
 * Rough daily query count for the settings window's interval hint.
 *
 * The guard is not defensive noise. Svelte's `bind:value` on
 * `<input type="number">` sets the bound variable to `null` when the field is
 * cleared (`to_number` returns `null` for `''`), and
 * `Math.round((86400 / null) * 2)` is `Infinity`. Rendering "roughly Infinity
 * queries per day" is AGENTS.md's confidently-wrong-number failure in
 * miniature.
 */
export function queriesPerDay(intervalSecs: number | null, accountCount: number): number {
  if (!(Number(intervalSecs) > 0) || !(accountCount > 0)) return 0
  return Math.round((86400 / Number(intervalSecs)) * accountCount)
}

/**
 * docs/design.md §7.1 fixes this as "throttled, after HH:MM" — a locale string
 * is wrong.
 *
 * It lives here rather than in `src/widget/AccountRow.svelte` because both
 * windows say it: the widget row renders §7.1's state, and the settings window
 * renders §6.4's refusal of a manual refresh. Two copies of a string the spec
 * pins is the two-sources-disagree hazard §7.1 exists to prevent — the same
 * reasoning the `AccountView` doc comment in `src-tauri/src/commands.rs` uses
 * to justify keeping no second copy of `quarantined` on the wire.
 *
 * Wall clock in the **user's** zone, which is why `getHours`/`getMinutes` and
 * not the UTC pair: the instant is transmitted as UTC, but "after 14:05" is
 * only actionable if it reads off the clock the user is looking at.
 */
export function untilHhMm(iso: string): string {
  const d = new Date(iso)
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  return `${hh}:${mm}`
}

/**
 * One `CreditSpend` amount as text, e.g. `$22.31`.
 *
 * The exponent comes from the response and is honoured rather than assumed to
 * be 2 — `crates/core/src/usage/raw.rs` leaves `exponent` unmasked in the debug
 * window precisely because a silent change from cents to mills is the drift
 * §12.4 asks us to notice, and hardcoding 2 here is how that drift would become
 * a wrong number on screen instead.
 *
 * `Intl` throws a `RangeError` on a currency code it does not know. The fallback
 * keeps the amount readable rather than blanking the line: the digits are the
 * part the user needs, and dropping them to protect a currency symbol would be
 * the worse trade.
 */
export function formatMoney(minor: number, currency: string, exponent: number): string {
  const amount = minor / 10 ** exponent
  try {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency,
      minimumFractionDigits: exponent,
      maximumFractionDigits: exponent,
    }).format(amount)
  } catch {
    return `${amount.toFixed(exponent)} ${currency}`
  }
}

/**
 * docs/design.md §8.1. The unit groups are separated by a space and the text is
 * variable width; Task 15 gives the column a fixed width in CSS instead. Zero
 * padding the leading units would produce readings like "0d 00h 00m".
 */
export function formatReset(resetsAt: Date, now: Date): string {
  const secs = Math.floor((resetsAt.getTime() - now.getTime()) / 1000)
  if (secs <= 0) return 'now'
  const days = Math.floor(secs / 86400)
  const hours = Math.floor((secs % 86400) / 3600)
  const mins = Math.floor((secs % 3600) / 60)
  if (days > 0) return `${days}d ${String(hours).padStart(2, '0')}h`
  if (hours > 0) return `${hours}h ${String(mins).padStart(2, '0')}m`
  return `${mins}m`
}
