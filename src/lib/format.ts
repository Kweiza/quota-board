import type { Severity } from './types'

/**
 * docs/design.md §8.2. The same thresholds terminal statusline tools use.
 *
 * **Duplicated deliberately.** `Severity::from_percent` in
 * `crates/core/src/model.rs` carries the identical table and has its own test;
 * no single test can catch the two drifting apart, so change them together.
 *
 * `percent` is always a finite 0-100 value: the Rust parser never fabricates a
 * window, so a missing or unparseable value arrives as an absent window rather
 * than as a number. See `crates/core/src/usage/parse.rs`.
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
 * queries per day" is CLAUDE.md's confidently-wrong-number failure in
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
