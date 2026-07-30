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
