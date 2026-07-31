import { describe, expect, it } from 'vitest'
import {
  barWidth,
  formatReset,
  queriesPerDay,
  relativeAge,
  severityOf,
  untilHhMm,
} from './format'

describe('severityOf', () => {
  it('changes at the 40/70/90 boundaries', () => {
    expect(severityOf(0)).toBe('green')
    expect(severityOf(39.9)).toBe('green')
    expect(severityOf(40)).toBe('cyan')
    expect(severityOf(69.9)).toBe('cyan')
    expect(severityOf(70)).toBe('yellow')
    expect(severityOf(89.9)).toBe('yellow')
    expect(severityOf(90)).toBe('red')
    expect(severityOf(100)).toBe('red')
  })
})

describe('barWidth', () => {
  it('converts a percentage into a cell count', () => {
    expect(barWidth(0, 10)).toBe(0)
    expect(barWidth(50, 10)).toBe(5)
    expect(barWidth(100, 10)).toBe(10)
  })
  it('clamps out-of-range values', () => {
    expect(barWidth(-5, 10)).toBe(0)
    expect(barWidth(140, 10)).toBe(10)
  })
  it('rounds to the nearest cell', () => {
    expect(barWidth(15, 10)).toBe(2)
    expect(barWidth(14, 10)).toBe(1)
  })
})

describe('relativeAge', () => {
  const now = new Date('2026-07-29T12:00:00Z')
  it('reports under a minute as "just now"', () => {
    expect(relativeAge(new Date('2026-07-29T11:59:30Z'), now)).toBe('just now')
  })
  it('switches to minutes at exactly 60 seconds', () => {
    expect(relativeAge(new Date('2026-07-29T11:59:00Z'), now)).toBe('1m ago')
  })
  it('reports whole minutes', () => {
    expect(relativeAge(new Date('2026-07-29T11:48:00Z'), now)).toBe('12m ago')
  })
  it('switches to hours at exactly 60 minutes', () => {
    expect(relativeAge(new Date('2026-07-29T11:00:00Z'), now)).toBe('1h ago')
  })
  it('reports whole hours', () => {
    expect(relativeAge(new Date('2026-07-29T09:30:00Z'), now)).toBe('2h ago')
  })
  it('still reports hours at 23h59m', () => {
    expect(relativeAge(new Date('2026-07-28T12:01:00Z'), now)).toBe('23h ago')
  })
  it('switches to days at exactly 24 hours', () => {
    expect(relativeAge(new Date('2026-07-28T12:00:00Z'), now)).toBe('1d ago')
  })
})

describe('queriesPerDay', () => {
  it('scales with the account count and inversely with the interval', () => {
    expect(queriesPerDay(300, 1)).toBe(288)
    expect(queriesPerDay(300, 3)).toBe(864)
    expect(queriesPerDay(180, 3)).toBe(1440)
  })

  // Every one of these reaches the hint through `bind:value`, which answers
  // `null` for a cleared field. Without the guard the first case renders
  // "roughly Infinity queries per day".
  it('never reports Infinity or NaN for a degenerate input', () => {
    expect(queriesPerDay(null, 2)).toBe(0)
    expect(queriesPerDay(0, 2)).toBe(0)
    expect(queriesPerDay(-1, 2)).toBe(0)
    expect(queriesPerDay(NaN, 2)).toBe(0)
    expect(queriesPerDay(300, 0)).toBe(0)
  })
})

describe('untilHhMm', () => {
  // Every input here is built from local calendar fields and then serialized,
  // so the expected string is the same in any zone the suite runs in. Writing
  // a UTC literal and expecting '14:05' would only pass in UTC+0 — and this
  // formatter is deliberately local-time, so such a test would be asserting
  // the machine's zone rather than the format.
  const iso = (hours: number, minutes: number): string =>
    new Date(2026, 6, 31, hours, minutes).toISOString()

  it('renders the fixed HH:MM shape §7.1 pins, not a locale string', () => {
    expect(untilHhMm(iso(14, 5))).toBe('14:05')
  })

  it('pads a single-digit hour, so the field never narrows to H:MM', () => {
    // A row that reads "9:05" one moment and "14:05" the next changes width
    // under the user; §7.1 pins two digits.
    expect(untilHhMm(iso(9, 5))).toBe('09:05')
  })

  it('keeps midnight as 00:00 on a 24-hour clock, not 12:00', () => {
    // `toLocaleTimeString` on an en-US machine answers "12:00 AM" here, which
    // is the locale string this formatter exists to avoid.
    expect(untilHhMm(iso(0, 0))).toBe('00:00')
  })
})

describe('formatReset', () => {
  const now = new Date('2026-07-29T12:00:00Z')
  it('reports an hour or more as hours and minutes', () => {
    expect(formatReset(new Date('2026-07-29T13:23:00Z'), now)).toBe('1h 23m')
  })
  it('pads the minutes inside an hours reading', () => {
    expect(formatReset(new Date('2026-07-29T14:05:00Z'), now)).toBe('2h 05m')
  })
  it('reports under an hour as minutes only', () => {
    expect(formatReset(new Date('2026-07-29T12:47:00Z'), now)).toBe('47m')
  })
  it('reports a day or more as days and hours', () => {
    expect(formatReset(new Date('2026-08-02T00:00:00Z'), now)).toBe('3d 12h')
  })
  it('pads the hours inside a days reading', () => {
    expect(formatReset(new Date('2026-08-01T16:00:00Z'), now)).toBe('3d 04h')
  })
  it('switches to the days branch at exactly one day', () => {
    expect(formatReset(new Date('2026-07-30T17:00:00Z'), now)).toBe('1d 05h')
  })
  it('reports "now" at exactly zero', () => {
    expect(formatReset(new Date('2026-07-29T12:00:00Z'), now)).toBe('now')
  })
  it('reports "now" once the reset is in the past', () => {
    expect(formatReset(new Date('2026-07-29T11:00:00Z'), now)).toBe('now')
  })
  it('reports under a minute as 0m, not "now"', () => {
    expect(formatReset(new Date('2026-07-29T12:00:30Z'), now)).toBe('0m')
  })
})
