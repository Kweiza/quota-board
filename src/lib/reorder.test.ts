import { describe, expect, it } from 'vitest'
import { moveTo } from './reorder'

describe('moveTo', () => {
  const abcde = ['a', 'b', 'c', 'd', 'e']

  it('lands the moved item on the index it was dropped on, dragging down', () => {
    expect(moveTo(abcde, 0, 2)).toEqual(['b', 'c', 'a', 'd', 'e'])
  })

  it('lands on the same index dragging up, which is what makes a drag reversible', () => {
    // The round trip is the property that matters: a user who drags a row down
    // and immediately drags it back must get the arrangement they started with.
    expect(moveTo(moveTo(abcde, 0, 2), 2, 0)).toEqual(abcde)
  })

  it('moves to either end', () => {
    expect(moveTo(abcde, 4, 0)).toEqual(['e', 'a', 'b', 'c', 'd'])
    expect(moveTo(abcde, 0, 4)).toEqual(['b', 'c', 'd', 'e', 'a'])
  })

  it('returns the input untouched for a no-op or an out-of-range request', () => {
    expect(moveTo(abcde, 2, 2)).toBe(abcde)
    expect(moveTo(abcde, -1, 2)).toBe(abcde)
    expect(moveTo(abcde, 2, 5)).toBe(abcde)
    expect(moveTo(abcde, 5, 2)).toBe(abcde)
    expect(moveTo([], 0, 0)).toEqual([])
  })

  it('does not mutate the array it was given', () => {
    const original = [...abcde]
    moveTo(abcde, 0, 3)
    expect(abcde).toEqual(original)
  })
})
