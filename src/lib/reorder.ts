/**
 * Move the item at `from` to index `to`, leaving every other item's relative
 * order alone.
 *
 * **Positional, not "insert before" or "insert after".** Dropping a row on the
 * third row makes it the third row, whichever direction it came from — the
 * two-rule alternative reads as an off-by-one to the person dragging, because
 * dragging down and dragging back up then land in different places.
 *
 * Returns a new array; an out-of-range or no-op request returns the input
 * unchanged rather than throwing, so a drop on the row that is already there
 * costs a comparison instead of a write to disk.
 */
export function moveTo<T>(items: T[], from: number, to: number): T[] {
  if (from === to) return items
  if (from < 0 || to < 0 || from >= items.length || to >= items.length) return items
  const next = items.slice()
  next.splice(to, 0, ...next.splice(from, 1))
  return next
}
