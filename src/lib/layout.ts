import { hasBothProviders } from './provider'
import type { AccountView, WidgetLayout } from './types'

/**
 * docs/design.md §8.1's widget widths.
 *
 * **These two numbers have one home, and both `src/main.ts` and
 * `src/widget/Widget.svelte` read them from here.** The window size and the
 * document's own minimum width have to agree: the view measures its height and
 * pushes it back (`followContentHeight`), so if the document laid itself out at
 * 280px while the window was about to become 520px, the height pushed back
 * would be the height of the squeezed layout.
 */
export const WIDGET_WIDTH_SINGLE = 280

/**
 * Two columns. Measured rather than guessed: one bar row needs 7.8em of label
 * track (85.8px at 11px), a ten-cell monospace bar with its percent
 * (about 95px), the reset column (about 35px) and two .35em gaps — roughly
 * 224px. Two of those plus the column gap and the card's .7em side padding come
 * to about 481px, and 520 leaves the reset column the slack that keeps it from
 * wrapping, which would double every bar row's height.
 */
export const WIDGET_WIDTH_SPLIT = 520

/**
 * Whether the widget draws its provider sections side by side.
 *
 * **The one answer both the window size and the document read.** `Widget.svelte`
 * decides its grid from this and `widgetWidth` decides the window from it, so
 * a vertical layout can never be laid out at 280px inside a 520px window, or
 * the reverse.
 */
export function isSplit(accounts: AccountView[], layout: WidgetLayout): boolean {
  return layout === 'horizontal' && hasBothProviders(accounts)
}

/**
 * How wide the widget window should be for this account list and layout.
 *
 * A function of the accounts rather than a constant because a user with only
 * Claude accounts would otherwise get a 520px window with half of it empty —
 * and that is also every widget that existed before columns did. A vertical
 * layout stacks the sections, so it keeps the single-column width however many
 * providers there are.
 */
export function widgetWidth(accounts: AccountView[], layout: WidgetLayout): number {
  return isSplit(accounts, layout) ? WIDGET_WIDTH_SPLIT : WIDGET_WIDTH_SINGLE
}
