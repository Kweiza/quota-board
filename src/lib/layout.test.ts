import { describe, expect, it } from 'vitest'
import { WIDGET_WIDTH_SINGLE, WIDGET_WIDTH_SPLIT, isSplit, widgetWidth } from './layout'
import type { AccountView, Provider } from './types'

const account = (provider: Provider): AccountView => ({
  account_id: `${provider}-1`,
  provider,
  label: provider,
  email: `${provider}@example.com`,
  state: { kind: 'loading' },
})

describe('widgetWidth', () => {
  it('stays at the single-column width until both providers have an account', () => {
    // Including the empty list: the widget starts empty on every launch, and a
    // 520px window holding one "Loading accounts…" line would be the first
    // thing every user saw.
    expect(widgetWidth([], 'horizontal')).toBe(WIDGET_WIDTH_SINGLE)
    expect(widgetWidth([account('anthropic')], 'horizontal')).toBe(WIDGET_WIDTH_SINGLE)
    expect(widgetWidth([account('openai')], 'horizontal')).toBe(WIDGET_WIDTH_SINGLE)
    expect(widgetWidth([account('anthropic'), account('anthropic')], 'horizontal')).toBe(WIDGET_WIDTH_SINGLE)
  })

  it('widens to two columns once both providers have an account', () => {
    expect(widgetWidth([account('anthropic'), account('openai')], 'horizontal')).toBe(WIDGET_WIDTH_SPLIT)
  })

  /**
   * §8.1's vertical layout stacks the sections, so the window stays narrow even
   * with both providers. Checked through `isSplit` as well as `widgetWidth`:
   * `Widget.svelte` draws its grid from the first and `src/main.ts` sizes the
   * window from the second, and the two disagreeing is the squeezed-layout
   * height defect `WIDGET_WIDTH_SPLIT`'s comment describes.
   */
  it('keeps the single-column width when the layout is vertical', () => {
    const both = [account('anthropic'), account('openai')]
    expect(widgetWidth(both, 'vertical')).toBe(WIDGET_WIDTH_SINGLE)
    expect(isSplit(both, 'vertical')).toBe(false)
    expect(isSplit(both, 'horizontal')).toBe(true)
  })

  /**
   * One bar row needs about 224px (see `WIDGET_WIDTH_SPLIT`'s own comment), so
   * two columns plus the gap and the card's padding do not fit in anything
   * near the single-column width. A split width that had drifted down toward
   * 280 would wrap every reset time and double the height of every row.
   */
  it('leaves room for two full bar rows', () => {
    expect(WIDGET_WIDTH_SPLIT).toBeGreaterThanOrEqual(2 * 224 + 12 + 23)
  })
})
