<script lang="ts">
  import { formatMoney, severityOf } from '../lib/format'
  import type { CreditSpend } from '../lib/types'

  export let credit: CreditSpend

  // `severityOf` saturates at red, which is what a percentage over 100 should
  // read as. It is not clamped before this call: the number printed beside the
  // amounts has to agree with them, and $22.31 against $20.00 is 112%.
  $: severity = severityOf(credit.percent)
  $: used = formatMoney(credit.used_minor, credit.currency, credit.exponent)
  $: limit = formatMoney(credit.limit_minor, credit.currency, credit.exponent)
</script>

<div class="credit-row">
  <span class="label">credits</span>
  <span class="pct {severity}">{credit.percent.toFixed(0)}%</span>
  <span class="amounts">{used} / {limit}</span>
</div>

<style>
  /* **The three column widths must stay identical to `.bar-row` in
     Bar.svelte.** They are what lines this row's percentage up with the 5h and
     weekly percentages directly above it; a mismatch does not break anything,
     it just quietly ragged-edges the column, which is the kind of defect that
     survives review because the screen still looks fine.

     There is no bar here, and that is a width decision rather than a stylistic
     one. The widget is 280px wide with .7em of padding a side, leaving ~258px.
     The label track is 7.8em (85.8px) and the percent 2.85em (31.35px); a
     10-cell bar plus its gap costs ~68px more, which leaves ~65px for
     "$22.31 / $20.00" — about 90px at 11px system-ui. The amounts are the
     thing this line exists to show, so the bar is what gives way. */
  .credit-row { display: grid; grid-template-columns: 7.8em max-content 1fr;
                align-items: baseline; gap: .35em; font-size: 11px; }
  .label { opacity: .75; white-space: nowrap; }
  /* Same box as Bar.svelte's `.pct`, for the same measured reason — except this
     one is not capped at "100%": an over-limit reading is three digits plus the
     sign, so the box is a minimum and the column grows if it has to. */
  .pct { display: inline-block; min-width: 2.85em; text-align: right;
         font-variant-numeric: tabular-nums; }
  .amounts { text-align: right; opacity: .7; white-space: nowrap;
             overflow: hidden; text-overflow: ellipsis;
             font-variant-numeric: tabular-nums; }
  .green  { color: #4ade80 }
  .cyan   { color: #22d3ee }
  .yellow { color: #facc15 }
  .red    { color: #f87171 }
</style>
