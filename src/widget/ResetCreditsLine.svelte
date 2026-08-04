<script lang="ts">
  import type { ResetCredits } from '../lib/types'

  export let credits: ResetCredits

  /**
   * Both numbers only when they disagree. Measured `1 / 0` means "you hold a
   * credit and it does nothing for the limit you are hitting"; printing the
   * first alone would say the opposite, and printing "2 (2 applicable)" is
   * noise.
   */
  $: text =
    credits.applicable === credits.available
      ? `${credits.available}`
      : `${credits.available} (${credits.applicable} applicable)`
</script>

<div class="credit-row">
  <span class="label">reset credits</span>
  <span class="amounts">{text}</span>
</div>

<style>
  /* Two tracks, not three: unlike Bar and CreditLine, this row has no
     percentage, so there is nothing to put in a middle column — an empty one
     would be a track that exists only to be empty. The label is still pinned
     to the same 7.8em the bars above it use, and the figure is right-aligned
     in a trailing 1fr, so it lands on the same right edge as Bar's `.reset`
     and CreditLine's `.amounts` even though nothing sits between them. `gap`
     and `align-items` match both siblings' values for no reason other than
     that they are siblings: a value that differs with no reason stated is the
     quietly-ragged column CreditLine.svelte's own comment warns about. */
  .credit-row { display: grid; grid-template-columns: 7.8em 1fr;
                align-items: baseline; gap: .35em; font-size: 11px; }
  .label   { opacity: .75; white-space: nowrap; }
  .amounts { text-align: right; opacity: .7; white-space: nowrap; }
</style>
