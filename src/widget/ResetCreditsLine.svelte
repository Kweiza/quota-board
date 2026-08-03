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
  /* The grid tracks match Bar.svelte for the reason CreditLine.svelte's own
     comment gives: this row's figure lines up with the percentages above it. */
  .credit-row { display: grid; grid-template-columns: 7.8em 1fr; gap: .4em;
                font-size: 11px; padding: .1em 0; }
  .label   { opacity: .75; white-space: nowrap; }
  .amounts { text-align: right; opacity: .7; white-space: nowrap; }
</style>
