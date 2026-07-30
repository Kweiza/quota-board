<script lang="ts">
  import { barWidth, formatReset, severityOf } from '../lib/format'
  import type { UsageWindow } from '../lib/types'

  export let window_: UsageWindow
  export let now: Date

  const CELLS = 10
  $: severity = severityOf(window_.percent)
  $: filled = barWidth(window_.percent, CELLS)
  $: reset = formatReset(new Date(window_.resets_at), now)
</script>

<div class="bar-row">
  <span class="label" title={window_.label}>{window_.label}</span>
  <span class="meter">
    <span
      class="bar {severity}"
      role="meter"
      aria-valuenow={window_.percent}
      aria-valuemin="0"
      aria-valuemax="100"
      aria-label={window_.label}
    >{'█'.repeat(filled)}{'░'.repeat(CELLS - filled)}</span> <span class="pct">{window_.percent.toFixed(0)}%</span>
  </span>
  <span class="reset">{reset}</span>
</div>

<style>
  /* 7.8em holds every weekly label the core is known to send: at 11px,
     "weekly (Opus)" is 75.31px, "weekly (Fable)" 75.81px and
     "weekly (Sonnet)" 84.69px, against 85.8px of track. A longer name still
     clips, and then the ellipsis plus title/aria-label carry the full text.
     The reset column is 1fr and right-aligned rather than a fixed width: a
     too-narrow fixed column did not overflow, it *wrapped*, which doubled
     every bar row from 13px to 26px. */
  .bar-row { display: grid; grid-template-columns: 7.8em max-content 1fr;
             align-items: baseline; gap: .35em; font-size: 11px; }
  .label  { opacity: .75; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  /* Bar and percent share one grid cell, joined by a literal space, so no
     leftover track width can ever open a gap between them. */
  .meter  { white-space: nowrap; }
  .bar    { font-family: ui-monospace, monospace; letter-spacing: -.5px; }
  /* Wide enough for "100%", from a measurement rather than a guess: rendered
     at 11px system-ui with tabular-nums it is 31.23px, i.e. 2.839em, rounded
     up here to the next hundredth. A `ch` value would be wrong because `%`
     (10.23px) is far wider than a tabular digit (7px). Re-measure if the font
     or the font-size changes. Right-aligning inside that box lines the percent
     signs up across rows while keeping "72%" one character clear of the bar. */
  .pct    { display: inline-block; min-width: 2.85em; text-align: right;
            font-variant-numeric: tabular-nums; }
  /* opacity .7, not .55: .55 measured 4.37:1 against the widget background,
     below AA. */
  .reset  { text-align: right; opacity: .7; white-space: nowrap; overflow: hidden;
            font-variant-numeric: tabular-nums; }
  .green  { color: #4ade80 }
  .cyan   { color: #22d3ee }
  .yellow { color: #facc15 }
  .red    { color: #f87171 }
</style>
