<script>
  import { t } from './i18n.svelte.js';
  import { bytesDec } from './format.js';

  // "12.3 GB of 50 GB" with a thin bar, for a client that has a traffic limit.
  let { c } = $props();
  let used = $derived(c.period_bytes ?? 0);
  let share = $derived(c.limit ? Math.min(100, (used / c.limit) * 100) : 0);
</script>

{#if c.limit}
  <div class="flex flex-col gap-1">
    <span class="text-xs text-muted">{t('lim.of', { used: bytesDec(used), limit: bytesDec(c.limit) })}</span>
    <div class="h-1 w-full overflow-hidden rounded-full bg-surface2" role="progressbar" aria-valuemin="0" aria-valuemax="100"
      aria-valuenow={Math.round(share)} aria-label={t('lim.of', { used: bytesDec(used), limit: bytesDec(c.limit) })}>
      <div class="h-full rounded-full {share >= 100 ? 'bg-danger' : share >= 85 ? 'bg-warn' : 'bg-accent'}" style="width: {share}%"></div>
    </div>
  </div>
{/if}
