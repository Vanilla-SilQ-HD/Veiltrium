<script>
  import { t } from './i18n.svelte.js';
  let { servers = [] } = $props();
</script>
{#if servers.length}
  <p role="note" class="m-0 rounded-lg bg-warn-soft p-3 text-xs text-warn">{t('sb.changeWarning', { servers: servers.join(', ') })}</p>
{/if}
