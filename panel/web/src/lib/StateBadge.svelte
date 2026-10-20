<script>
  import { t } from './i18n.svelte.js';

  // Active, or Disabled with the reason (quota, expired, manual).
  let { c } = $props(); // a client from the list or the detail document
  let disabled = $derived(c.state === 'disabled');
  let key = $derived(disabled ? 'lim.state.' + (['quota', 'expired'].includes(c.reason) ? c.reason : 'manual') : 'lim.state.active');
</script>

<span class="inline-flex w-fit items-center rounded-full px-2 py-0.5 text-[11px] font-medium
  {disabled ? 'bg-warn-soft text-warn' : 'bg-ok-soft text-ok'}">{t(key)}</span>
