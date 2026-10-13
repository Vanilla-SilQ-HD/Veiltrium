<script>
  import { t } from './i18n.js';
  import Icon from './Icon.svelte';

  // Progress of a client change as the installer reports it (::step lines).
  let { order, seen, done = false } = $props();
  let current = $derived(seen.length ? seen[seen.length - 1] : '');
</script>

<ol class="m-0 flex list-none flex-col gap-2.5 p-0">
  {#each order as s (s)}
    {@const finished = done || (seen.includes(s) && s !== current)}
    {@const active = !done && s === current}
    <li class="flex items-center gap-2.5 {finished || active ? 'text-fg' : 'text-muted'}">
      <span class="flex h-5 w-5 items-center justify-center rounded-full border-[1.5px]
        {finished ? 'border-ok bg-ok text-on-accent' : active ? 'border-accent' : 'border-line'}">
        {#if finished}<Icon name="check" size={12} />{/if}
      </span>
      <span>{t('step.' + s)}</span>
    </li>
  {/each}
</ol>
