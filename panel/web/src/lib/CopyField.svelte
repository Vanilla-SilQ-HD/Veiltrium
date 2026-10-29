<script>
  import Icon from './Icon.svelte';
  import { t } from './i18n.svelte.js';
  import { flash } from './toast.svelte.js';

  let { title, hint, value, shown, multiline = false } = $props();
  let manual = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      manual = false;
      flash(t('common.copied', { what: title }));
    } catch {
      manual = true;
    }
  }
</script>

<div class="flex flex-col gap-1.5">
  <div class="flex items-center justify-between gap-2">
    <span class="text-xs font-medium">{title}</span>
    <span class="text-[11px] text-muted">{hint}</span>
  </div>
  <div class="flex items-stretch gap-2">
    <code class="min-w-0 flex-1 overflow-x-auto rounded-lg border border-line bg-bg px-3 py-2.5 font-mono text-xs
      {multiline ? 'whitespace-pre' : 'whitespace-nowrap'}">{shown}</code>
    <button type="button" onclick={copy} aria-label={t('common.copy', { what: title })}
      class="flex w-11 shrink-0 items-center justify-center rounded-lg border border-line text-fg">
      <Icon name="copy" size={16} />
    </button>
  </div>
  {#if manual}
    <label class="flex flex-col gap-1 text-xs text-muted">
      {t('common.copyManual')}
      <textarea readonly value={value} onfocus={(e) => e.currentTarget.select()} rows={multiline ? 6 : 3}
        class="w-full min-w-0 rounded-lg border border-line bg-bg p-2 font-mono text-xs text-fg" aria-label={t('common.copy', { what: title })}></textarea>
    </label>
  {/if}
</div>
