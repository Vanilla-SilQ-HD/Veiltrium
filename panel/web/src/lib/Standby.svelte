<script>
  import { api, AuthError } from './api.js';
  import { onMount } from 'svelte';
  import { t, locale } from './i18n.svelte.js';
  import CopyField from './CopyField.svelte';
  let { status, onAuthLost, onUpdated } = $props();
  let details = $state(null);
  let token = $state('');
  let error = $state('');
  let saving = $state(false);
  let expanded = $state(false);
  let message = $state('');
  // Parent status is authoritative after refresh or a local client change.
  let now = $state(Date.now());
  onMount(() => { const timer = setInterval(() => (now = Date.now()), 30000); return () => clearInterval(timer); });
  let servers = $derived((status?.servers ?? []).map((server) => ({ ...server,
    state: server.state === 'matching' && now - Date.parse(server.checked_at) > (status?.max_age_seconds ?? 86400) * 1000 ? 'stale' : server.state,
  })));
  const date = (v) => v ? new Date(v).toLocaleString(locale()) : t('sb.never');
  async function open() {
    expanded = !expanded;
    if (!expanded) return;
    error = '';
    try { details = await api.standby(); }
    catch (e) { if (e instanceof AuthError) onAuthLost(); else error = e.message; }
  }
  async function verify() {
    if (saving || !token.trim()) return;
    saving = true; error = ''; message = '';
    try {
      details = await api.verifyStandby(token.trim());
      token = '';
      message = t('sb.recorded');
      await onUpdated();
    } catch (e) { if (e instanceof AuthError) onAuthLost(); else error = e.message; }
    finally { saving = false; }
  }
</script>

<section class="flex flex-col gap-3 rounded-xl border border-line bg-surface p-4" aria-label={t('sb.title')}>
  <div class="flex flex-wrap items-center justify-between gap-2">
    <h2 class="m-0 text-base font-semibold">{t('sb.title')}</h2>
    <button type="button" onclick={open} aria-expanded={expanded} class="min-h-10 rounded-lg border border-line px-3 text-sm">{t('sb.manage')}</button>
  </div>
  <p class="m-0 text-xs text-muted">{t('sb.scope')}</p>
  {#if !servers.length}<p class="m-0 text-sm text-muted">{t('sb.none')}</p>{/if}
  {#each servers as server (server.server)}
    <div class="flex flex-wrap items-start justify-between gap-2 rounded-lg bg-surface2 p-3">
      <span class="font-mono text-sm">{server.server}</span>
      <div class="flex flex-col text-right text-xs">
        <span class={server.state === 'matching' ? 'text-ok' : 'text-warn'}>{t('sb.state.' + server.state)}</span>
        <span class="text-muted">{date(server.checked_at)}</span>
      </div>
    </div>
  {/each}
  {#if expanded}
    <ol class="m-0 flex flex-col gap-2 pl-5 text-sm text-muted">
      <li>{t('sb.how1')} <code class="font-mono text-fg">veiltrium standby-receipt</code></li>
      <li>{t('sb.how2')}</li>
      <li>{t('sb.how3')}</li>
    </ol>
    {#if servers.length}
      <label for="standby-receipt" class="text-sm font-medium">{t('sb.paste')}</label>
      <textarea id="standby-receipt" bind:value={token} rows="3" maxlength="512" spellcheck="false" autocomplete="off" placeholder="vt-standby-1|…"
        class="w-full min-w-0 rounded-lg border border-line bg-bg p-3 font-mono text-xs text-fg"></textarea>
      <button type="button" onclick={verify} disabled={saving || !token.trim()} class="min-h-11 self-start rounded-lg bg-accent px-4 font-semibold text-on-accent disabled:opacity-50">{saving ? t('sb.verifying') : t('sb.verify')}</button>
    {/if}
    <details class="text-sm">
      <summary class="cursor-pointer text-accent">{t('sb.thisReceipt')}</summary>
      {#if details?.local_receipt}
        <CopyField title={t('sb.thisReceipt')} hint="" value={details.local_receipt} shown={details.local_receipt} />
        <p class="text-xs text-muted">{t('sb.receiptNote')}</p>
      {:else}<p class="text-muted">{t('sb.noReceipt')}</p>{/if}
    </details>
    <details class="text-sm"><summary class="cursor-pointer text-accent">{t('sb.updateTitle')}</summary>
      <p class="text-muted">{t('sb.updateText')}</p>
      <p class="text-xs text-muted">{t('sb.quotaNote')}</p>
    </details>
  {/if}
  {#if message}<p role="status" class="m-0 text-sm text-ok">{message}</p>{/if}
  {#if error}<p role="alert" class="m-0 text-sm text-danger">{error}</p>{/if}
</section>
