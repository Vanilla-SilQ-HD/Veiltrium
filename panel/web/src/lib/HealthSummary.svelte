<script>
  import { onMount } from 'svelte';
  import { health } from './health.js';
  import { t, locale } from './i18n.svelte.js';
  let { st, onClients, onCheckRussia, checking } = $props();
  let now = $state(Date.now());
  onMount(() => { const timer = setInterval(() => (now = Date.now()), 30000); return () => clearInterval(timer); });
  let h = $derived(health(st, now));
  const date = (v) => v ? new Date(v).toLocaleString(locale()) : t('health.never');
  let homes = $derived([
    st.hysteria2 && ['Hysteria 2', st.hysteria2.home_network, st.hysteria2.home_checked_at],
    st.reality && ['VLESS Reality', st.reality.home_network, st.reality.home_checked_at],
    st.trusttunnel && ['TrustTunnel HTTP/2', st.trusttunnel.home_network_h2, st.trusttunnel.home_checked_at_h2],
    st.trusttunnel && ['TrustTunnel HTTP/3', st.trusttunnel.home_network_h3, st.trusttunnel.home_checked_at_h3],
  ].filter(Boolean));
  const known = ['ok', 'fail', 'degraded', 'stalled', 'stale', 'route_unverified', 'untested'];
</script>

<section aria-label={t('health.title')} class="flex flex-col gap-4 rounded-xl border border-line bg-surface p-5">
  <div class="flex flex-col gap-1">
    <span class="text-xs text-muted">{t('health.title')}</span>
    <h2 class="m-0 text-xl font-semibold {h.tone === 'ok' ? 'text-ok' : h.tone === 'danger' ? 'text-danger' : 'text-warn'}">{t('health.title.' + h.title)}</h2>
    <p class="m-0 text-sm text-muted">{t('health.detail.' + h.title)}</p>
  </div>
  <dl class="m-0 grid gap-3 text-sm sm:grid-cols-3">
    <div><dt class="text-xs text-muted">{t('ov.services')}</dt><dd class="m-0">{t('ov.servicesValue', { n: h.active, total: h.total })}</dd></div>
    <div><dt class="text-xs text-muted">{t('health.address')}</dt><dd class="m-0">{t('health.russia.' + (h.russia ?? 'unchecked'))}</dd>
      <dd class="m-0 text-xs text-muted">{date(st.russia?.checked_at)}</dd></div>
    <div><dt class="text-xs text-muted">{t('health.tunnel')}</dt><dd class="m-0">{t('health.home.' + h.home)}</dd></div>
  </dl>
  <div class="flex flex-col gap-2 rounded-lg bg-surface2 p-3">
    <span class="text-xs font-semibold">{t('health.next')}</span>
    <p class="m-0 text-sm">{t('health.action.' + h.action)}</p>
    {#if h.action === 'diagnose'}<code class="font-mono text-sm">veiltrium diagnose</code>
    {:else if h.action === 'russia'}<button type="button" onclick={onCheckRussia} disabled={checking} class="min-h-10 self-start rounded-lg border border-line px-3">{checking ? t('ov.ruChecking') : t('ov.ruCheck')}</button>
    {:else if h.action === 'connect'}<button type="button" onclick={onClients} class="min-h-10 self-start rounded-lg bg-accent px-3 font-semibold text-on-accent">{t('setup.title')}</button>{/if}
    {#if h.action === 'home' || h.action === 'working'}<p class="m-0 text-xs text-muted">{t('health.probeHelp')}</p>{/if}
    {#if h.action !== 'connect'}<button type="button" onclick={onClients} class="min-h-10 self-start rounded-lg border border-line px-3">{t('setup.title')}</button>{/if}
  </div>
  <details class="text-sm"><summary class="cursor-pointer text-accent">{t('health.evidence')}</summary>
    <ul class="mb-0 flex flex-col gap-2 pl-5">
      {#each homes as [name, state, at]}
        <li><span class="font-medium">{name}</span>: {t('health.probe.' + (known.includes(state) ? state : 'untested'))}
          <span class="block text-xs text-muted">{date(at)}</span></li>
      {/each}
    </ul>
    <p class="text-xs text-muted">{t('health.expiry', { days: st.home_max_age_days ?? 14 })}</p>
  </details>
</section>
