<script>
  import { api, AuthError } from './api.js';
  import { t } from './i18n.js';
  import Icon from './Icon.svelte';

  let { onAuthLost } = $props();
  let st = $state(null);
  let error = $state('');
  let loading = $state(false);

  async function load() {
    loading = true;
    error = '';
    try {
      st = await api.status();
    } catch (err) {
      if (err instanceof AuthError) return onAuthLost();
      error = err.message;
    } finally {
      loading = false;
    }
  }
  load();

  const uptime = (s) => {
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
    return d > 0 ? `${d}d ${h}h` : `${h}h ${Math.floor((s % 3600) / 60)}m`;
  };
  const time = (iso) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  // home-network results: ok | fail | degraded | route_unverified | stale | untested
  const good = (v) => v === 'ok' || v === 'verified';

  let services = $derived(st ? Object.values(st.services) : []);
  // the last check from Russian networks (Globalping): reachable | partly | blocked | unchecked
  let ru = $derived(st?.russia ?? null);
  let ruState = $derived(!st ? '' : !st.globalping && !ru ? 'off' : (ru?.verdict ?? 'unchecked'));
  let ruTally = $derived.by(() => {
    if (!ru) return null;
    const parts = [ru.icmp, ru.tcp_reality, ru.tcp_trusttunnel].filter(Boolean);
    return { ok: parts.reduce((n, x) => n + x.ok, 0), total: parts.reduce((n, x) => n + x.total, 0) };
  });
  const ruLabel = { reachable: 'ov.ruReachable', partly: 'ov.ruPartly', blocked: 'ov.ruBlocked', unchecked: 'ov.ruUnchecked', off: 'ov.ruOff' };
  const ruColor = { reachable: 'text-ok', partly: 'text-warn', blocked: 'text-danger' };
  let checking = $state(false);
  async function checkRussia() {
    checking = true;
    try {
      await api.russiaCheck();
      await load();
    } catch (err) {
      if (err instanceof AuthError) return onAuthLost();
      error = err.message;
    } finally {
      checking = false;
    }
  }
  const day = (iso) => new Date(iso).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  let ports = $derived.by(() => {
    if (!st) return '';
    const p = st.protection.ssh_ports.map((x) => `SSH ${x}/TCP`);
    p.push(`${st.hysteria2.port}/UDP`);
    if (st.reality) p.push(`${st.reality.port}/TCP`);
    if (st.trusttunnel) p.push(`${st.trusttunnel.port}/TCP+UDP`);
    return p.join(', ');
  });
  let protocols = $derived(st ? [
    st.reality && { name: 'VLESS Reality', svc: st.services.xray, port: `${st.reality.port}/TCP`, sni: st.reality.sni,
      tls: t('ov.tlsReality'), version: `Xray ${st.versions.xray}`, check: st.last_install_check?.reality,
      home: t('ov.homeCheck', { state: st.reality.home_network }), homeOk: good(st.reality.home_network),
      homeKnown: st.reality.home_network !== 'untested' },
    { name: 'Hysteria 2', svc: st.services['hysteria-server'], port: `${st.hysteria2.port}/UDP`, sni: st.hysteria2.sni,
      tls: t('ov.tlsPinned'), version: st.versions.hysteria, check: st.last_install_check?.hysteria2,
      home: t('ov.homeCheck', { state: st.hysteria2.home_network }), homeOk: good(st.hysteria2.home_network),
      homeKnown: st.hysteria2.home_network !== 'untested' },
    st.trusttunnel && { name: 'TrustTunnel', svc: st.services.trusttunnel, port: `${st.trusttunnel.port}/TCP+UDP`,
      sni: st.trusttunnel.hostname, tls: t('ov.tlsLink'), version: st.versions.trusttunnel, check: st.last_install_check?.trusttunnel_h2,
      home: t('ov.homeCheckTT', { h2: st.trusttunnel.home_network_h2, h3: st.trusttunnel.home_network_h3 }),
      homeOk: good(st.trusttunnel.home_network_h2), homeKnown: st.trusttunnel.home_network_h2 !== 'untested' },
  ].filter(Boolean) : []);
</script>

<div class="flex flex-col gap-6">
  <div class="flex flex-wrap items-baseline justify-between gap-2">
    <h1 class="m-0 text-[22px] font-semibold">{t('ov.title')}</h1>
    <div class="flex items-center gap-3">
      {#if st}<span class="text-xs text-muted">{t('ov.checked', { time: time(st.generated_at), version: st.script_version })}</span>{/if}
      <button type="button" onclick={load} disabled={loading}
        class="flex h-9 items-center gap-2 rounded-lg border border-line px-3 text-fg disabled:opacity-60">
        <Icon name="refresh" size={15} /><span>{t('common.refresh')}</span>
      </button>
    </div>
  </div>

  {#if error}
    <div role="alert" class="rounded-xl border border-danger-line p-4 text-danger">{error}</div>
  {:else if !st}
    <p class="text-muted">{t('common.loading')}</p>
  {:else}
    <div class="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-3">
      <div class="flex flex-col gap-1 rounded-xl border border-line bg-surface p-4">
        <span class="text-xs text-muted">{t('ov.services')}</span>
        <span class="text-xl font-semibold">{t('ov.servicesValue', { n: services.filter((s) => s === 'active').length, total: services.length })}</span>
        <span class="text-xs text-muted">{t('ov.servicesNote')}</span>
      </div>
      <div class="flex flex-col gap-1 rounded-xl border border-line bg-surface p-4">
        <span class="text-xs text-muted">{t('ov.clients')}</span>
        <span class="text-xl font-semibold">{st.clients.added + 1}</span>
        <span class="text-xs text-muted">{t('ov.clientsNote', { n: st.clients.added })}</span>
      </div>
      <div class="flex flex-col gap-1 rounded-xl border border-line bg-surface p-4">
        <div class="flex items-center justify-between gap-2">
          <span class="text-xs text-muted">{t('ov.russia')}</span>
          {#if ruState !== 'off'}
            <button type="button" onclick={checkRussia} disabled={checking}
              class="rounded-md border border-line px-2 py-0.5 text-[11px] text-fg disabled:opacity-60">
              {checking ? t('ov.ruChecking') : t('ov.ruCheck')}</button>
          {/if}
        </div>
        <span class="text-xl font-semibold {ruColor[ruState] ?? ''}">{t(ruLabel[ruState] ?? 'ov.ruUnchecked')}</span>
        <span class="text-xs {ruState === 'blocked' ? 'text-danger' : 'text-muted'}" title={ru ? t('ov.ruNetworks', { networks: ru.networks.join(', ') }) : ''}>
          {#if ruState === 'blocked'}{t('ov.ruBlockedNote')}
          {:else if ruState === 'off'}{t('ov.ruOffNote')}
          {:else if ruTally && ruTally.total}{t('ov.ruNote', { ok: ruTally.ok, total: ruTally.total, when: day(ru.checked_at) })}
          {:else}{t('ov.ruNoteNone')}{/if}
        </span>
      </div>
      <div class="flex flex-col gap-1 rounded-xl border border-line bg-surface p-4">
        <span class="text-xs text-muted">{t('ov.system')}</span>
        <span class="text-xl font-semibold">{st.os || 'Linux'}</span>
        <span class="text-xs {st.reboot_required ? 'text-warn' : 'text-muted'}">
          {st.reboot_required ? t('ov.rebootPending') : t('ov.noReboot', { uptime: uptime(st.uptime_seconds) })}</span>
      </div>
    </div>

    <h2 class="m-0 mt-2 text-[15px] font-semibold">{t('ov.protocols')}</h2>
    <div class="grid grid-cols-[repeat(auto-fit,minmax(260px,1fr))] gap-3">
      {#each protocols as p (p.name)}
        <div class="flex flex-col gap-3.5 rounded-xl border border-line bg-surface p-[18px]">
          <div class="flex items-center justify-between gap-2">
            <span class="text-[15px] font-semibold">{p.name}</span>
            <span class="inline-flex items-center gap-1.5 text-xs {p.svc === 'active' ? 'text-ok' : 'text-danger'}">
              <span class="h-[7px] w-[7px] rounded-full {p.svc === 'active' ? 'bg-ok' : 'bg-danger'}"></span>{p.svc}</span>
          </div>
          <dl class="m-0 grid grid-cols-2 gap-x-3 gap-y-2.5 text-[13px]">
            <div><dt class="text-[11px] uppercase tracking-wider text-muted">{t('ov.port')}</dt><dd class="m-0 font-mono">{p.port}</dd></div>
            <div><dt class="text-[11px] uppercase tracking-wider text-muted">{t('ov.serverName')}</dt><dd class="m-0 font-mono break-all">{p.sni}</dd></div>
            <div><dt class="text-[11px] uppercase tracking-wider text-muted">{t('ov.tls')}</dt><dd class="m-0">{p.tls}</dd></div>
            <div><dt class="text-[11px] uppercase tracking-wider text-muted">{t('ov.version')}</dt><dd class="m-0 font-mono">{p.version}</dd></div>
          </dl>
          <div class="flex flex-wrap gap-2">
            {#if p.check}
              <span class="rounded-full px-2.5 py-0.5 text-xs {good(p.check) ? 'bg-ok-soft text-ok' : 'bg-warn-soft text-warn'}">
                {t('ov.serverCheck', { state: p.check })}</span>
            {/if}
            {#if p.homeKnown}
              <span class="rounded-full px-2.5 py-0.5 text-xs {p.homeOk ? 'bg-ok-soft text-ok' : 'bg-surface2 text-muted'}">{p.home}</span>
            {/if}
          </div>
        </div>
      {/each}
    </div>

    <h2 class="m-0 mt-2 text-[15px] font-semibold">{t('ov.protection')}</h2>
    <dl class="m-0 overflow-hidden rounded-xl border border-line bg-surface">
      {#each [
        ['ov.firewall', st.protection.firewall ? t('ov.firewallValue', { ports }) : t('ov.firewallMissing')],
        ['ov.scanners', t('ov.scannersValue', { n: st.protection.scanner_networks })],
        ['ov.ssh', t('ov.sshValue', { f2b: st.protection.fail2ban })],
        ['ov.proxies', t('ov.proxiesValue')],
        ['ov.updates', t('ov.updatesValue')],
      ] as [k, v], i (k)}
        <div class="flex flex-wrap gap-x-4 gap-y-1 px-4 py-3 {i ? 'border-t border-line' : ''}">
          <dt class="basis-44 text-muted">{t(k)}</dt>
          <dd class="m-0 flex-[1_1_280px]">{v}</dd>
        </div>
      {/each}
    </dl>
  {/if}
</div>
