<script>
  import Icon from './Icon.svelte';
  import QR from './QR.svelte';
  import CopyField from './CopyField.svelte';
  import { t } from './i18n.svelte.js';
  import { flash } from './toast.svelte.js';
  import StateBadge from './StateBadge.svelte';
  import LimitUsage from './LimitUsage.svelte';
  import DeviceSetup from './DeviceSetup.svelte';
  import { bytes, bytesDec, ago, dateText } from './format.js';

  let { c, onRevoke, onReset, onLimits, onDisable, onEnable } = $props(); // c: a veiltrium-client/1 document
  let reveal = $state(false);
  let qrKind = $state('vless');

  const dots = '•'.repeat(12);
  // Shown text: the secrets stay hidden until asked; copying always copies the real value.
  function mask(kind, s) {
    if (reveal || !s) return s;
    if (kind === 'hy2') return s.replace(/^(hysteria2:\/\/)[^@]+@/, (_, p) => p + (c.hysteria2.auth.includes(':') ? c.hysteria2.auth.split(':')[0] + ':' : '') + dots + '@');
    if (kind === 'vless') return s.replace(/^(vless:\/\/)[^@]+@/, `$1${dots}@`).replace(/(pbk=)[^&]+/, `$1${dots}`).replace(/(sid=)[^&]+/, `$1${dots}`);
    if (kind === 'tt') return 'tt://?' + dots;
    if (kind === 'awg') return s.replace(/("password": ")[^"]+"/, `$1${dots}"`);
    return s;
  }

  let awg = $derived(JSON.stringify(c.hysteria2.awg_group, null, 2));
  let links = $derived([
    { kind: 'hy2', title: t('cl.hy2'), hint: t('cl.hy2Hint'), value: c.hysteria2.link },
    c.vless && { kind: 'vless', title: t('cl.vless'), hint: t('cl.vlessHint'), value: c.vless.link },
    c.trusttunnel && { kind: 'tt', title: t('cl.tt'), hint: t('cl.ttHint'), value: c.trusttunnel.link },
    { kind: 'awg', title: t('cl.awg'), hint: t('cl.awgHint'), value: awg, multiline: true },
  ].filter(Boolean));
  // the same accounts on the standby servers (when any are set)
  let standby = $derived([
    ...(c.hysteria2.standby_links ?? []).map((v, i) => ({ kind: 'hy2', n: i + 1, title: t('cl.standbyLink', { title: t('cl.hy2'), n: i + 1 }), value: v })),
    ...(c.vless?.standby_links ?? []).map((v, i) => ({ kind: 'vless', n: i + 1, title: t('cl.standbyLink', { title: t('cl.vless'), n: i + 1 }), value: v })),
    ...(c.trusttunnel?.standby_links ?? []).map((v, i) => ({ kind: 'tt', n: i + 1, title: t('cl.standbyLink', { title: t('cl.tt'), n: i + 1 }), value: v })),
  ].map((l) => ({ ...l, id: l.kind + '-s' + l.n })));
  let qrTabs = $derived([...links.filter((l) => l.kind !== 'awg'), ...standby]);
  const tabName = (l) => (l.kind === 'hy2' ? 'HY2' : l.kind === 'vless' ? 'VLESS' : 'TT') + (l.n ? ' S' + l.n : '');
  const tabId = (l) => l.id ?? l.kind;
  let traffic = $derived(c.traffic);
  let qrLink = $derived(qrTabs.find((l) => tabId(l) === qrKind) ?? qrTabs[0]);

  let profileText = $derived(c.singbox_profile ? JSON.stringify(c.singbox_profile, null, 2) : '');
  function downloadProfile() {
    const file = `${c.node_name}-${c.name}.singbox.json`;
    const url = URL.createObjectURL(new Blob([profileText], { type: 'application/json' }));
    const a = Object.assign(document.createElement('a'), { href: url, download: file });
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    flash(t('cl.downloaded', { file }));
  }
  let profileManual = $state(false);
  $effect(() => { void profileText; void reveal; profileManual = false; });
  async function copyProfile() {
    try {
      await navigator.clipboard.writeText(profileText);
      profileManual = false;
      flash(t('common.copied', { what: t('cl.imp.profileCopy') }));
    } catch {
      profileManual = true;
    }
  }

  const proto = (k) => {
    const p = traffic?.by_protocol?.[k];
    return p ? bytes(p.up + p.down) : '-';
  };

  function download() {
    const lines = [`Veiltrium connection details: node ${c.node_name}, client ${c.name}`,
      'Keep this secret: the links and configs contain passwords and keys.', ''];
    for (const l of links) lines.push(`${l.title}:`, l.value, '');
    if (standby.length) {
      lines.push(`Standby servers (${(c.standby ?? []).join(', ')}):`);
      for (const l of standby) lines.push(`${l.title}:`, l.value, '');
    }
    lines.push('sing-box outbound (Hysteria 2):', JSON.stringify(c.hysteria2.outbound, null, 2), '');
    if (c.vless) lines.push('sing-box outbound (VLESS Reality):', JSON.stringify(c.vless.outbound, null, 2), '');
    const file = `${c.node_name}-${c.name}.txt`;
    const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/plain' }));
    const a = Object.assign(document.createElement('a'), { href: url, download: file });
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    flash(t('cl.downloaded', { file }));
  }
</script>

<section aria-label={c.name} class="flex min-w-0 flex-[2_1_460px] flex-col gap-[18px] rounded-xl border border-line bg-surface p-5">
  <div class="flex flex-wrap items-center justify-between gap-3">
    <div class="flex flex-col">
      <span class="text-lg font-semibold">{c.name}</span>
      <span class="text-xs text-muted">{c.main ? t('cl.first') : t('cl.added', { date: c.created ?? '' })} · {t('cl.shownAs', { label: c.node_name })}</span>
    </div>
    <div class="flex flex-wrap gap-2">
      <button type="button" onclick={() => (reveal = !reveal)} class="flex h-10 items-center gap-2 rounded-lg border border-line px-3 text-fg">
        <Icon name="eye" size={16} /><span>{reveal ? t('cl.hideSecrets') : t('cl.showSecrets')}</span>
      </button>
      <button type="button" onclick={download} class="flex h-10 items-center gap-2 rounded-lg border border-line px-3 text-fg">
        <Icon name="download" size={16} /><span>{t('cl.download')}</span>
      </button>
      {#if !c.main}
        <button type="button" onclick={onLimits} class="flex h-10 items-center gap-2 rounded-lg border border-line px-3 text-fg">
          <Icon name="gauge" size={16} /><span>{t('lim.edit')}</span>
        </button>
        {#if c.state === 'disabled'}
          <button type="button" onclick={onEnable} class="flex h-10 items-center gap-2 rounded-lg border border-line px-3 text-fg">
            <Icon name="play" size={16} /><span>{t('lim.enable')}</span>
          </button>
        {:else}
          <button type="button" onclick={onDisable} class="flex h-10 items-center gap-2 rounded-lg border border-line px-3 text-fg">
            <Icon name="pause" size={16} /><span>{t('lim.disable')}</span>
          </button>
        {/if}
        <button type="button" onclick={onReset} class="flex h-10 items-center gap-2 rounded-lg border border-line px-3 text-fg">
          <Icon name="refresh" size={16} /><span>{t('cl.reset')}</span>
        </button>
        <button type="button" onclick={onRevoke} class="flex h-10 items-center gap-2 rounded-lg border border-danger-line px-3 text-danger">
          <Icon name="trash" size={16} /><span>{t('cl.revoke')}</span>
        </button>
      {/if}
    </div>
  </div>

  {#if !c.main}
    <div class="flex flex-col gap-2 text-[13px]">
      <div class="flex items-center gap-2">
        <span class="text-[11px] uppercase tracking-wider text-muted">{t('lim.title')}</span>
        <StateBadge {c} />
      </div>
      {#if c.state === 'disabled'}
        <span class="text-xs text-warn">{t('lim.why.' + (['quota', 'expired'].includes(c.reason) ? c.reason : 'manual'))}</span>
      {/if}
      {#if !c.limit && !c.expires && c.reset === 'none'}
        <span class="text-muted">{t('lim.noLimits')}</span>
      {:else}
        <div class="flex flex-wrap gap-x-8 gap-y-2">
          <span class="flex flex-col"><span class="text-xs text-muted">{t('lim.fieldLimit')}</span>
            <span>{c.limit ? bytesDec(c.limit) : t('lim.unlimited')}</span></span>
          <span class="flex flex-col"><span class="text-xs text-muted">{t('lim.fieldExpiry')}</span>
            <span>{c.expires ? dateText(c.expires) : t('lim.never')}</span></span>
          <span class="flex flex-col"><span class="text-xs text-muted">{t('lim.fieldReset')}</span>
            <span>{t('lim.reset.' + (c.reset ?? 'none'))}</span></span>
        </div>
        {#if c.period_bytes !== null && c.period_bytes !== undefined}
          <div class="flex max-w-sm flex-col gap-1">
            <span class="text-xs text-muted">{c.period_start ? t('lim.periodSince', { used: bytesDec(c.period_bytes), date: dateText(c.period_start) }) : t('lim.periodUsed', { used: bytesDec(c.period_bytes) })}</span>
            <LimitUsage {c} />
          </div>
        {/if}
      {/if}
    </div>
  {/if}

  <div class="flex flex-col gap-0.5 text-[13px]">
    <span class="text-[11px] uppercase tracking-wider text-muted">{t('cl.usage')}</span>
    {#if traffic}
      <span>{t('cl.down', { n: bytes(traffic.down) })} · {t('cl.up', { n: bytes(traffic.up) })} · {t('cl.lastSeen', { when: ago(traffic.last_seen) })}</span>
      {#if traffic.by_protocol && Object.keys(traffic.by_protocol).length}
        <span class="text-xs text-muted">{t('cl.byProtocol', { hy: proto('hysteria2'), vl: proto('vless'), tt: proto('trusttunnel') })}</span>
      {/if}
    {:else}
      <span class="text-muted">{t('cl.notCounted')}</span>
    {/if}
  </div>

  {#key c.name + c.hysteria2.link + (c.vless?.link ?? '') + c.state}
    <DeviceSetup {c} bind:reveal />
  {/key}

  <details>
    <summary class="cursor-pointer py-2 text-sm font-medium text-accent">{t('setup.advanced')}</summary>
  <div class="flex flex-wrap gap-5">
    <div class="flex flex-col items-center gap-2">
      {#if reveal}
        <QR text={qrLink.value} label={t('cl.qr', { kind: qrLink.title })} />
      {:else}
        <button type="button" onclick={() => (reveal = true)}
          class="flex h-[180px] w-[180px] items-center justify-center rounded-lg border border-dashed border-line p-4 text-center text-xs text-muted">
          {t('cl.showSecrets')}
        </button>
      {/if}
      <div class="flex gap-1" role="group" aria-label={t('cl.qr', { kind: '' })}>
        {#each qrTabs as l (tabId(l))}
          <button type="button" onclick={() => (qrKind = tabId(l))} aria-pressed={tabId(qrLink) === tabId(l)}
            class="h-8 rounded-md border px-2.5 text-xs {tabId(qrLink) === tabId(l) ? 'border-line bg-surface2 text-fg' : 'border-transparent text-muted'}">
            {tabName(l)}
          </button>
        {/each}
      </div>
    </div>
    <div class="flex min-w-0 flex-[1_1_280px] flex-col gap-3">
      {#each links as l (l.kind)}
        <CopyField title={l.title} hint={l.hint} value={l.value} shown={mask(l.kind, l.value)} multiline={l.multiline} />
      {/each}
    </div>
  </div>
  {#if standby.length}
    <div class="flex flex-col gap-3 border-t border-line pt-4">
      <span class="text-[15px] font-semibold">{t('cl.standby')}</span>
      <span class="text-xs text-muted">{t('cl.standbyHint', { servers: (c.standby ?? []).join(', ') })}</span>
      {#each standby as l (l.id)}
        <CopyField title={l.title} hint="" value={l.value} shown={mask(l.kind, l.value)} />
      {/each}
    </div>
  {/if}
  <div class="flex flex-col gap-3 border-t border-line pt-4">
    <span class="text-[15px] font-semibold">{t('cl.imp.title')}</span>
    {#if c.subscription_base64 || c.singbox_profile}
      {#if c.subscription_base64}
        <div class="flex flex-wrap gap-5">
          <div class="flex min-w-0 flex-[1_1_280px] flex-col gap-2">
            <CopyField title={t('cl.imp.sub')} hint="" value={c.subscription_base64}
              shown={reveal ? c.subscription_base64 : dots} />
            <span class="text-xs text-muted">{t('cl.imp.subHint')}</span>
          </div>
          {#if reveal}
            <QR text={c.subscription_base64} label={t('cl.imp.subQr')} />
          {/if}
        </div>
      {/if}
      {#if c.singbox_profile}
        <div class="flex flex-col gap-2">
          <span class="text-xs font-medium">{t('cl.imp.profile')}</span>
          <div class="flex flex-wrap gap-2">
            <button type="button" onclick={copyProfile} class="flex h-10 items-center gap-2 rounded-lg border border-line px-3 text-fg">
              <Icon name="copy" size={16} /><span>{t('common.copy', { what: t('cl.imp.profileCopy') })}</span>
            </button>
            <button type="button" onclick={downloadProfile} class="flex h-10 items-center gap-2 rounded-lg border border-line px-3 text-fg">
              <Icon name="download" size={16} /><span>{t('cl.imp.profileDownload')}</span>
            </button>
          </div>
          {#if profileManual}
            <label class="flex flex-col gap-1 text-xs text-muted">{t('common.copyManual')}
              <textarea readonly value={profileText} onfocus={(e) => e.currentTarget.select()} rows="6" class="w-full rounded-lg border border-line bg-bg p-2 font-mono text-xs text-fg"></textarea>
            </label>
          {/if}
          <span class="text-xs text-muted">{t('cl.imp.profileHint')}</span>
        </div>
      {/if}
      <div class="flex flex-col gap-1">
        <span class="text-xs font-medium">{t('cl.imp.hints')}</span>
        <ul class="flex list-disc flex-col gap-1 pl-5 text-xs text-muted">
          {#each [1, 2, 3, 4, 5] as n (n)}<li>{t('cl.imp.h' + n)}</li>{/each}
        </ul>
      </div>
    {:else}
      <span class="text-xs text-muted">{t('cl.imp.disabled')}</span>
    {/if}
  </div>
  <span class="text-xs text-muted">{t('cl.awgNote')}</span>
  </details>
</section>
