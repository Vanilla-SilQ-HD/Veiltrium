<script>
  import Icon from './Icon.svelte';
  import QR from './QR.svelte';
  import CopyField from './CopyField.svelte';
  import { t } from './i18n.js';
  import { flash } from './toast.svelte.js';

  let { c, onRevoke } = $props(); // c: a veiltrium-client/1 document
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
  let qrTabs = $derived(links.filter((l) => l.kind !== 'awg'));
  let qrLink = $derived(qrTabs.find((l) => l.kind === qrKind) ?? qrTabs[0]);

  function download() {
    const lines = [`Veiltrium connection details: node ${c.node_name}, client ${c.name}`,
      'Keep this secret: the links and configs contain passwords and keys.', ''];
    for (const l of links) lines.push(`${l.title}:`, l.value, '');
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
        <button type="button" onclick={onRevoke} class="flex h-10 items-center gap-2 rounded-lg border border-danger-line px-3 text-danger">
          <Icon name="trash" size={16} /><span>{t('cl.revoke')}</span>
        </button>
      {/if}
    </div>
  </div>

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
        {#each qrTabs as l (l.kind)}
          <button type="button" onclick={() => (qrKind = l.kind)} aria-pressed={qrLink.kind === l.kind}
            class="h-8 rounded-md border px-2.5 text-xs {qrLink.kind === l.kind ? 'border-line bg-surface2 text-fg' : 'border-transparent text-muted'}">
            {l.kind === 'hy2' ? 'HY2' : l.kind === 'vless' ? 'VLESS' : 'TT'}
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
  <span class="text-xs text-muted">{t('cl.awgNote')}</span>
</section>
