<script>
  import { t } from './i18n.svelte.js';
  import { setupChoices, setupPayload } from './setup.js';
  import CopyField from './CopyField.svelte';
  import QR from './QR.svelte';

  let { c } = $props();
  let step = $state(1);
  let device = $state('android');
  let kind = $state('vless');
  let reveal = $state(false);
  let opened = $state(false);
  let transfer = $state(false);
  let done = $state(false);
  let choices = $derived(setupChoices(device, c));
  let chosen = $derived(choices.includes(kind) ? kind : choices[0]);
  let payload = $derived(setupPayload(chosen, c));
  function chooseDevice(value) {
    device = value; opened = false; transfer = false; done = false; reveal = false;
  }
  function chooseKind(value) {
    kind = value; opened = false; transfer = false; done = false; reveal = false;
  }
  function download() {
    const url = URL.createObjectURL(new Blob([payload], { type: 'application/json' }));
    Object.assign(document.createElement('a'), { href: url, download: `${c.node_name}-${c.name}-${chosen}.json` }).click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
</script>

<section aria-label={t('setup.title')} class="flex flex-col gap-4 rounded-xl border border-line bg-surface2 p-4">
  <div class="flex flex-wrap items-center justify-between gap-2">
    <h2 class="m-0 text-base font-semibold">{t('setup.title')}</h2>
    <span class="text-xs text-muted">{t('setup.progress', { step })}</span>
  </div>
  {#if c.state === 'disabled'}
    <p class="m-0 text-warn">{t('cl.imp.disabled')}</p>
  {:else}
    <ol class="m-0 grid list-none grid-cols-2 gap-2 p-0 text-xs sm:grid-cols-4" aria-label={t('setup.steps')}>
      {#each ['device', 'app', 'import', 'test'] as label, i}
        <li aria-current={step === i + 1 ? 'step' : undefined} class="rounded-lg border p-2 {step === i + 1 ? 'border-accent text-accent' : 'border-line text-muted'}">{i + 1}. {t('setup.' + label)}</li>
      {/each}
    </ol>
    {#if step === 1}
      <label for="setup-device" class="text-sm font-medium">{t('setup.devicePrompt')}</label>
      <select id="setup-device" value={device} onchange={(e) => chooseDevice(e.currentTarget.value)} class="h-11 rounded-lg border border-line bg-bg px-3 text-fg">
        {#each ['android', 'ios', 'windows', 'router'] as d}<option value={d}>{t('setup.device.' + d)}</option>{/each}
      </select>
    {:else if step === 2}
      <label for="setup-app" class="text-sm font-medium">{t('setup.appPrompt')}</label>
      <select id="setup-app" value={chosen} onchange={(e) => chooseKind(e.currentTarget.value)} class="h-11 rounded-lg border border-line bg-bg px-3 text-fg">
        {#each choices as k}<option value={k}>{t('setup.format.' + k)}</option>{/each}
      </select>
      <p class="m-0 text-sm text-muted">{t('setup.app.' + device)}</p>
      <p class="m-0 text-xs text-muted">{t('setup.reason.' + chosen)}</p>
    {:else if step === 3}
      <p class="m-0 text-sm">{t('setup.import.' + chosen)}</p>
      {#if chosen === 'singbox' || chosen === 'awg'}
        <button type="button" onclick={download} class="min-h-11 self-start rounded-lg bg-accent px-4 font-semibold text-on-accent">{t('setup.download')}</button>
      {/if}
      <button type="button" onclick={() => (reveal = !reveal)} class="min-h-10 self-start rounded-lg border border-line px-3">{reveal ? t('cl.hideSecrets') : t('setup.reveal')}</button>
      <CopyField title={t('setup.format.' + chosen)} hint={t('setup.secret')} value={payload} shown={reveal ? payload : '••••••••••••'} multiline={chosen === 'singbox' || chosen === 'awg'} />
      {#if reveal && !['singbox', 'awg'].includes(chosen)}<QR text={payload} label={t('cl.qr', { kind: chosen })} />{/if}
      <p class="m-0 text-xs text-muted">{t('setup.activate.' + device)}</p>
    {:else}
      <p class="m-0 text-sm">{t('setup.testIntro')}</p>
      <label class="flex items-start gap-3"><input type="checkbox" bind:checked={opened} onchange={() => (done = false)} class="mt-1" /><span>{t('setup.opened')}</span></label>
      <label class="flex items-start gap-3"><input type="checkbox" bind:checked={transfer} onchange={() => (done = false)} class="mt-1" /><span>{t('setup.transfer')}</span></label>
      <p class="m-0 text-xs text-muted">{t('setup.testNote')}</p>
      {#if done}<p role="status" class="m-0 rounded-lg bg-ok-soft p-3 text-ok">{t('setup.done')}</p>{/if}
      <details class="text-sm"><summary class="cursor-pointer text-accent">{t('setup.trouble')}</summary><p class="text-muted">{t('setup.troubleText')}</p></details>
    {/if}
    <div class="flex justify-between gap-3">
      <button type="button" onclick={() => { step--; done = false; }} disabled={step === 1} class="h-11 rounded-lg border border-line px-4 disabled:opacity-40">{t('setup.back')}</button>
      {#if step < 4}
        <button type="button" onclick={() => (step++)} disabled={!choices.length} class="h-11 rounded-lg bg-accent px-4 font-semibold text-on-accent disabled:opacity-40">{t('setup.next')}</button>
      {:else}
        <button type="button" onclick={() => (done = true)} disabled={!opened || !transfer || done} class="h-11 rounded-lg bg-accent px-4 font-semibold text-on-accent disabled:opacity-40">{t('setup.confirm')}</button>
      {/if}
    </div>
  {/if}
</section>
