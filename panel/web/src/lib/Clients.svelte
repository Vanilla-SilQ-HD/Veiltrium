<script>
  import { api, AuthError } from './api.js';
  import { t } from './i18n.svelte.js';
  import { flash } from './toast.svelte.js';
  import Icon from './Icon.svelte';
  import Dialog from './Dialog.svelte';
  import Steps from './Steps.svelte';
  import StandbyWarning from './StandbyWarning.svelte';
  import ClientDetail from './ClientDetail.svelte';
  import StateBadge from './StateBadge.svelte';
  import LimitUsage from './LimitUsage.svelte';
  import { bytes, ago, dateText } from './format.js';

  let { onAuthLost, onChanged } = $props();
  let list = $state(null);
  let error = $state('');
  let selected = $state('main');
  let detail = $state(null);
  let detailError = $state('');

  // add / revoke dialogs
  let dialog = $state(null); // 'add' | 'remove' | 'reset' | 'limits' | 'disable' | 'enable' | null
  let name = $state('');
  let running = $state(false);
  let steps = $state([]);
  let finished = $state(false);
  let changeError = $state('');
  let notice = $state('');

  const fail = (err, set) => (err instanceof AuthError ? onAuthLost() : set(err.message));

  async function loadList() {
    try {
      list = await api.clients();
      error = '';
      onChanged?.(list);
    } catch (err) {
      fail(err, (m) => (error = m));
    }
  }
  async function loadDetail(n) {
    detail = null;
    detailError = '';
    try {
      const d = await api.client(n);
      if (selected === n) detail = d;
    } catch (err) {
      if (selected === n) fail(err, (m) => (detailError = m));
    }
  }
  loadList();
  $effect(() => {
    loadDetail(selected);
  });

  const valid = (n) => /^[a-z0-9][a-z0-9_-]{0,31}$/.test(n) && n !== 'main';
  let taken = $derived(!!list?.clients.some((c) => c.name === name));
  let canAdd = $derived(valid(name) && !taken);
  let nameHint = $derived(name && taken ? t('add.taken') : name && !valid(name) ? t('add.invalid') : t('add.rules'));

  const addOrder = ['write', 'restart', 'check-hysteria', 'check-reality', 'check-trusttunnel', 'commit'];
  let order = $derived(addOrder.filter((s) => (s !== 'check-reality' || detail?.vless !== null) && (s !== 'check-trusttunnel' || detail?.trusttunnel !== null)));

  function openAdd() {
    dialog = 'add'; name = ''; steps = []; finished = false; changeError = ''; notice = '';
  }
  function close() {
    if (!running) dialog = null;
  }
  async function add() {
    if (!canAdd || running) return;
    running = true; steps = []; changeError = '';
    try {
      const res = await api.addClient(name, (s) => (steps = [...steps, s]));
      finished = true;
      if (res.main_hysteria_link_changed) notice = t('add.mainChanged');
      await loadList();
      loadDetail(selected);
    } catch (err) {
      fail(err, (m) => (changeError = t('add.failed', { reason: m })));
      // the change may have finished on the server
      if (!(err instanceof AuthError)) { await loadList(); loadDetail(selected); }
    } finally {
      running = false;
    }
  }
  function showNew() {
    const n = name;
    dialog = null;
    selected = n;
  }
  async function reset() {
    if (running) return;
    const n = selected;
    running = true; steps = []; changeError = '';
    try {
      await api.resetClient(n, (s) => (steps = [...steps, s]));
      dialog = null;
      flash(t('reset.done', { name: n }));
      await loadList();
      loadDetail(n);
    } catch (err) {
      fail(err, (m) => (changeError = t('reset.failed', { reason: m })));
      // the change may have finished on the server
      if (!(err instanceof AuthError)) { await loadList(); loadDetail(selected); }
    } finally {
      running = false;
    }
  }
  // limits: size = number + unit (decimal, as the installer counts); empty = none
  const mults = { MB: 1e6, GB: 1e9, TB: 1e12 };
  const maxLimit = 1e15;
  let limVal = $state('');
  let limUnit = $state('GB');
  let expVal = $state('');
  let rstVal = $state('none');
  let limBytes = $derived.by(() => {
    const v = limVal.trim().replace(',', '.');
    if (v === '') return null;
    if (!/^\d+(\.\d+)?$/.test(v)) return NaN;
    const n = Math.round(parseFloat(v) * mults[limUnit]);
    return n >= 1 && n <= maxLimit ? n : NaN;
  });
  let limOk = $derived(!Number.isNaN(limBytes));
  let expOk = $derived(expVal === '' || /^\d{4}-\d{2}-\d{2}$/.test(expVal));
  let expPast = $derived(expOk && expVal !== '' && expVal < new Date().toISOString().slice(0, 10));
  function openLimits() {
    const d = detail;
    limVal = ''; limUnit = 'GB';
    if (d?.limit) {
      limUnit = d.limit >= 1e12 ? 'TB' : d.limit >= 1e9 ? 'GB' : 'MB';
      limVal = String(Number((d.limit / mults[limUnit]).toFixed(3)));
    }
    expVal = d?.expires ?? '';
    rstVal = d?.reset ?? 'none';
    dialog = 'limits'; steps = []; changeError = '';
  }
  // one change of limits or state: streams the progress, then reloads the list and the client
  async function changeLimits(run, okText, failText) {
    if (running) return;
    const n = selected;
    running = true; steps = []; changeError = '';
    try {
      await run(n, (s) => (steps = [...steps, s]));
      dialog = null;
      flash(t(okText, { name: n }));
      await loadList();
      loadDetail(n);
    } catch (err) {
      fail(err, (m) => (changeError = t(failText, { reason: m })));
      // the change may have finished on the server
      if (!(err instanceof AuthError)) { await loadList(); loadDetail(selected); }
    } finally {
      running = false;
    }
  }
  const saveLimits = () => limOk && expOk && changeLimits(
    (n, on) => api.setClientLimits(n, { limit: limBytes, expires: expVal || null, reset: rstVal }, on), 'lim.saved', 'lim.saveFailed');
  const disableClient = () => changeLimits((n, on) => api.disableClient(n, on), 'lim.disabledDone', 'lim.disableFailed');
  const enableClient = () => changeLimits((n, on) => api.enableClient(n, on), 'lim.enabledDone', 'lim.enableFailed');

  async function revoke() {
    if (running) return;
    const n = selected;
    running = true; steps = []; changeError = '';
    try {
      await api.removeClient(n, (s) => (steps = [...steps, s]));
      dialog = null;
      selected = 'main';
      flash(t('rm.done', { name: n }));
      await loadList();
    } catch (err) {
      fail(err, (m) => (changeError = t('rm.failed', { reason: m })));
      // the change may have finished on the server
      if (!(err instanceof AuthError)) { await loadList(); loadDetail(selected); }
    } finally {
      running = false;
    }
  }
</script>

<div class="flex flex-col gap-5">
  <div class="flex flex-wrap items-center justify-between gap-3">
    <div class="flex flex-col gap-0.5">
      <h1 class="m-0 text-[22px] font-semibold">{t('cl.title')}</h1>
      <span class="text-[13px] text-muted">{t('cl.subtitle')}</span>
    </div>
    <button type="button" onclick={openAdd} class="flex h-11 items-center gap-2 rounded-lg bg-accent px-4 font-semibold text-on-accent">
      <Icon name="plus" size={16} /><span>{t('cl.add')}</span>
    </button>
  </div>

  {#if error}<div role="alert" class="rounded-xl border border-danger-line p-4 text-danger">{error}</div>{/if}
  {#if list?.standby?.length}
    <p role="note" class="m-0 rounded-xl border border-line bg-warn-soft p-4 text-sm text-warn">{t('sb.changeWarning', { servers: list.standby.join(', ') })}</p>
  {/if}

  <div class="flex flex-wrap items-start gap-5">
    <div class="min-w-0 flex-[1_1_300px] overflow-hidden rounded-xl border border-line bg-surface">
      {#if !list}
        <p class="m-0 p-4 text-muted">{t('common.loading')}</p>
      {:else}
        {#each list.clients as c, i (c.name)}
          <button type="button" onclick={() => (selected = c.name)} aria-current={selected === c.name}
            class="flex min-h-14 w-full items-center gap-3 px-4 py-3.5 text-left text-fg
              {i ? 'border-t border-line' : ''} {selected === c.name ? 'bg-surface2' : ''}">
            <span class="flex h-8 w-8 items-center justify-center rounded-full bg-surface2 font-mono text-[13px] text-accent">
              {c.name.slice(0, 1).toUpperCase()}</span>
            <span class="flex min-w-0 flex-1 flex-col">
              <span class="font-medium">{c.name}</span>
              <span class="text-xs text-muted">{c.main ? t('cl.first') : t('cl.added', { date: c.created ?? '' })}</span>
              <span class="text-xs text-muted">
                {c.traffic ? t('cl.traffic', { total: bytes(c.traffic.up + c.traffic.down), seen: ago(c.traffic.last_seen) }) : t('cl.notCounted')}</span>
              {#if c.limit || c.expires}
                <span class="mt-1 flex flex-col gap-1">
                  <LimitUsage {c} />
                  {#if c.expires}<span class="text-xs text-muted">{t('lim.until', { date: dateText(c.expires) })}</span>{/if}
                </span>
              {/if}
            </span>
            <StateBadge {c} />
          </button>
        {/each}
      {/if}
    </div>

    {#if detail}
      <ClientDetail c={detail} onRevoke={() => { dialog = 'remove'; steps = []; changeError = ''; }}
        onReset={() => { dialog = 'reset'; steps = []; changeError = ''; }}
        onLimits={openLimits}
        onDisable={() => { dialog = 'disable'; steps = []; changeError = ''; }}
        onEnable={() => { dialog = 'enable'; steps = []; changeError = ''; }} />
    {:else if detailError}
      <div role="alert" class="flex-[2_1_460px] rounded-xl border border-danger-line p-4 text-danger">{detailError}</div>
    {:else}
      <p class="flex-[2_1_460px] text-muted">{t('common.loading')}</p>
    {/if}
  </div>
</div>

{#if dialog === 'add'}
  <Dialog label={t('add.title')} locked={running} onClose={close}>
    <span class="text-lg font-semibold">{t('add.title')}</span>
    {#if !running && !finished}
      <div class="flex flex-col gap-1.5">
        <label for="cname" class="text-[13px] font-medium">{t('add.name')}</label>
        <input id="cname" bind:value={name} placeholder={t('add.placeholder')} autocomplete="off" spellcheck="false"
          onkeydown={(e) => e.key === 'Enter' && add()}
          class="h-11 rounded-lg border bg-bg px-3 font-mono text-fg outline-none {name && !canAdd ? 'border-danger' : 'border-line focus:border-accent'}" />
        <span class="text-xs {name && !canAdd ? 'text-danger' : 'text-muted'}">{nameHint}</span>
      </div>
      <p class="m-0 rounded-lg bg-surface2 px-3 py-2.5 text-xs text-muted">{t('add.note')}</p>
      <StandbyWarning servers={list?.standby ?? []} />
      {#if changeError}<p role="alert" class="m-0 text-[13px] text-danger">{changeError}</p>{/if}
      <div class="flex justify-end gap-2">
        <button type="button" onclick={close} class="h-11 rounded-lg border border-line px-4 text-fg">{t('common.cancel')}</button>
        <button type="button" onclick={add} disabled={!canAdd} class="h-11 rounded-lg bg-accent px-4 font-semibold text-on-accent disabled:opacity-50">{t('add.button')}</button>
      </div>
    {:else}
      <Steps {order} seen={steps} done={finished} />
      {#if notice}<p class="m-0 rounded-lg bg-warn-soft px-3 py-2.5 text-[13px] text-warn">{notice}</p>{/if}
      {#if finished}
        <div class="flex justify-end">
          <button type="button" onclick={showNew} class="h-11 rounded-lg bg-accent px-4 font-semibold text-on-accent">{t('add.show')}</button>
        </div>
      {/if}
    {/if}
  </Dialog>
{/if}

{#if dialog === 'remove'}
  <Dialog label={t('rm.title', { name: selected })} locked={running} onClose={close}>
    <span class="text-lg font-semibold">{t('rm.title', { name: selected })}</span>
    {#if running}
      <Steps {order} seen={steps} />
    {:else}
      <p class="m-0 text-muted">{t('rm.text')}</p>
      <StandbyWarning servers={list?.standby ?? []} />
      {#if changeError}<p role="alert" class="m-0 text-[13px] text-danger">{changeError}</p>{/if}
      <div class="flex justify-end gap-2">
        <button type="button" onclick={close} class="h-11 rounded-lg border border-line px-4 text-fg">{t('common.cancel')}</button>
        <button type="button" onclick={revoke} class="h-11 rounded-lg bg-danger px-4 font-semibold text-white">{t('rm.button')}</button>
      </div>
    {/if}
  </Dialog>
{/if}

{#if dialog === 'reset'}
  <Dialog label={t('reset.title', { name: selected })} locked={running} onClose={close}>
    <span class="text-lg font-semibold">{t('reset.title', { name: selected })}</span>
    {#if running}
      <Steps {order} seen={steps} />
    {:else}
      <p class="m-0 text-muted">{t('reset.text', { name: selected })}</p>
      <StandbyWarning servers={list?.standby ?? []} />
      {#if changeError}<p role="alert" class="m-0 text-[13px] text-danger">{changeError}</p>{/if}
      <div class="flex justify-end gap-2">
        <button type="button" onclick={close} class="h-11 rounded-lg border border-line px-4 text-fg">{t('common.cancel')}</button>
        <button type="button" onclick={reset} class="h-11 rounded-lg bg-danger px-4 font-semibold text-white">{t('reset.button')}</button>
      </div>
    {/if}
  </Dialog>
{/if}

{#if dialog === 'limits'}
  <Dialog label={t('lim.editTitle', { name: selected })} locked={running} onClose={close}>
    <span class="text-lg font-semibold">{t('lim.editTitle', { name: selected })}</span>
    {#if running}
      <Steps {order} seen={steps} />
    {:else}
      <div class="flex flex-col gap-1.5">
        <label for="lim-val" class="text-[13px] font-medium">{t('lim.fieldLimit')}</label>
        <div class="flex gap-2">
          <input id="lim-val" bind:value={limVal} inputmode="decimal" placeholder={t('lim.unlimited')} autocomplete="off"
            class="h-11 min-w-0 flex-1 rounded-lg border bg-bg px-3 text-fg outline-none {limOk ? 'border-line focus:border-accent' : 'border-danger'}" />
          <select bind:value={limUnit} aria-label={t('lim.fieldUnit')} class="h-11 rounded-lg border border-line bg-bg px-2 text-fg">
            {#each Object.keys(mults) as u (u)}<option value={u}>{t('unit.' + u)}</option>{/each}
          </select>
        </div>
        <span class="text-xs {limOk ? 'text-muted' : 'text-danger'}">{limOk ? t('lim.fieldLimitHint') : t('lim.errLimit')}</span>
      </div>
      <div class="flex flex-col gap-1.5">
        <label for="lim-exp" class="text-[13px] font-medium">{t('lim.fieldExpiry')}</label>
        <input id="lim-exp" type="date" bind:value={expVal}
          class="h-11 rounded-lg border bg-bg px-3 text-fg outline-none {expOk ? 'border-line focus:border-accent' : 'border-danger'}" />
        <span class="text-xs {expPast ? 'text-warn' : 'text-muted'}">{expPast ? t('lim.pastWarn') : t('lim.fieldExpiryHint')}</span>
      </div>
      <div class="flex flex-col gap-1.5">
        <label for="lim-rst" class="text-[13px] font-medium">{t('lim.fieldReset')}</label>
        <select id="lim-rst" bind:value={rstVal} class="h-11 rounded-lg border border-line bg-bg px-3 text-fg">
          {#each ['none', 'daily', 'weekly', 'monthly'] as r (r)}<option value={r}>{t('lim.reset.' + r)}</option>{/each}
        </select>
        <span class="text-xs text-muted">{t('lim.fieldResetHint')}</span>
      </div>
      <p class="m-0 rounded-lg bg-surface2 px-3 py-2.5 text-xs text-muted">{t('lim.editNote')}</p>
      <StandbyWarning servers={list?.standby ?? []} />
      {#if changeError}<p role="alert" class="m-0 text-[13px] text-danger">{changeError}</p>{/if}
      <div class="flex justify-end gap-2">
        <button type="button" onclick={close} class="h-11 rounded-lg border border-line px-4 text-fg">{t('common.cancel')}</button>
        <button type="button" onclick={saveLimits} disabled={!limOk || !expOk}
          class="h-11 rounded-lg bg-accent px-4 font-semibold text-on-accent disabled:opacity-50">{t('lim.save')}</button>
      </div>
    {/if}
  </Dialog>
{/if}

{#if dialog === 'disable'}
  <Dialog label={t('lim.disableTitle', { name: selected })} locked={running} onClose={close}>
    <span class="text-lg font-semibold">{t('lim.disableTitle', { name: selected })}</span>
    {#if running}
      <Steps {order} seen={steps} />
    {:else}
      <p class="m-0 text-muted">{t('lim.disableText', { name: selected })}</p>
      <StandbyWarning servers={list?.standby ?? []} />
      {#if changeError}<p role="alert" class="m-0 text-[13px] text-danger">{changeError}</p>{/if}
      <div class="flex justify-end gap-2">
        <button type="button" onclick={close} class="h-11 rounded-lg border border-line px-4 text-fg">{t('common.cancel')}</button>
        <button type="button" onclick={disableClient} class="h-11 rounded-lg bg-danger px-4 font-semibold text-white">{t('lim.disable')}</button>
      </div>
    {/if}
  </Dialog>
{/if}

{#if dialog === 'enable'}
  <Dialog label={t('lim.enableTitle', { name: selected })} locked={running} onClose={close}>
    <span class="text-lg font-semibold">{t('lim.enableTitle', { name: selected })}</span>
    {#if running}
      <Steps {order} seen={steps} />
    {:else}
      <p class="m-0 text-muted">{t('lim.enableText', { name: selected })}</p>
      <StandbyWarning servers={list?.standby ?? []} />
      {#if changeError}<p role="alert" class="m-0 text-[13px] text-danger">{changeError}</p>{/if}
      <div class="flex justify-end gap-2">
        <button type="button" onclick={close} class="h-11 rounded-lg border border-line px-4 text-fg">{t('common.cancel')}</button>
        <button type="button" onclick={enableClient} class="h-11 rounded-lg bg-accent px-4 font-semibold text-on-accent">{t('lim.enable')}</button>
      </div>
    {/if}
  </Dialog>
{/if}
