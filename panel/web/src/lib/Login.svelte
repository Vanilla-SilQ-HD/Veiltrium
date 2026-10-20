<script>
  import { api } from './api.js';
  import { t } from './i18n.svelte.js';
  import Logo from './Logo.svelte';

  let { onSignedIn } = $props();
  let password = $state('');
  let busy = $state(false);
  let error = $state('');

  async function submit(e) {
    e.preventDefault();
    if (!password || busy) return;
    busy = true;
    error = '';
    try {
      await api.login(password);
      password = '';
      onSignedIn();
    } catch (err) {
      error = err.message;
    } finally {
      busy = false;
    }
  }
</script>

<div class="flex min-h-screen items-center justify-center p-6">
  <form onsubmit={submit} class="flex w-full max-w-sm flex-col gap-5 rounded-2xl border border-line bg-surface p-8">
    <div class="flex items-center gap-3">
      <Logo big />
      <span class="text-lg font-semibold">{t('app.name')}</span>
    </div>
    <div class="flex flex-col gap-2">
      <label for="pw" class="text-[13px] font-medium">{t('login.title')}</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input id="pw" type="password" autocomplete="current-password" autofocus bind:value={password}
        class="h-11 rounded-lg border border-line bg-bg px-3 text-fg outline-none focus:border-accent" />
      <span class="text-xs text-muted">{t('login.hint')}</span>
    </div>
    {#if error}<p role="alert" class="m-0 text-[13px] text-danger">{error}</p>{/if}
    <button type="submit" disabled={busy || !password}
      class="h-11 rounded-lg bg-accent font-semibold text-on-accent disabled:opacity-60">
      {busy ? t('login.busy') : t('login.button')}
    </button>
    <span class="text-xs text-muted">{t('login.note')}</span>
  </form>
</div>
