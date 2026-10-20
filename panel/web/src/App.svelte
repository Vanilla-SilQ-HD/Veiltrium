<script>
  import { api } from './lib/api.js';
  import { t, lang, setLanguage } from './lib/i18n.svelte.js';
  import { toast } from './lib/toast.svelte.js';
  import Icon from './lib/Icon.svelte';
  import Logo from './lib/Logo.svelte';
  import Login from './lib/Login.svelte';
  import Overview from './lib/Overview.svelte';
  import Clients from './lib/Clients.svelte';

  let signedIn = $state(null); // null: still checking the session
  let page = $state(location.hash === '#clients' ? 'clients' : 'overview');
  let node = $state(null);

  function stored(key, fallback) {
    try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; }
  }
  let theme = $state(stored('vt-theme', matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'));
  $effect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('vt-theme', theme); } catch { /* private window */ }
  });
  $effect(() => {
    history.replaceState(null, '', page === 'clients' ? '#clients' : '#');
  });

  async function check() {
    try {
      await api.session();
      signedIn = true;
      node = await api.clients().catch(() => null);
    } catch {
      signedIn = false;
    }
  }
  check();

  function lost() {
    signedIn = false;
  }
  async function signOut() {
    await api.logout().catch(() => {});
    signedIn = false;
  }
  const navItems = [
    { id: 'overview', icon: 'overview', label: 'nav.overview' },
    { id: 'clients', icon: 'clients', label: 'nav.clients' },
  ];
</script>

{#if signedIn === false}
  <Login onSignedIn={check} />
{:else if signedIn}
  <div class="flex min-h-screen flex-col">
    <header class="flex flex-wrap items-center justify-between gap-3 border-b border-line bg-surface px-6 py-3.5">
      <div class="flex flex-wrap items-center gap-3">
        <Logo />
        <span class="text-base font-semibold">{t('app.name')}</span>
        {#if node}
          <span class="inline-flex items-center gap-2 rounded-full border border-line bg-surface2 px-2.5 py-1 text-xs">
            <span class="h-[7px] w-[7px] rounded-full bg-ok"></span>
            <span>{node.node_name}</span>
            <span class="font-mono text-muted">{node.server}</span>
          </span>
        {/if}
      </div>
      <div class="flex items-center gap-2">
        <button type="button" onclick={() => (theme = theme === 'dark' ? 'light' : 'dark')} aria-label={t('top.theme')}
          class="flex h-10 w-10 items-center justify-center rounded-lg border border-line text-fg"><Icon name="sun" /></button>
        <button type="button" onclick={() => setLanguage(lang() === 'ru' ? 'en' : 'ru')} aria-label={t('top.lang')}
          class="flex h-10 w-10 items-center justify-center rounded-lg border border-line text-xs font-semibold text-fg">{lang() === 'ru' ? 'EN' : 'RU'}</button>
        <button type="button" onclick={signOut} class="flex h-10 items-center gap-2 rounded-lg border border-line px-3.5 text-fg">
          <Icon name="logout" size={16} /><span>{t('top.signout')}</span>
        </button>
      </div>
    </header>

    <div class="flex flex-1 flex-wrap items-stretch">
      <nav aria-label={t('nav.sections')} class="flex max-w-full flex-[1_1_200px] flex-col gap-1 border-line px-4 py-5 sm:max-w-60 sm:border-r">
        {#each navItems as n (n.id)}
          <button type="button" onclick={() => (page = n.id)} aria-current={page === n.id ? 'page' : undefined}
            class="flex h-11 items-center gap-2.5 rounded-lg px-3 text-left font-medium {page === n.id ? 'bg-surface2 text-fg' : 'text-muted'}">
            <Icon name={n.icon} /><span class="flex-1">{t(n.label)}</span>
            {#if n.id === 'clients' && node}
              <span class="rounded-full bg-surface2 px-2 text-xs text-muted">{node.clients.length}</span>
            {/if}
          </button>
        {/each}
        <p class="mt-4 rounded-lg border border-dashed border-line p-3 text-xs text-muted">{t('nav.later')}</p>
      </nav>
      <main class="flex min-w-0 flex-[999_1_560px] flex-col gap-6 px-8 py-7">
        {#if page === 'overview'}
          <Overview onAuthLost={lost} />
        {:else}
          <Clients onAuthLost={lost} onChanged={(l) => (node = l)} />
        {/if}
      </main>
    </div>
  </div>
{/if}

{#if toast.text}
  <div role="status" class="fixed bottom-6 left-1/2 -translate-x-1/2 rounded-lg bg-fg px-4 py-2.5 text-[13px] text-bg">{toast.text}</div>
{/if}
