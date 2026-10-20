<script>
  import qrcode from 'qrcode-generator';
  import { t } from './i18n.svelte.js';

  // An SVG QR code drawn in the browser: the secret never leaves the page.
  let { text, label } = $props();
  let qr = $derived.by(() => {
    try {
      const q = qrcode(0, 'L');
      q.addData(text, 'Byte');
      q.make();
      const n = q.getModuleCount();
      let d = '';
      for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (q.isDark(r, c)) d += `M${c} ${r}h1v1h-1z`;
      return { n, d };
    } catch {
      return null; // too long for a QR code
    }
  });
</script>

{#if qr}
  <svg role="img" aria-label={label} viewBox="-2 -2 {qr.n + 4} {qr.n + 4}" shape-rendering="crispEdges"
    class="h-[180px] w-[180px] rounded-lg bg-white">
    <path d={qr.d} fill="#111111"></path>
  </svg>
{:else}
  <div class="flex h-[180px] w-[180px] items-center justify-center rounded-lg border border-line p-3 text-center text-xs text-muted">
    {t('cl.qrTooLong')}
  </div>
{/if}
