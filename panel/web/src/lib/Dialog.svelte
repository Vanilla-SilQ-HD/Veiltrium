<script>
  // A modal: Escape and the backdrop close it (unless locked while a change runs).
  let { label, locked = false, onClose, children } = $props();
  let box;
  $effect(() => {
    box?.querySelector('input, button')?.focus();
  });
  function key(e) {
    if (e.key === 'Escape' && !locked) onClose();
  }
</script>

<svelte:window onkeydown={key} />
<div class="fixed inset-0 z-10 flex items-center justify-center bg-black/60 p-4"
  role="presentation" onclick={(e) => { if (e.target === e.currentTarget && !locked) onClose(); }}>
  <div bind:this={box} role="dialog" aria-modal="true" aria-label={label}
    class="flex w-full max-w-md flex-col gap-4 rounded-2xl border border-line bg-surface p-6 text-fg">
    {@render children()}
  </div>
</div>
