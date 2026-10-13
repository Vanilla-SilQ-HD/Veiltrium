<script>
  // Stroke icons (lucide-style paths), decorative: the button around them carries the label.
  let { name, size = 18 } = $props();
  const paths = {
    overview: ['M3 3h7v9H3z', 'M14 3h7v5h-7z', 'M14 12h7v9h-7z', 'M3 16h7v5H3z'],
    clients: ['M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2', 'M9 3a4 4 0 1 1 0 8 4 4 0 0 1 0-8z', 'M22 21v-2a4 4 0 0 0-3-3.9', 'M16 3.1a4 4 0 0 1 0 7.8'],
    sun: ['M12 8a4 4 0 1 1 0 8 4 4 0 0 1 0-8z', 'M12 2v2', 'M12 20v2', 'M4.9 4.9l1.4 1.4', 'M17.7 17.7l1.4 1.4', 'M2 12h2', 'M20 12h2', 'M4.9 19.1l1.4-1.4', 'M17.7 6.3l1.4-1.4'],
    logout: ['M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4', 'M16 17l5-5-5-5', 'M21 12H9'],
    plus: ['M12 5v14', 'M5 12h14'],
    eye: ['M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z', 'M12 9a3 3 0 1 1 0 6 3 3 0 0 1 0-6z'],
    download: ['M12 3v12', 'M7 10l5 5 5-5', 'M4 21h16'],
    trash: ['M3 6h18', 'M8 6V4h8v2', 'M6 6l1 14h10l1-14'],
    copy: ['M11 9h10v12H9V11a2 2 0 0 1 2-2z', 'M5 15V5a2 2 0 0 1 2-2h10'],
    refresh: ['M21 12a9 9 0 1 1-3-6.7', 'M21 3v6h-6'],
    check: ['M5 12l5 5 9-10'],
  };
</script>

<svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
  stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
  {#each paths[name] ?? [] as d (d)}<path {d}></path>{/each}
</svg>
