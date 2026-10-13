import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [svelte(), tailwindcss()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsInlineLimit: 0, // no data: URLs: everything is a file under the strict CSP
    sourcemap: false,
  },
  server: {
    // npm run dev: the API of a panel reached through an SSH tunnel on localhost:2096
    proxy: { '/api': 'http://localhost:2096' },
  },
});
