import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // REACT_APP_API_URL keeps its Create React App name, so the compose files and launchers that set
  // it don't change (apiBase.js)
  envPrefix: ['VITE_', 'REACT_APP_'],
  // The app's own entry only: public/architecture's static pages bring their own three.js
  optimizeDeps: { entries: ['index.html'] },
  build: {
    // Where the Dockerfiles copy it from
    outDir: 'build',
  },
  server: {
    host: '0.0.0.0',
    port: 3000,
    strictPort: true,
    proxy: {
      '/api': { target: 'http://backend:5688', changeOrigin: true, ws: true },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
  },
});
