import path from 'path';
import fs from 'fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(() => {
  return {
    // Base path - served under /vault/ path
    base: '/vault/',
    server: {
      port: 3000,
      host: '0.0.0.0',
    },
    plugins: [
      react(),
      {
        name: 'serve-wallet-files',
        configureServer(server) {
          server.middlewares.use('/vault/wallet', (req, res, next) => {
            const url = req.url.split('?')[0];
            const filePath = path.join(__dirname, 'wallet', url);

            if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
              const ext = path.extname(filePath);
              const mimeTypes: Record<string, string> = {
                '.js': 'application/javascript',
                '.wasm': 'application/wasm',
                '.json': 'application/json'
              };

              res.setHeader('Content-Type', mimeTypes[ext] || 'application/octet-stream');
              res.end(fs.readFileSync(filePath));
              return;
            }
            next();
          });
        }
      }
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      }
    },
    build: {
      outDir: 'dist',
      assetsDir: 'assets',
      sourcemap: false,
      // Disable minification completely to avoid SES/MetaMask conflicts
      // The SES lockdown from MetaMask breaks minified React 19 code
      minify: false,
      target: 'es2020',
      rollupOptions: {
        output: {
          // Disable code splitting - put everything in one bundle
          // This avoids circular dependency issues with dynamic imports
          entryFileNames: 'assets/vault-[hash].js',
          chunkFileNames: 'assets/[name]-[hash].js',
          assetFileNames: 'assets/[name]-[hash][extname]',
          manualChunks: undefined,
          inlineDynamicImports: true,
          // Use ES module format (more compatible than IIFE with modern tooling)
          format: 'es'
        }
      }
    }
  };
});
