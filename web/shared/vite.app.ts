// The one Vite configuration every console uses. An app's vite.config.ts is a single call:
//   export default appConfig('host', import.meta.dirname)
// Everything (output directory, dev proxy, port) comes from web/apps.json.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

interface AppEntry { dist: string; devPort: number; previewPort: number; proxy: { env: string; default: string } }

export function loadEntry(name: string): AppEntry & { repo: string } {
  const repo = resolve(import.meta.dirname, '..', '..')
  const reg = JSON.parse(readFileSync(join(repo, 'web', 'apps.json'), 'utf8')).apps as Record<string, AppEntry>
  if (!reg[name]) throw new Error(`app ${name} is not in web/apps.json`)
  return { ...reg[name], repo }
}

/** JAILOPS_DEMO_BUILD=1 builds the demo: it honours ?demo and goes to <app>/.demo-dist, never into a binary. */
export function isDemoBuild(): boolean {
  return process.env.JAILOPS_DEMO_BUILD === '1'
}

export function appConfig(name: string, appDir: string) {
  const e = loadEntry(name)
  const demo = isDemoBuild()
  const outDir = demo ? join(appDir, '.demo-dist') : join(e.repo, e.dist)
  const target = process.env[e.proxy.env] || e.proxy.default
  // emptyOutDir removes the tracked placeholder that keeps go:embed compiling before the first build.
  const keepPlaceholder = () => ({
    name: 'keep-gitkeep',
    closeBundle() {
      mkdirSync(outDir, { recursive: true })
      writeFileSync(join(outDir, '.gitkeep'), '')
    },
  })
  return defineConfig({
    root: appDir,
    plugins: demo ? [vue()] : [vue(), keepPlaceholder()],
    // the console a daemon embeds has no demo: ?demo cannot switch a production console to canned data
    define: { 'import.meta.env.VITE_JAILOPS_DEMO': JSON.stringify(demo ? '1' : '') },
    resolve: {
      alias: {
        '@jailops/shared': join(appDir, '..', 'shared', 'src'),
        '@': join(appDir, 'src'),
      },
    },
    server: {
      port: e.devPort,
      proxy: {
        '/api/v1': {
          target,
          secure: false, // a development server often has a self-signed certificate
          // The daemon rejects a state-changing request whose Origin host differs from its Host
          // (CSRF defence). The browser sends the dev server's origin, so rewrite it to the target.
          changeOrigin: true,
          configure: (proxy) => {
            proxy.on('proxyReq', (req) => {
              if (req.getHeader('origin')) req.setHeader('origin', target)
            })
          },
        },
      },
    },
    preview: { port: e.previewPort, strictPort: true },
    build: { outDir, emptyOutDir: true, target: 'es2022', assetsInlineLimit: 0, chunkSizeWarningLimit: 400 },
    // a loaded CI machine runs the demo server slowly: a test may take up to 30 s (the tests wait for a condition, not a fixed time)
    test: { name, environment: 'jsdom', include: ['src/**/*.test.ts'], testTimeout: 30000 },
  })
}

/** The end-to-end tests run against a demo build of the app, made and served by Playwright's web server. */
export function e2eConfig(name: string) {
  const port = loadEntry(name).previewPort
  return { port, command: `JAILOPS_DEMO_BUILD=1 npx vite build --logLevel warn && JAILOPS_DEMO_BUILD=1 npx vite preview --host 127.0.0.1` }
}
