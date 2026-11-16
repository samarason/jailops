import { defineConfig, devices } from '@playwright/test'
import { e2eConfig } from '../shared/vite.app.ts'

// The specs run against a demo build of the console (`?demo`), so no server is needed; the web server below makes
// it (JAILOPS_DEMO_BUILD=1, into .demo-dist) and serves it.
const { port, command } = e2eConfig('backup')
// E2E_BASE_URL runs the specs against a server that is already up (a dev server) instead of the built demo.
const base = process.env.E2E_BASE_URL
export default defineConfig({
  testDir: 'e2e',
  outputDir: 'e2e/.results',
  fullyParallel: true,
  workers: process.env.CI ? 4 : undefined, // a hosted runner has 4 cores; the default is half of them
  retries: 0,
  reporter: [['list']],
  use: { baseURL: base ?? `http://127.0.0.1:${port}`, testIdAttribute: 'data-test', trace: 'retain-on-failure' },
  webServer: base ? undefined : { command, url: `http://127.0.0.1:${port}`, reuseExistingServer: true },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 800 } } },
    { name: 'phone', use: { ...devices['Pixel 5'] } },
  ],
})
