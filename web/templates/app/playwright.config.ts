import { defineConfig, devices } from '@playwright/test'
import { e2eConfig } from '../shared/vite.app.ts'

// The specs run against a demo build of the console (`?demo`), so no server is needed; the web server below makes
// it (JAILOPS_DEMO_BUILD=1, into .demo-dist) and serves it.
const { port, command } = e2eConfig('__APP__')
export default defineConfig({
  testDir: 'e2e',
  outputDir: 'e2e/.results',
  fullyParallel: true,
  retries: 0,
  reporter: [['list']],
  use: { baseURL: `http://127.0.0.1:${port}`, testIdAttribute: 'data-test', trace: 'retain-on-failure' },
  webServer: { command, url: `http://127.0.0.1:${port}`, reuseExistingServer: true },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 800 } } },
    { name: 'phone', use: { ...devices['Pixel 5'] } },
  ],
})
