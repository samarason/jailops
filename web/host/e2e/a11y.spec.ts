import { test, expect } from '@playwright/test'
import { audit } from '../../shared/a11y'
import { DEMO_SETUP_TOKEN } from '../src/demo/setupToken'

const routes = ['/', '/doctor', '/jails', '/jails/web', '/jails/mail', '/projects', '/projects/shop', '/storage', '/profiles', '/updates', '/images', '/apps', '/apps?tab=installed', '/apps/nginx', '/apps/postgresql', '/apps/isms', '/apps/nsd', '/apps/mail', '/apps/memcached', '/apps/wiki', '/jails/web?tab=logs', '/jails/build?tab=logs', '/networks', '/firewall', '/backups', '/hosts', '/operations', '/events', '/audit', '/access', '/host', '/networks/wireguard', '/jails/db?tab=access', '/jails/web?tab=access', '/logs', '/logs?jail=db&app_logs=true', '/logs?tab=forwarding', '/jails/vault', '/volumes', '/volumes/pgdata', '/volumes/secrets',
  '/jails/web?tab=config', '/firewall?tab=sets', '/firewall?tab=test', '/firewall?tab=test&from=jail:web&to=jail:db&port=5432', '/firewall?tab=test&from=jail:web&to=jail:db&port=5433', '/firewall?tab=test&from=192.0.2.66&to=@web&port=80', '/firewall?tab=test&from=jail:web&to=jail:mail&port=26', '/backups?tab=policies', '/profiles?tab=host', '/access?tab=sessions', '/access?tab=trust', '/access?tab=tokens', '/nope']

for (const scheme of ['light', 'dark'] as const) {
  test.describe(`a11y ${scheme}`, () => {
    test.use({ colorScheme: scheme })
    for (const r of routes) {
      test(`${r}: names, labels, ids, landmarks and AA contrast`, async ({ page }) => {
        await page.goto('/?demo')
        await page.waitForSelector('.shell')
        if (r !== '/') await page.evaluate((p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')) }, r)
        await page.waitForLoadState('networkidle')
        await expect(page.locator('main h1').first()).toBeVisible()
        expect(await audit(page)).toEqual([])
      })
    }
  })
}

// The banner of a change that waits for its confirmation (the demo starts with one: `?demo=pending`).
for (const scheme of ['light', 'dark'] as const) {
  test(`a11y ${scheme}: /host with a pending change`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto('/?demo=pending')
    await page.waitForSelector('.shell')
    await page.evaluate(() => { history.pushState({}, '', '/host'); dispatchEvent(new PopStateEvent('popstate')) })
    await page.waitForLoadState('networkidle')
    await expect(page.getByTestId('pending-banner')).toBeVisible()
    expect(await audit(page)).toEqual([])
  })
}

// The first-run wizard of a host without an administrator (`?demo=setup`).
for (const scheme of ['light', 'dark'] as const) {
  test(`a11y ${scheme}: /setup`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto('/?demo=setup')
    await expect(page.getByTestId('setup-step')).toBeVisible()
    expect(await audit(page)).toEqual([])
  })
}

// A host without an image (`?demo=empty`): the empty Images page and the Create image dialog with its build running.
for (const scheme of ['light', 'dark'] as const) {
  test(`a11y ${scheme}: /images without an image, and the build`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto('/?demo=empty')
    await page.waitForSelector('.shell')
    await page.evaluate(() => { history.pushState({}, '', '/images'); dispatchEvent(new PopStateEvent('popstate')) })
    await expect(page.getByTestId('images-empty')).toBeVisible()
    expect(await audit(page)).toEqual([])
    await page.getByTestId('image-new-empty').click()
    await page.getByTestId('image-create-go').click()
    await expect(page.getByTestId('image-progress')).toBeVisible()
    expect(await audit(page)).toEqual([])
  })
}

// The Images page with a failed night (`?demo=nightlyfail`), and a host on a new release (`?demo=newrelease`) with its
// notice and the Create image dialog it opens.
for (const scheme of ['light', 'dark'] as const) {
  test(`a11y ${scheme}: /images with a failed night and a new release`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto('/?demo=nightlyfail,newrelease')
    await page.waitForSelector('.shell')
    await page.evaluate(() => { history.pushState({}, '', '/images'); dispatchEvent(new PopStateEvent('popstate')) })
    await expect(page.getByTestId('auto-upgrade-failed')).toBeVisible()
    await expect(page.getByTestId('new-release')).toBeVisible()
    expect(await audit(page)).toEqual([])
    await page.getByTestId('new-release-go').click()
    await expect(page.getByTestId('image-auto')).not.toBeChecked()
    expect(await audit(page)).toEqual([])
  })
}

// The wizard's base image step (`?demo=setup`, the steps before it skipped).
for (const scheme of ['light', 'dark'] as const) {
  test(`a11y ${scheme}: /setup base image step`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto('/?demo=setup')
    await page.getByTestId('setup-token').fill(DEMO_SETUP_TOKEN)
    await page.getByTestId('setup-password').fill('correct horse battery')
    await page.getByTestId('setup-repeat').fill('correct horse battery')
    await page.getByTestId('setup-create').click()
    for (const name of ['Host name', 'Certificate', 'Firewall', 'Storage and network']) {
      await expect(page.getByTestId('setup-step')).toContainText(name)
      await page.getByTestId('setup-skip').click()
    }
    await expect(page.getByTestId('image-fields')).toBeVisible()
    expect(await audit(page)).toEqual([])
  })
}

// Dialogs and states of the confirmation tiers and the form checks: each one opened, then audited.
const states: Array<{ name: string; route: string; steps: Array<{ click?: string; force?: boolean; fill?: [string, string] }> }> = [
  { name: 'delete jail (typed)', route: '/jails/proxy', steps: [{ click: '[data-test="jail-delete"]' }, { click: '[data-test="confirm"]', force: true }] },
  { name: 'stop a running jail', route: '/jails', steps: [{ click: '[data-stop="db"]' }] },
  { name: 'uninstall an app', route: '/apps?tab=installed', steps: [{ click: '[data-test^="uninstall-"]' }] },
  { name: 'create jail after a failed submit', route: '/jails', steps: [{ click: '[data-test="new-jail"]' }, { click: '[data-test="jail-create-go"]', force: true }] },
  { name: 'image upgrade confirm', route: '/images', steps: [{ click: '[data-test^="upgrade-"]' }] },
  { name: 'nightly upgrade after a failed save', route: '/images', steps: [{ fill: ['[data-test="auto-upgrade-at"]', ''] }, { click: '[data-test="auto-upgrade-save"]', force: true }] },
  { name: 'network edit', route: '/networks', steps: [{ click: '[data-test="edit-net-lan"]' }] },
  { name: 'network delete (typed)', route: '/networks', steps: [{ click: '[data-test="delete-net-lan"]' }] },
  { name: 'create firewall policy', route: '/firewall', steps: [{ click: '[data-test="new-policy"]' }, { click: '[data-test="policy-create-go"]', force: true }] },
  { name: 'create address set after a failed submit', route: '/firewall?tab=sets', steps: [{ click: '[data-test="new-set"]' }, { fill: ['#fws-name', 'Bad-Name'] }, { fill: ['#fws-members', 'nope'] }, { click: '[data-test="set-create-go"]', force: true }] },
  { name: 'delete an address set in use, refused', route: '/firewall?tab=sets', steps: [{ click: '[data-test="delete-set"]' }, { click: '[data-test="confirm"]' }] },
  { name: 'address set editor with field errors', route: '/firewall?tab=sets', steps: [{ fill: ['#sa', 'nope'] }, { click: '[data-test="save-set"]', force: true }] },
  { name: 'new token after a failed submit', route: '/access?tab=tokens', steps: [{ click: '.page-head .btn-primary' }, { click: '[data-test="token-create"]', force: true }] },
  { name: 'add a log sink', route: '/logs?tab=forwarding', steps: [{ click: '[data-test="fw-add"]' }] },
  { name: 'create image after a failed submit', route: '/images', steps: [{ click: '[data-test="image-new"]' }, { fill: ['[data-test="image-name"]', 'Bad'] }, { click: '[data-test="image-create-go"]', force: true }] },
  { name: 'quick switcher with results', route: '/jails', steps: [{ click: '[data-test^="search-open-"]:visible' }, { fill: ['[data-test="qs-input"]', 'web'] }] },
  { name: 'quick switcher on recent items and with no match', route: '/jails/api', steps: [{ click: '[data-test^="search-open-"]:visible' }, { fill: ['[data-test="qs-input"]', 'zzzqqq'] }] },
  { name: 'quick switcher of every project', route: '/', steps: [{ click: '[data-test^="search-open-"]:visible' }, { click: '[data-test="qs-all"]' }, { fill: ['[data-test="qs-input"]', 'env=staging'] }] },
  { name: 'labels editor after a failed add', route: '/jails/api', steps: [{ click: '[data-test="labels-edit"]' }, { fill: ['[data-test="label-key"]', 'Bad key'] }, { click: '[data-test="label-add"]', force: true }] },
  { name: 'filtered jail list with suggestions', route: '/jails?q=env%3Dprod%20-team%3Dweb', steps: [{ click: '[data-test="jails-filter"]' }, { fill: ['[data-test="jails-filter"]', 'env=prod -team=web t'] }] },
  { name: 'bulk labels', route: '/jails', steps: [{ click: '[aria-label="Select api"]' }, { click: '[data-test="bulk-labels"]' }, { click: '[data-test="bl-apply"]', force: true }] },
  { name: 'connected shell', route: '/jails/web/shell', steps: [] },
]
for (const scheme of ['light', 'dark'] as const) {
  test.describe(`a11y ${scheme} dialogs`, () => {
    test.use({ colorScheme: scheme })
    for (const st of states) {
      test(`${st.name}`, async ({ page }) => {
        await page.goto('/?demo')
        await page.waitForSelector('.shell')
        await page.evaluate((p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')) }, st.route)
        await page.waitForLoadState('networkidle')
        for (const x of st.steps) {
          if (x.fill) await page.locator(x.fill[0]).first().fill(x.fill[1])
          if (x.click) await page.locator(x.click).first().click({ force: x.force })
        }
        await page.waitForTimeout(300)
        expect(await audit(page)).toEqual([])
      })
    }
  })
}
