import { test, expect, type Page } from '@playwright/test'

const routes = ['/', '/hosts', '/snapshots', '/deletions', '/retention', '/maintenance', '/audit', '/access']

function watch(page: Page): string[] {
  const problems: string[] = []
  page.on('console', (m) => m.type() === 'error' && problems.push(m.text()))
  page.on('pageerror', (e) => problems.push(String(e)))
  return problems
}

async function open(page: Page, path: string, query = '?demo'): Promise<void> {
  await page.goto('/' + query)
  await page.waitForSelector('.shell')
  if (path !== '/') {
    await page.evaluate((p) => {
      history.pushState({}, '', p)
      dispatchEvent(new PopStateEvent('popstate'))
    }, path)
  }
  await page.waitForLoadState('networkidle')
}

for (const scheme of ['light', 'dark'] as const) {
  test.describe(scheme, () => {
    test.use({ colorScheme: scheme })
    for (const r of routes) {
      test(`${r}: renders without console errors or horizontal overflow`, async ({ page }, info) => {
        const problems = watch(page)
        await open(page, r)
        await expect(page.locator('main h1').first()).toBeVisible()
        expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), 'horizontal page overflow in px').toBeLessThanOrEqual(0)
        expect(problems).toEqual([])
        if (process.env.SHOTS) await page.screenshot({ path: `${process.env.SHOTS}/backup-${info.project.name}-${scheme}-${r.replace(/\//g, '_') || '_'}.png`, fullPage: true })
      })
    }
  })
}

test('the console names itself and has no host views', async ({ page }) => {
  await open(page, '/')
  await expect(page).toHaveTitle('Overview - JailOps backup node console')
  await expect(page.locator('.brand-side')).toContainText('backup node')
  await expect(page.getByRole('link', { name: 'Jails' })).toHaveCount(0)
  await expect(page.getByRole('link', { name: 'Firewall' })).toHaveCount(0)
  await expect(page.getByTestId('whoami')).toContainText('admin')
})

test('overview shows the repository as the node reports it and says the node is keyless', async ({ page }) => {
  await open(page, '/')
  await expect(page.getByTestId('keyless')).toContainText('no encryption key')
  await expect(page.getByTestId('mode')).toHaveText('Online')
  await expect(page.getByTestId('quarantined')).toHaveText('2')
  await expect(page.getByTestId('attention')).toContainText('quarantine')
  await expect(page.getByTestId('open-sessions')).toBeVisible()
  await expect(page.getByTestId('fingerprint')).toContainText('SHA256:')
})

test('login view signs in with a token', async ({ page }) => {
  await page.goto('/?demo=login')
  await expect(page.getByLabel('One-time code')).toHaveCount(0)
  await page.getByLabel('Token').fill('jot_demo')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.locator('main h1')).toHaveText('Overview')
})

test('retention dry run shows the plan and deletes nothing', async ({ page }) => {
  await open(page, '/retention')
  await page.getByTestId('dry-run').click()
  await expect(page.getByTestId('plan')).toContainText('Dry run')
  await expect(page.getByTestId('plan')).toContainText('would be deleted')
})

test('a real retention run needs the typed node name', async ({ page }) => {
  await open(page, '/retention')
  await page.getByTestId('run').click()
  const go = page.getByTestId('confirm')
  await expect(go).toHaveAttribute('aria-disabled', 'true')
  await page.getByLabel(/Type the node name/).fill('vault.example.net')
  await expect(go).toHaveAttribute('aria-disabled', 'false')
  await go.click()
  await expect(page.getByTestId('run-result')).toContainText('deleted')
})

test('repository mode changes need the typed node name', async ({ page }) => {
  await open(page, '/maintenance')
  await page.locator('[data-mode="read-only"]').click()
  const go = page.getByTestId('confirm')
  await expect(page.getByTestId('confirm-items')).toContainText('hosts cannot push new snapshots')
  await expect(go).toHaveAttribute('aria-disabled', 'true')
  await page.getByLabel(/Type the node name/).fill('vault.example.net')
  await expect(go).toHaveAttribute('aria-disabled', 'false')
  await go.click()
  await expect(page.getByTestId('maint-state')).toHaveText('Read only')
})

test('GC dry run and verification run as jobs with results', async ({ page }) => {
  await open(page, '/maintenance')
  await page.getByTestId('gc-dry').click()
  await expect(page.locator('.toast').first()).toBeVisible()
  await page.getByTestId('verify-open').click()
  await page.getByTestId('verify-go').click()
  await expect(page.getByTestId('jobs')).toContainText('verify')
})

test('snapshots of a group: states, protection and a keyless notice', async ({ page }) => {
  await open(page, '/snapshots')
  await expect(page.getByTestId('keyless')).toBeVisible()
  await expect(page.locator('[data-snapshot="20261020021500-d8e2c7b9"]').getByTestId('protected')).toBeVisible()
  await expect(page.locator('[data-snapshot="20261020021500-d8e2c7b9"]').getByTestId('request')).toBeDisabled()
  await page.locator('[data-group="bsd01.db"]').click()
  await expect(page.locator('[data-snapshot="20261021110000-33cc44dd"]').getByTestId('failed')).toBeVisible()
})

test('deletion is two steps: execute is blocked until the delay has passed', async ({ page }) => {
  await open(page, '/deletions')
  await expect(page.locator('[data-deletion="20261019021500-c4410aa2"]').getByTestId('execute')).toBeDisabled()
  const ready = page.locator('[data-deletion="20260920030000-aa55bb66"]').getByTestId('execute')
  await expect(ready).toBeEnabled()
  await ready.click()
  const go = page.getByTestId('confirm')
  await expect(go).toHaveAttribute('aria-disabled', 'true')
  await page.getByLabel(/Type the snapshot id/).fill('20260920030000-aa55bb66')
  await expect(go).toHaveAttribute('aria-disabled', 'false')
})

test('requesting a deletion records a request; nothing is removed', async ({ page }) => {
  await open(page, '/snapshots')
  await page.locator('[data-snapshot="20261018021500-b27d11f0"]').getByTestId('request').click()
  await page.getByLabel('Delay').fill('48h')
  await page.getByTestId('request-go').click()
  await expect(page.locator('[data-snapshot="20261018021500-b27d11f0"]').getByTestId('pending')).toBeVisible()
})

test('host enrolment needs a fingerprint or certificate; revoking needs the host name', async ({ page }) => {
  await open(page, '/hosts')
  await page.getByTestId('enrol').click()
  await page.getByLabel(/^Host\b/).fill('bsd09')
  await expect(page.getByTestId('enrol-go')).toHaveAttribute('aria-disabled', 'true')
  await expect(page.getByTestId('enrol-why')).toContainText('fingerprint')
  await page.getByTestId('enrol-go').click({ force: true })
  await expect(page.getByLabel('Certificate fingerprint')).toBeFocused()
  await page.getByLabel('Certificate fingerprint').fill('SHA256:aa:bb')
  await page.getByTestId('enrol-go').click()
  await expect(page.locator('[data-host="bsd09"]')).toBeVisible()
  await page.locator('[data-host="bsd09"]').getByTestId('revoke').click()
  await expect(page.getByTestId('confirm')).toHaveAttribute('aria-disabled', 'true')
  await page.getByLabel(/Type the host name/).fill('bsd09')
  await expect(page.getByTestId('confirm')).toHaveAttribute('aria-disabled', 'false')
})

test('a new token is shown once', async ({ page }) => {
  await open(page, '/access')
  await page.getByRole('tab', { name: 'API tokens' }).click()
  await page.getByRole('button', { name: 'New token' }).click()
  await page.locator('#nt-name').fill('e2e')
  await page.getByRole('button', { name: 'Create token' }).click()
  await expect(page.getByLabel('Name', { exact: true }).last()).toHaveValue(/^jot_/)
  await page.getByTestId('secret-done').click()
  await expect(page.getByText('jot_', { exact: false })).toHaveCount(0)
})

test('a readonly user sees who may do what and cannot operate or administer', async ({ page }) => {
  await open(page, '/maintenance', '?demo&role=readonly')
  await expect(page.getByTestId('role-note')).toContainText('backup-admin')
  await expect(page.getByTestId('gc-run')).toBeDisabled()
  await expect(page.locator('[data-mode="read-only"]')).toBeDisabled()
  await page.evaluate(() => { history.pushState({}, '', '/audit'); dispatchEvent(new PopStateEvent('popstate')) })
  await expect(page.getByTestId('role-note')).toContainText('admin')
  await expect(page.getByTestId('whoami')).toContainText('readonly')
})

test('phone width: the menu opens and navigates', async ({ page }, info) => {
  test.skip(info.project.name !== 'phone')
  await open(page, '/')
  await page.getByRole('button', { name: 'Menu' }).click()
  await page.getByRole('link', { name: 'Hosts' }).click()
  await expect(page.locator('main h1')).toHaveText('Hosts')
})

test('row buttons name their row for screen readers', async ({ page }) => {
  await open(page, '/retention')
  await expect(page.getByRole('button', { name: 'Edit bsd01.db' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Delete bsd01.db' })).toBeVisible()
  await open(page, '/snapshots')
  await expect(page.getByRole('button', { name: /^Request deletion 2026/ }).first()).toBeVisible()
})
