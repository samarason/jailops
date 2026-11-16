import { test, expect, type Page } from '@playwright/test'

// Who may connect to an installed app, in demo mode: the Access tab of the app's jail, Allow and Deny.

function watch(page: Page): string[] {
  const problems: string[] = []
  page.on('console', (m) => m.type() === 'error' && problems.push(m.text()))
  page.on('pageerror', (e) => problems.push(String(e)))
  return problems
}

async function open(page: Page, path: string): Promise<void> {
  await page.goto('/?demo')
  await page.waitForSelector('.shell')
  await page.evaluate((p) => {
    history.pushState({}, '', p)
    dispatchEvent(new PopStateEvent('popstate'))
  }, path)
  await page.waitForLoadState('networkidle')
}

test('the access tab lists the grants with the rules they generated', async ({ page }) => {
  const problems = watch(page)
  await open(page, '/jails/db?tab=access')
  const tab = page.getByTestId('access-tab')
  await expect(page.locator('[data-tab="access"]')).toHaveAttribute('aria-selected', 'true')
  await expect(tab.getByTestId('access-state')).toHaveText('closed')
  const g = tab.locator('[data-grant="jail:web"]')
  await expect(g).toContainText('5432/tcp')
  await expect(g).toContainText('role web')
  await expect(g.getByText('host web web 10.20.0.11/32 scram-sha-256')).toBeHidden()
  await g.locator('summary').click()
  await expect(g.getByText('host web web 10.20.0.11/32 scram-sha-256')).toBeVisible()
  await expect(g).toContainText('allow in tcp from jail:web to port 5432')
  // a jail that is not an installed app has no such tab
  await open(page, '/jails/mail')
  await expect(page.locator('h1')).toHaveText('mail')
  await expect(page.locator('[data-tab="access"]')).toHaveCount(0)
  expect(problems).toEqual([])
})

test('allow a jail: preview, the connection string shown once with a copy button, then deny it with a confirmation', async ({ page }) => {
  const problems = watch(page)
  await open(page, '/apps?tab=installed')
  await page.getByTestId('access-db').click()
  await expect(page.locator('[data-tab="access"]')).toHaveAttribute('aria-selected', 'true')
  await page.getByTestId('allow-open').click()
  const dialog = page.getByTestId('allow-dialog')
  await expect(dialog.getByTestId('allow-jails')).toContainText('jail:build')
  await expect(dialog.getByTestId('allow-jails')).not.toContainText('jail:db')
  await dialog.getByTestId('allow-filter').fill('buil')
  await dialog.getByTestId('allow-jails').getByText('jail:build').click()
  await expect(dialog.locator('#acc-db')).toHaveAttribute('placeholder', 'build')
  await page.getByTestId('allow-preview-btn').click()
  await expect(dialog.getByTestId('allow-preview')).toContainText('CREATE ROLE "build"')
  await expect(dialog.getByTestId('allow-preview')).toContainText('scram-sha-256')
  await page.getByTestId('allow-go').click()
  await expect(dialog.getByTestId('allow-ok')).toContainText('jail:build may now reach db')
  const secret = dialog.getByTestId('allow-secret')
  await expect(secret).toContainText('Shown once and stored nowhere')
  await expect(secret.locator('input')).toHaveValue(/^postgres:\/\/build:[A-Za-z0-9]{32}@[0-9.]+:5432\/build\?sslmode=disable$/)
  await secret.getByRole('button', { name: 'Copy' }).click()
  await expect(secret.getByRole('button', { name: 'Copied' })).toBeVisible()
  await page.getByTestId('allow-close').click()
  await expect(page.getByTestId('allow-secret')).toHaveCount(0)
  const g = page.locator('[data-grant="jail:build"]')
  await expect(g).toContainText('5432/tcp')
  // the connection string is not part of the page any more
  expect(await page.content()).not.toMatch(/postgres:\/\/build:/)

  await g.getByTestId('deny-jail:build').click()
  const deny = page.getByTestId('deny-dialog')
  await expect(deny).toContainText('keeps its database')
  await page.getByTestId('drop-role').check()
  await page.getByTestId('confirm').click()
  await expect(page.locator('[data-grant="jail:build"]')).toHaveCount(0)
  await expect(page.locator('[data-grant="jail:web"]')).toBeVisible()
  expect(problems).toEqual([])
})

test('an address must be an address; a source that is not a jail needs a database name', async ({ page }) => {
  await open(page, '/jails/db?tab=access')
  await page.getByTestId('allow-open').click()
  const dialog = page.getByTestId('allow-dialog')
  await dialog.getByTestId('kind-cidr').check()
  await dialog.getByTestId('allow-cidr').fill('192.0.2.300')
  await expect(dialog.getByRole('alert')).toContainText('Not an IPv4 or IPv6 address')
  await dialog.getByTestId('allow-cidr').fill('192.0.2.0/24')
  await page.getByTestId('allow-go').click()
  await expect(dialog.getByRole('alert')).toContainText('Name the database')
  await dialog.locator('#acc-db').fill('reports')
  await page.getByTestId('allow-go').click()
  await expect(dialog.getByTestId('allow-ok')).toContainText('192.0.2.0/24 may now reach db')
  await expect(dialog.getByTestId('allow-secret')).toBeVisible()
})

test('a web app gets the firewall rule only: no database field, a note on what the app must do', async ({ page }) => {
  await open(page, '/jails/web?tab=access')
  await expect(page.locator('[data-grant="host"]')).toContainText('80/tcp, 443/tcp')
  await page.getByTestId('allow-open').click()
  const dialog = page.getByTestId('allow-dialog')
  await expect(dialog.locator('#acc-db')).toHaveCount(0)
  await dialog.getByTestId('kind-set').check()
  await dialog.getByTestId('allow-set').selectOption('office')
  await page.getByTestId('allow-go').click()
  await expect(dialog.getByTestId('allow-ok')).toContainText('set:office may now reach web')
  await expect(dialog).toContainText('only the firewall changed')
  await expect(dialog.getByTestId('allow-secret')).toHaveCount(0)
})
