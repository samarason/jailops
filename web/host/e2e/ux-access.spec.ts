import { test, expect, type Page } from '@playwright/test'
import { DEMO_SETUP_TOKEN } from '../src/demo/setupToken'

// The shared patterns on the pages of access, the host and the first-run wizard: tabs in the address, messages only
// after an attempt, toasts that go away, the countdown said once, and the phone drawer.

async function open(page: Page, path: string, query = '?demo'): Promise<void> {
  await page.goto('/' + query)
  await page.waitForSelector('.shell')
  await page.evaluate((p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')) }, path)
  await page.waitForLoadState('networkidle')
}

test('access opens on Users; ?tab= opens a tab; the arrow keys move along the tabs and into the address', async ({ page }) => {
  await open(page, '/access')
  await expect(page.locator('[data-tab="users"]')).toHaveAttribute('aria-selected', 'true')
  await expect(page.locator('[data-test="users"]')).toBeVisible()
  // nothing red on a form nobody touched
  await expect(page.getByTestId('scope-required')).toHaveCount(0)
  await page.locator('[data-tab="users"]').focus()
  await page.keyboard.press('ArrowRight')
  await expect(page.locator('[data-tab="tokens"]')).toBeFocused()
  await expect(page).toHaveURL(/\?tab=tokens$/)
  await page.keyboard.press('End')
  await expect(page.locator('[data-tab="whoami"]')).toHaveAttribute('aria-selected', 'true')
  await page.keyboard.press('Home')
  await expect(page).not.toHaveURL(/tab=/)
  await open(page, '/access?tab=trust')
  await expect(page.locator('[data-tab="trust"]')).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByTestId('trust-panel')).toBeVisible()
  await expect(page.getByTestId('scope-required')).toHaveCount(0)
  await expect(page.getByTestId('trust-why')).toContainText('Name the client')
  // a submit shows every message and focuses the first field with one
  await page.getByTestId('trust-create').click({ force: true })
  await expect(page.locator('#tt-name')).toBeFocused()
  await expect(page.getByTestId('scope-required')).toBeVisible()
})

test('deleting a user needs its name typed; revoking a session names who is signed out', async ({ page }) => {
  await open(page, '/access')
  await page.locator('[data-user="bob"]').getByTestId('user-delete').click()
  const d = page.getByTestId('confirm-dialog')
  await expect(d).toHaveAttribute('data-tier', '3')
  await expect(page.getByTestId('confirm-items')).toContainText('every session of bob')
  await page.getByTestId('confirm').click({ force: true })
  await expect(d.getByRole('alert')).toContainText('does not match')
  await page.keyboard.press('Escape')
  await expect(d).toHaveCount(0)
})

test('a failed toast goes away by itself; pointing at it holds it', async ({ page }) => {
  await page.clock.install()
  await open(page, '/jails')
  await page.locator('[data-unlock="vault"]').click()
  const dialog = page.getByRole('dialog')
  await dialog.locator('#unlock-pass').fill('not-the-passphrase')
  await dialog.getByTestId('unlock-go').click()
  await expect(dialog.getByTestId('unlock-error')).toBeVisible()
  await page.keyboard.press('Escape')
  const toast = page.locator('.toast[data-status="failure"]')
  await expect(toast).toHaveCount(1)
  await toast.hover()
  await page.clock.runFor(20_000)
  await expect(toast).toHaveCount(1)
  await page.mouse.move(5, 5)
  await page.clock.runFor(16_000)
  await expect(toast).toHaveCount(0)
})

test('the pending banner says the countdown once', async ({ page }) => {
  await open(page, '/host', '?demo=pending')
  const banner = page.getByTestId('pending-banner')
  await expect(banner).toBeVisible()
  const text = (await banner.textContent()) ?? ''
  expect(text.match(/\d+:\d\d/g)).toHaveLength(1)
})

test('phone: the menu drawer has a close button that gives the focus back', async ({ page }, info) => {
  test.skip(info.project.name !== 'phone')
  await open(page, '/')
  await page.getByRole('button', { name: 'Menu' }).click()
  const close = page.getByTestId('drawer-close')
  await expect(close).toBeVisible()
  const box = (await close.boundingBox())!
  expect(box.height).toBeGreaterThanOrEqual(40)
  await close.click()
  await expect(page.locator('#sidebar')).not.toBeInViewport()
  await expect(page.getByRole('button', { name: 'Menu' })).toBeFocused()
})

test('setup: the new host name is used at once, Skip keeps the self-signed certificate and says so, any prefix is taken', async ({ page }) => {
  await page.goto('/?demo=setup')
  await page.getByTestId('setup-token').fill(DEMO_SETUP_TOKEN)
  await page.getByTestId('setup-password').fill('correct horse battery')
  await page.getByTestId('setup-repeat').fill('correct horse battery')
  await page.getByTestId('setup-create').click()
  await page.getByTestId('setup-hostname').fill('jails1.example.com')
  await page.getByTestId('setup-apply').click()
  await expect(page.getByTestId('setup-step')).toHaveText('Step 3 of 7: Certificate')
  await expect(page.getByTestId('setup-host')).toHaveText('jails1.example.com')
  await expect(page.getByLabel('remote-add')).toHaveValue(/^jailops remote add jails1 https:\/\/jails1\.example\.com:/)
  // Continue carries out the chosen way: it opens that dialog
  await page.getByTestId('setup-cert-upload').check()
  await page.getByTestId('setup-next').click()
  await expect(page.getByRole('dialog')).toContainText('Upload a certificate')
  await expect(page.getByTestId('cu-host')).toHaveValue('jails1.example.com')
  await page.keyboard.press('Escape')
  await page.getByTestId('setup-skip').click()
  await expect(page.getByTestId('setup-cert-skipped')).toContainText('keeps its self-signed certificate')
  await page.getByTestId('setup-skip').click()
  await page.getByTestId('setup-subnet').fill('10.77.0.0/16')
  await expect(page.getByTestId('setup-make')).toBeEnabled()
  await page.getByTestId('setup-make').click()
  await expect(page.getByTestId('setup-step')).toHaveText('Step 6 of 7: Base image')
  await page.getByTestId('setup-skip').click()
  await expect(page.getByTestId('setup-done')).toContainText('Network lan with 10.77.0.0/16')
})
