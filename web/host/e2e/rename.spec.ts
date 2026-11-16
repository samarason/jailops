import { test, expect, type Page } from '@playwright/test'
import { audit } from '../../shared/a11y'

// Rename (extension rename) in the demo: the dialog's dry run lists what follows the new name, Rename runs it. A
// network, a stopped jail from its page, a running jail that says to stop it first, and an address set whose policy
// rule follows. Desktop and phone (the two Playwright projects), a fresh browser context each.

async function open(page: Page, path: string): Promise<void> {
  await page.goto('/?demo')
  await page.waitForSelector('.shell')
  await page.evaluate((p) => {
    history.pushState({}, '', p)
    dispatchEvent(new PopStateEvent('popstate'))
  }, path)
  await page.waitForLoadState('networkidle')
}

test('a network is renamed after the dry run lists what refers to it', async ({ page }) => {
  await open(page, '/networks')
  const opener = page.getByTestId('rename-net-lan')
  await opener.click()
  const dlg = page.getByRole('dialog')
  await expect(dlg.getByRole('heading', { name: 'Rename network lan' })).toBeVisible()
  await expect(page.locator('#rn-name')).toBeFocused()
  // Escape closes and gives the focus back to the button that opened the dialog
  await page.keyboard.press('Escape')
  await expect(dlg).toHaveCount(0)
  await expect(opener).toBeFocused()

  await opener.click()
  await expect(page.getByTestId('rename-why')).toHaveText('Enter a new name to see what changes.')
  await page.locator('#rn-name').fill('Lan 2')
  await expect(page.locator('#rn-name-e')).toHaveText('This name does not follow the rule above.')
  await page.locator('#rn-name').fill('lan2')
  await expect(page.getByTestId('rename-summary')).toContainText('The rename changes 1 object,')
  const refs = page.locator('[data-group="reference"]')
  await expect(refs).toContainText('project web')
  await expect(refs).toContainText('spec.networks: lan -> lan2')
  await expect(refs).toContainText('jail web (project web)')
  await expect(page.getByTestId('rename-why')).toHaveCount(0)
  await expect(page.getByTestId('rename-go')).toBeInViewport()
  await page.getByTestId('rename-go').click()
  await expect(dlg).toHaveCount(0)
  await expect(page.locator('[data-network="lan2"]')).toBeVisible()
  await expect(page.locator('[data-network="lan"]')).toHaveCount(0)
})

test('a stopped jail is renamed from its page, which moves to the new name', async ({ page }) => {
  await open(page, '/jails/build')
  await expect(page.locator('main h1')).toHaveText('build')
  await page.getByTestId('jail-rename').click()
  await page.locator('#rn-name').fill('ci')
  await expect(page.locator('[data-group="dataset"]')).toContainText('tank/jailops/web/build')
  await page.getByTestId('rename-go').click()
  await expect(page).toHaveURL(/\/jails\/ci$/)
  await expect(page.locator('main h1')).toHaveText('ci')
  await expect(page.getByRole('dialog')).toHaveCount(0)
})

test('a running jail says to stop it first instead of opening the dialog', async ({ page }) => {
  await open(page, '/jails/web')
  const btn = page.getByTestId('jail-rename')
  await expect(btn).toHaveAttribute('aria-disabled', 'true')
  await expect(page.getByTestId('jail-rename-why')).toHaveText('Stop the jail to rename it.')
  // the button is not silently dead: it stays clickable and opens nothing
  await btn.click({ force: true })
  await expect(page.getByRole('dialog')).toHaveCount(0)
})

test('an address set is renamed and the policy rule that names it follows', async ({ page }) => {
  await open(page, '/firewall?tab=sets')
  await expect(page.getByTestId('set-editor').locator('h2')).toHaveText('set:admins')
  await page.getByTestId('rename-set').click()
  await page.locator('#rn-name').fill('ops_team')
  await expect(page.locator('#rn-name-e')).toHaveText('This name does not follow the rule above.')
  await page.locator('#rn-name').fill('ops-team')
  await expect(page.locator('[data-group="reference"]')).toContainText('firewall policy web-default')
  await expect(page.locator('[data-group="reference"]')).toContainText('rules[1].from: set:admins -> set:ops-team')
  await page.getByTestId('rename-go').click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page.getByTestId('set-list')).toContainText('set:ops-team')
  await expect(page.getByTestId('set-list')).not.toContainText('set:admins')
  await page.locator('[data-tab="policies"]').click()
  await page.getByRole('button', { name: 'web-default' }).click()
  await expect(page.locator('[data-rule="1"]').getByLabel('From')).toHaveValue('set:ops-team')
})

for (const scheme of ['light', 'dark'] as const) {
  test(`a11y ${scheme}: the open dialog with its plan and with a refusal`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme })
    await open(page, '/networks')
    await page.getByTestId('rename-net-edge').click()
    await page.locator('#rn-name').fill('dmz')
    await expect(page.getByTestId('rename-summary')).toBeVisible()
    expect(await audit(page)).toEqual([])
    await page.locator('#rn-name').fill('lan')
    await expect(page.getByTestId('rename-plan').getByTestId('error-panel')).toContainText('already exists')
    expect(await audit(page)).toEqual([])
  })
}

test('phone width: the rename dialog fits the screen', async ({ page }, info) => {
  test.skip(info.project.name !== 'phone')
  await open(page, '/networks')
  await page.getByTestId('rename-net-lan').click()
  await page.locator('#rn-name').fill('lan2')
  await expect(page.getByTestId('rename-summary')).toBeVisible()
  const box = (await page.getByRole('dialog').boundingBox())!
  expect(box.x).toBeGreaterThanOrEqual(0)
  expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize()!.width)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
})
