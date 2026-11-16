import { test, expect, type Page } from '@playwright/test'

// The infrastructure pages: confirmation tiers, the missing actions (network edit and delete, firewall policies),
// the host firewall on the WireGuard page, words instead of API paths, and phone cards. Demo mode.

async function open(page: Page, path: string): Promise<void> {
  await page.goto('/?demo')
  await page.waitForSelector('.shell')
  await page.evaluate((p) => {
    history.pushState({}, '', p)
    dispatchEvent(new PopStateEvent('popstate'))
  }, path)
  await page.waitForLoadState('networkidle')
}

test('upgrading an image asks first and lists the jails on it', async ({ page }) => {
  await open(page, '/images')
  await page.getByTestId('upgrade-freebsd-15-1').click()
  const dlg = page.getByTestId('confirm-dialog')
  await expect(dlg).toHaveAttribute('data-tier', '2')
  await expect(dlg.getByTestId('confirm-items')).toContainText('web')
  await expect(dlg.getByTestId('confirm-items')).toContainText('mail')
  await page.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  // building is asked too, and runs after the confirmation
  await page.getByTestId('build-alpine-3-22').click()
  await expect(page.getByTestId('confirm-items')).toContainText('alpine-app')
  await page.getByTestId('confirm').click()
  await expect(page.locator('.toast').first()).toBeVisible()
})

test('a network is edited with its name kept, and deleted with its name typed while jails use it', async ({ page }) => {
  await open(page, '/networks')
  await page.getByTestId('edit-net-lan').click()
  await expect(page.locator('#nf-name')).toHaveAttribute('readonly', '')
  await expect(page.locator('#nf-v4r')).toHaveValue('10.20.0.10-10.20.0.60')
  await page.locator('#nf-v4r').fill('10.20.0.10-10.20.0.90')
  await page.getByTestId('net-create-go').click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page.locator('[data-network="lan"]')).toContainText('10.20.0.10-10.20.0.90')

  // lan has jails: the name must be typed, and the button says why it does nothing yet
  await page.getByTestId('delete-net-lan').click()
  const dlg = page.getByTestId('confirm-dialog')
  await expect(dlg).toHaveAttribute('data-tier', '3')
  await expect(dlg.getByTestId('confirm-items')).toContainText('web')
  await expect(page.getByTestId('confirm-why')).toContainText('Type lan')
  await page.getByTestId('confirm').click({ force: true })
  await expect(page.getByRole('dialog')).toBeVisible()
  await page.getByTestId('confirm-type').fill('lan')
  await page.getByTestId('confirm').click()
  // the web project still grants lan: the server refuses and says what to do
  await expect(page.getByTestId('error-panel')).toContainText('granted to project')
  await page.getByRole('button', { name: 'Cancel' }).click()

  // stg has no jails: a plain confirmation; the staging project grants it, so the refusal shows too
  await page.getByTestId('delete-net-shop').click()
  await expect(page.getByTestId('confirm-dialog')).toHaveAttribute('data-tier', '2')
})

test('a firewall policy is created with the name rule and deleted with its name typed while jails use it', async ({ page }) => {
  await open(page, '/firewall')
  await page.getByTestId('new-policy').click()
  await page.locator('#fwp-name').fill('Bad_Name')
  await page.getByTestId('policy-create-go').click({ force: true })
  await expect(page.locator('#fwp-name-e')).toContainText('does not follow the rule')
  await expect(page.locator('#fwp-name')).toBeFocused()
  await page.locator('#fwp-name').fill('api-edge')
  await page.getByTestId('policy-create-go').click()
  await expect(page.getByTestId('policy-editor')).toContainText('api-edge')
  // nobody uses the new policy: tier 2
  await page.getByTestId('delete-policy').click()
  await expect(page.getByTestId('confirm-dialog')).toHaveAttribute('data-tier', '2')
  await page.getByTestId('confirm').click()
  await expect(page.getByRole('button', { name: 'api-edge' })).toHaveCount(0)
  // web-default is attached to jails: tier 3, listing them
  await page.getByRole('button', { name: 'web-default' }).click()
  await page.getByTestId('delete-policy').click()
  await expect(page.getByTestId('confirm-dialog')).toHaveAttribute('data-tier', '3')
  await expect(page.getByTestId('confirm-items')).toContainText('web')
})

test('the firewall tab is in the address and moves with the arrow keys', async ({ page }) => {
  await open(page, '/firewall?tab=sets')
  await expect(page.locator('[data-tab="sets"]')).toHaveAttribute('aria-selected', 'true')
  await page.locator('[data-tab="sets"]').focus()
  await page.keyboard.press('ArrowLeft')
  await expect(page.locator('[data-tab="policies"]')).toHaveAttribute('aria-selected', 'true')
  await expect(page.locator('[data-tab="policies"]')).toBeFocused()
  await expect(page).not.toHaveURL(/tab=/)
})

test('WireGuard: the managed host firewall covers a port, or one click adds it with the confirm window', async ({ page }) => {
  await open(page, '/networks/wireguard')
  await expect(page.locator('[data-wg="office"]').getByTestId('wg-fw')).toContainText('allows udp 51820')
  await page.getByTestId('wg-new').click()
  await page.locator('#wgf-name').fill('lab')
  await page.locator('#wgf-addr').fill('10.97.0.1/24')
  await page.locator('#wgf-port').fill('51821')
  await page.getByTestId('wg-create-go').click()
  const lab = page.locator('[data-wg="lab"]')
  await expect(lab.getByTestId('wg-fw')).toContainText('does not pass udp 51821')
  await lab.getByTestId('wg-fw-add').click()
  await expect(page.getByRole('dialog')).toContainText('reverts itself')
  await page.getByTestId('confirm').click()
  await expect(page.getByTestId('pending-banner')).toBeVisible()
  await expect(lab.getByTestId('wg-fw')).toContainText('allows udp 51821')
})

test('operations and the audit log speak in words and link objects by name', async ({ page }) => {
  await open(page, '/audit')
  const table = page.getByTestId('audit-table')
  await expect(table).toContainText('Upgrade jail')
  await expect(table.getByRole('link', { name: 'web-default' })).toHaveAttribute('href', '/firewall?policy=web-default')
  await expect(page.locator('main')).not.toContainText('/api/v1')
  await open(page, '/operations')
  await expect(page.locator('main')).not.toContainText('/api/v1')
  await expect(page.locator('[data-op="op-1002"]').getByRole('link', { name: 'db' })).toHaveAttribute('href', '/jails/db')
  await expect(page.locator('[data-op="op-1002"]')).toContainText('Replication is running')
})

test('phone: /doctor and /audit rows are cards with every column in view', async ({ page, isMobile }) => {
  test.skip(!isMobile)
  for (const [path, last] of [['/doctor', 'Finding'], ['/audit', 'Result']] as const) {
    await open(page, path)
    const row = page.locator('tbody tr').first()
    const cell = row.locator(`td[data-label="${last}"]`)
    await expect(cell).toBeVisible()
    const box = (await cell.boundingBox())!
    expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize()!.width)
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  }
})

test('the demo firewall and backups follow the project switch', async ({ page }) => {
  await open(page, '/firewall')
  await expect(page.getByRole('button', { name: 'web-default' })).toBeVisible()
  await page.getByTestId('project-select').selectOption('staging')
  await expect(page.getByRole('button', { name: 'web-default' })).toHaveCount(0)
  await open(page, '/backups')
  await expect(page.locator('[data-jail="web"]')).toHaveCount(0)
})
