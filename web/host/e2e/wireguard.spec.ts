import { test, expect, type Page } from '@playwright/test'

async function open(page: Page, path: string): Promise<void> {
  await page.goto('/?demo')
  await page.waitForSelector('.shell')
  await page.evaluate((p) => {
    history.pushState({}, '', p)
    dispatchEvent(new PopStateEvent('popstate'))
  }, path)
  await page.waitForLoadState('networkidle')
}

test('the Networks area has a WireGuard tab that lists tunnels with their peers', async ({ page }) => {
  await open(page, '/networks')
  await page.getByTestId('net-tabs').getByRole('link', { name: 'WireGuard' }).click()
  await expect(page.locator('main h1').first()).toHaveText('WireGuard')
  const office = page.locator('[data-wg="office"]')
  await expect(office.locator('[data-wg-mode="server"]')).toBeVisible()
  await expect(office.getByTestId('wg-state')).toHaveText('Up')
  // the host firewall is managed in the demo and its allow list passes udp 51820
  await expect(office.getByTestId('wg-fw')).toContainText('The host firewall allows udp 51820')
  await expect(office.locator('[data-peer="laptop"] [data-test="wg-handshake"]')).toHaveText(/ago$/)
  await expect(office.locator('[data-peer="phone"] [data-test="wg-handshake"]')).toHaveText('never')
  await expect(page.locator('[data-wg="branch"] [data-wg-mode="client"]')).toBeVisible()
})

test('adding a peer shows the token once with a download, and it is gone after closing', async ({ page }) => {
  await open(page, '/networks/wireguard')
  const office = page.locator('[data-wg="office"]')
  await office.getByTestId('wg-add-peer').click()
  await page.locator('#wgp-name').fill('tablet')
  await page.getByTestId('wg-peer-go').click()
  await expect(page.getByTestId('wg-token-warning')).toContainText('only time')
  const token = await page.getByLabel('Join token').inputValue()
  expect(token).toMatch(/^jwg1\./)
  const download = page.waitForEvent('download')
  await page.getByTestId('wg-download').click()
  expect((await download).suggestedFilename()).toBe('tablet.conf')
  await page.getByTestId('wg-token-done').click()
  await expect(page.getByText(token)).toHaveCount(0)
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }))).not.toContain(token.slice(5, 40))
  await expect(office.locator('[data-peer="tablet"]')).toContainText('10.99.0.4/32')
  // remove it again, behind a confirmation
  await office.locator('[data-peer="tablet"]').getByRole('button', { name: 'Remove tablet' }).click()
  await page.getByTestId('confirm').click()
  await expect(office.locator('[data-peer="tablet"]')).toHaveCount(0)
})

test('create a server, join with a token, take a tunnel down and delete it', async ({ page }) => {
  await open(page, '/networks/wireguard')
  await page.getByTestId('wg-new').click()
  await page.getByTestId('wg-create-go').click({ force: true })
  await expect(page.locator('#wgf-name-e')).toContainText('Required')
  await page.locator('#wgf-name').fill('lab')
  await page.locator('#wgf-addr').fill('10.97.0.1/24')
  await page.locator('#wgf-port').fill('51821')
  await page.locator('[data-wg-net="lan"]').check()
  await page.getByTestId('wg-create-go').click({ force: true })
  const lab = page.locator('[data-wg="lab"]')
  await expect(lab.locator('[data-wg-mode="server"]')).toBeVisible()

  await page.getByTestId('wg-join').click()
  await page.locator('#wgj-token').fill('not a token')
  await page.getByTestId('wg-join-go').click({ force: true })
  await expect(page.locator('#wgj-token-e')).toContainText('does not look like')
  // a token from the lab server joins as a client
  await page.keyboard.press('Escape')
  await lab.getByTestId('wg-add-peer').click()
  await page.locator('#wgp-name').fill('home')
  await page.getByTestId('wg-peer-go').click()
  const token = await page.getByLabel('Join token').inputValue()
  await page.getByTestId('wg-token-done').click()
  await page.getByTestId('wg-join').click()
  await page.locator('#wgj-token').fill(token)
  await page.locator('#wgj-name').fill('homelink')
  await page.getByTestId('wg-join-go').click({ force: true })
  const home = page.locator('[data-wg="homelink"]')
  await expect(home.locator('[data-wg-mode="client"]')).toBeVisible()

  await home.getByTestId('wg-down').click()
  await expect(home.getByTestId('wg-state')).toHaveText('Down')
  await home.getByTestId('wg-up').click()
  await expect(home.getByTestId('wg-state')).toHaveText('Up')

  await lab.getByTestId('wg-rotate').click()
  await page.getByTestId('confirm').click()
  await expect(page.getByTestId('wg-rotated-key')).toHaveText(/^demo/)
  await page.getByRole('button', { name: 'Close' }).last().click()

  await home.getByTestId('wg-delete').click()
  await expect(page.getByRole('dialog')).toContainText('keys are deleted')
  await page.getByTestId('confirm').click()
  await expect(home).toHaveCount(0)
})
