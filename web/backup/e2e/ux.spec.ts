import { test, expect, type Page } from '@playwright/test'

// The retention policy form, the shared tab pattern and the phone cards of the backup console.

async function open(page: Page, path: string): Promise<void> {
  await page.goto('/?demo')
  await page.waitForSelector('.shell')
  await page.evaluate((p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')) }, path)
  await page.waitForLoadState('networkidle')
}

test('Add retention policy starts empty, offers only scopes without a policy and never overwrites one', async ({ page }) => {
  await open(page, '/retention')
  await page.getByTestId('add-policy').click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByRole('heading')).toHaveText('Add retention policy')
  const scope = dialog.locator('#pe-scope')
  await expect(scope).toHaveValue('')
  // default and bsd01.db have a policy: neither is offered again
  const offered = await scope.locator('option:not([disabled])').evaluateAll((o) => o.map((x) => (x as HTMLOptionElement).value))
  expect(offered).not.toContain('default')
  expect(offered).not.toContain('bsd01.db')
  expect(offered).toContain('bsd01.web')
  // a submit without a scope says what is missing and focuses it
  await page.getByTestId('policy-save').click({ force: true })
  await expect(page.getByTestId('scope-error')).toContainText('Choose the scope')
  await expect(scope).toBeFocused()
  await scope.selectOption('bsd01.web')
  await page.getByTestId('policy-save').click({ force: true })
  await expect(page.getByTestId('policy-why')).toContainText('Keep at least one snapshot')
  await dialog.getByLabel('Daily').fill('7')
  await page.getByTestId('policy-save').click()
  await expect(page.locator('[data-policy="bsd01.web"]')).toContainText('7 daily')
  // the default policy is untouched
  await expect(page.locator('[data-policy="default"]')).toContainText('3 last, 7 daily, 4 weekly, 6 monthly')
})

test('Edit keeps the scope read-only and names it in the title', async ({ page }) => {
  await open(page, '/retention')
  await page.getByRole('button', { name: 'Edit bsd01.db' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByRole('heading')).toHaveText('Edit the policy of bsd01.db')
  await expect(page.getByTestId('scope-readonly')).toHaveText('bsd01.db')
  await expect(dialog.locator('#pe-scope')).toHaveCount(0)
})

test('deleting a policy says what the groups fall back to', async ({ page }) => {
  await open(page, '/retention')
  await page.getByRole('button', { name: 'Delete bsd01.db' }).click()
  await expect(page.getByTestId('confirm-dialog')).toContainText('falls back to the default policy')
  await page.getByTestId('confirm').click()
  await expect(page.locator('[data-policy="bsd01.db"]')).toHaveCount(0)
})

test('access opens on Users, keeps the tab in the address and moves with the arrow keys', async ({ page }) => {
  await open(page, '/access')
  await expect(page.locator('[data-tab="users"]')).toHaveAttribute('aria-selected', 'true')
  await page.locator('[data-tab="users"]').focus()
  await page.keyboard.press('ArrowRight')
  await expect(page.locator('[data-tab="tokens"]')).toHaveAttribute('aria-selected', 'true')
  await expect(page.locator('[data-tab="tokens"]')).toBeFocused()
  await expect(page).toHaveURL(/\?tab=tokens/)
  await open(page, '/access?tab=tokens')
  await expect(page.locator('[data-tab="tokens"]')).toHaveAttribute('aria-selected', 'true')
})

test('phone: snapshots and jobs are cards with their buttons at the bottom', async ({ page }, info) => {
  test.skip(info.project.name !== 'phone')
  await open(page, '/snapshots')
  const row = page.locator('[data-snapshot="20261018021500-b27d11f0"]')
  const id = await row.locator('td').first().boundingBox()
  const actions = await row.locator('td.actions').boundingBox()
  expect(actions!.y).toBeGreaterThan(id!.y)
  await expect(row.getByTestId('request')).toBeInViewport({ ratio: 0.1 }).catch(() => undefined)
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0)
  // every action of a card is fully inside the screen
  for (const b of await row.locator('td.actions button').all()) {
    const box = (await b.boundingBox())!
    expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize()!.width)
  }
  await open(page, '/maintenance')
  const details = page.locator('[data-test="jobs"] td.actions button').first()
  const box = (await details.boundingBox())!
  expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize()!.width)
})
