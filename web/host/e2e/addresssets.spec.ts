import { test, expect, type Page } from '@playwright/test'

// Firewall address sets: created, used as set:NAME in a rule, refused while in use, deleted. And the list that
// once rendered and then vanished (a render error in the set editor). Demo mode, a fresh browser context.

async function open(page: Page, path: string): Promise<void> {
  await page.goto('/?demo')
  await page.waitForSelector('.shell')
  await page.evaluate((p) => {
    history.pushState({}, '', p)
    dispatchEvent(new PopStateEvent('popstate'))
  }, path)
  await page.waitForLoadState('networkidle')
}

const listText = (page: Page) => page.evaluate(() => [...document.querySelectorAll('ul[aria-label="Address sets"] li')].map((x) => x.textContent?.trim()).join('|'))

test('the address sets stay on screen: no render error, and the project switch shows the right sets', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()) })
  // a first visit: nothing stored, the way the owner opened it
  await page.goto('/?demo=1')
  await page.waitForSelector('.shell')
  await page.evaluate(() => { history.pushState({}, '', '/firewall'); dispatchEvent(new PopStateEvent('popstate')) })
  await page.locator('[data-tab="sets"]').click()
  await expect(page.getByRole('heading', { name: 'set:admins' })).toBeVisible()
  const samples: string[] = []
  for (let i = 0; i < 26; i++) {
    samples.push(await listText(page))
    await page.waitForTimeout(300)
  }
  expect(new Set(samples)).toEqual(new Set(['set:admins|set:office']))
  // an edit recomputes the editor's state: the list and the editor stay (they vanished when that threw)
  await page.getByLabel('Addresses').fill('198.51.100.7\n203.0.113.0/28\n192.0.2.99')
  await page.waitForTimeout(300)
  expect(await listText(page)).toBe('set:admins|set:office')
  await expect(page.getByRole('heading', { name: 'set:admins' })).toBeVisible()
  expect(errors).toEqual([])
  await page.getByRole('button', { name: 'Revert' }).click()
  // staging has no sets: the empty state, not the editor of the web project's set
  await page.getByTestId('project-select').selectOption('staging')
  await expect(page.getByTestId('sets-empty')).toContainText('No address sets yet.')
  await expect(page.getByTestId('set-editor')).toHaveCount(0)
  await page.getByTestId('project-select').selectOption('web')
  await expect(page.getByTestId('set-editor')).toContainText('set:admins')
  expect(await listText(page)).toBe('set:admins|set:office')
  expect(errors).toEqual([])
})

test('a new address set is used in a rule, refused while in use, and deleted once the rule is gone', async ({ page }) => {
  await open(page, '/firewall?tab=sets')
  await expect(page.getByTestId('save-set')).toHaveText('Save set')
  await page.getByTestId('new-set').click()
  await expect(page.locator('#fws-name')).toBeFocused()
  await page.locator('#fws-name').fill('Lab-1')
  await page.getByTestId('set-create-go').click({ force: true })
  await expect(page.locator('#fws-name-e')).toContainText('does not follow the rule')
  await page.locator('#fws-name').fill('lab')
  await page.locator('#fws-members').fill('198.51.100.10\n2001:db8:1::/64')
  await page.getByTestId('set-create-go').click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page.getByTestId('set-list')).toContainText('set:lab')
  await expect(page.getByTestId('set-editor').locator('h2')).toHaveText('set:lab')
  await expect(page.locator('#sa')).toHaveValue('198.51.100.10\n2001:db8:1::/64')

  // a policy whose rule allows ssh from set:lab
  await page.locator('[data-tab="policies"]').click()
  await page.getByTestId('new-policy').click()
  await page.locator('#fwp-name').fill('lab-edge')
  await page.getByTestId('policy-create-go').click()
  await expect(page.getByTestId('policy-editor')).toContainText('lab-edge')
  await page.getByRole('button', { name: 'Add rule' }).click()
  await page.locator('[data-rule="0"]').getByLabel('From').fill('set:lab')
  await page.locator('[data-rule="0"]').getByLabel('Ports').fill('22')
  await page.getByTestId('save-policy').click()
  await expect(page.getByTestId('policy-editor').locator('.pill.warn')).toHaveCount(0)

  // the set is in use: the confirmation names the policy, the server refuses and says what to do
  await page.locator('[data-tab="sets"]').click()
  await page.getByTestId('set-list').getByRole('button', { name: 'set:lab' }).click()
  await expect(page.getByTestId('set-users')).toContainText('lab-edge')
  await page.getByTestId('delete-set').click()
  await expect(page.getByTestId('confirm-items')).toContainText('lab-edge')
  await page.getByTestId('confirm').click()
  await expect(page.getByTestId('error-panel')).toContainText('address set "lab" is used by firewall policy "lab-edge"')
  await expect(page.getByTestId('error-hint')).toContainText('remove set:lab from the rules of lab-edge first')
  await page.getByRole('button', { name: 'Cancel' }).click()

  // remove the rule, then the set goes
  await page.locator('[data-tab="policies"]').click()
  await page.getByRole('button', { name: 'lab-edge' }).click()
  await page.locator('[data-rule="0"]').getByRole('button', { name: 'Remove rule' }).click()
  await page.getByTestId('save-policy').click()
  await expect(page.getByTestId('policy-editor').locator('.pill.warn')).toHaveCount(0)
  await page.locator('[data-tab="sets"]').click()
  await page.getByTestId('set-list').getByRole('button', { name: 'set:lab' }).click()
  await expect(page.getByTestId('set-users')).toHaveCount(0)
  await page.getByTestId('delete-set').click()
  await expect(page.getByTestId('confirm-dialog')).toHaveAttribute('data-tier', '2')
  await page.getByTestId('confirm').click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page.getByTestId('set-list')).not.toContainText('set:lab')
  await expect(page.getByTestId('set-editor').locator('h2')).toHaveText('set:admins')
})

// What a reviewer of the firewall reads: a comment on a set, on each of its members, on a policy and on a rule is typed in the
// console, saved, and still there after a reload.
test('comments on a set, its members, a policy and a rule are saved and read back', async ({ page }) => {
  await open(page, '/firewall?tab=sets')
  await page.getByTestId('new-set').click()
  await page.locator('#fws-name').fill('git-allow')
  await page.locator('#fws-comment').fill('Who may reach the git server')
  await page.locator('#fws-members').fill('198.51.100.10  # the office\n2001:db8:1::/64')
  await page.getByTestId('set-create-go').click()
  await expect(page.getByTestId('set-editor').locator('h2')).toHaveText('set:git-allow')
  await expect(page.getByTestId('set-comment')).toHaveValue('Who may reach the git server')
  await expect(page.locator('#sa')).toHaveValue('198.51.100.10  # the office\n2001:db8:1::/64')

  await page.locator('[data-tab="policies"]').click()
  await page.getByTestId('new-policy').click()
  await page.locator('#fwp-name').fill('git-edge')
  await page.getByTestId('policy-create-go').click()
  await page.getByTestId('policy-comment').fill('The git server of the team')
  await page.getByRole('button', { name: 'Add rule' }).click()
  await page.locator('[data-rule="0"]').getByLabel('From').fill('set:git-allow')
  await page.locator('[data-rule="0"]').getByLabel('Ports').fill('22')
  await page.locator('[data-rule="0"]').getByTestId('rule-comment').fill('ssh from the team only')
  await page.locator('[data-rule="0"]').getByTestId('rule-disabled').check()
  await expect(page.locator('[data-rule="0"]').getByTestId('rule-off')).toBeVisible()
  await page.getByTestId('save-policy').click()
  await expect(page.getByTestId('policy-editor').locator('.pill.warn')).toHaveCount(0)

  // a fresh load of the page reads them from the server (the demo keeps its state in the page, so go back to the list and in again)
  await page.locator('[data-tab="sets"]').click()
  await page.locator('[data-tab="policies"]').click()
  await page.getByRole('button', { name: 'git-edge' }).click()
  await expect(page.getByTestId('policy-comment')).toHaveValue('The git server of the team')
  await expect(page.locator('[data-rule="0"]').getByTestId('rule-comment')).toHaveValue('ssh from the team only')
  // a rule switched off keeps its place and says so
  await expect(page.locator('[data-rule="0"]').getByTestId('rule-disabled')).toBeChecked()
  await expect(page.locator('[data-rule="0"]').getByTestId('rule-off')).toBeVisible()
})

test('phone width: the address set dialog and editor fit the screen', async ({ page }, info) => {
  test.skip(info.project.name !== 'phone')
  await open(page, '/firewall?tab=sets')
  await expect(page.getByTestId('set-editor')).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.getByTestId('new-set').click()
  const box = (await page.getByRole('dialog').boundingBox())!
  expect(box.x).toBeGreaterThanOrEqual(0)
  expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize()!.width)
  await expect(page.getByTestId('set-create-go')).toBeInViewport()
})
