import { test, expect, type Page } from '@playwright/test'

// Getting to a jail and into its shell fast: the quick switcher, labels on jails, and the Shell buttons, on the
// demo server, at desktop and phone width.

async function open(page: Page, path: string): Promise<void> {
  await page.goto('/?demo')
  await page.waitForSelector('.shell')
  if (path !== '/') await page.evaluate((p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')) }, path)
  await page.waitForLoadState('networkidle')
}
const switcher = (page: Page) => page.getByTestId('quick-switcher')
const input = (page: Page) => page.getByTestId('qs-input')

/** Waits until the results stopped changing (the list is ranked after a short pause: a read right after typing may see the old one). */
async function settled(page: Page): Promise<void> {
  let prev = ''
  for (let i = 0; i < 40; i++) {
    const cur = (await page.locator('[role="option"]').evaluateAll((els) => els.map((e) => e.getAttribute('data-qs')))).join(',')
    if (cur && cur === prev) return
    prev = cur
    await page.waitForTimeout(150)
  }
}

/** The search button of the layout in view: the side bar on a desktop, the top bar on a phone. */
async function searchButton(page: Page) {
  const side = page.getByTestId('search-open-side')
  return (await side.isVisible()) ? side : page.getByTestId('search-open-top')
}

test('Ctrl+K opens the switcher; type, arrows, Enter go to the jail; Escape gives the focus back', async ({ page }) => {
  await open(page, '/jails')
  const btn = await searchButton(page)
  await btn.focus()
  await page.keyboard.press('Control+k')
  await expect(switcher(page)).toBeVisible()
  await expect(input(page)).toBeFocused()
  await expect(switcher(page)).toHaveAttribute('role', 'dialog')
  await input(page).fill('wor')
  await expect(page.locator('[role="option"][aria-selected="true"]')).toHaveAttribute('data-qs', 'jail:web:worker')
  await expect(page.getByTestId('qs-status')).toHaveText(/\d+ results?/)
  await page.keyboard.press('Escape')
  await expect(switcher(page)).toHaveCount(0)
  await expect(btn).toBeFocused()

  // `/` outside a text field opens it too; the arrows move the active option and Enter opens it
  await page.locator('main h1').click()
  await page.keyboard.press('/')
  await expect(input(page)).toBeFocused()
  await input(page).fill('team=data')
  const opts = page.locator('[role="option"]')
  await settled(page)
  await expect(opts.first()).toHaveAttribute('aria-selected', 'true')
  await page.keyboard.press('ArrowDown')
  await expect(opts.nth(1)).toHaveAttribute('aria-selected', 'true')
  const id = await opts.nth(1).getAttribute('data-qs')
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(new RegExp(`/jails/${id!.split(':')[2]}$`))
  await expect(page.locator('main h1')).toHaveText(id!.split(':')[2])

  // the box opens on what was opened last
  await page.keyboard.press('Control+k')
  await expect(page.locator('[role="option"]').first()).toHaveAttribute('data-qs', id!)
})

test('the search button opens it on a touch screen; a tap on Shell opens the jail connected', async ({ page }) => {
  await open(page, '/')
  await (await searchButton(page)).click()
  await input(page).fill('api')
  const row = page.locator('[role="option"][data-qs="jail:web:api"]')
  await expect(row).toBeVisible()
  await row.locator('[data-act="shell"]').click()
  await expect(page).toHaveURL(/\/jails\/api\?tab=console$/)
  await expect(page.getByTestId('terminal')).toContainText('JailOps demo shell')
  await expect(page.getByTestId('exec-tab')).toContainText('Connected')
})

test('Shift+Enter starts a stopped jail and opens its shell once it runs', async ({ page }) => {
  await open(page, '/jails')
  await page.keyboard.press('Control+k')
  await input(page).fill('build')
  await expect(page.locator('[role="option"][aria-selected="true"]')).toHaveAttribute('data-qs', 'jail:web:build')
  await page.keyboard.press('Shift+Enter')
  await expect(page).toHaveURL(/\/jails\/build\?tab=console$/)
  await expect(page.getByTestId('terminal')).toContainText('JailOps demo shell', { timeout: 15000 })
  await expect(page.locator('main h1 + [data-state]')).toHaveAttribute('data-state', 'running')
})

test('/jails/NAME/shell is a shareable link to a connected shell, with the command line beside it', async ({ page }) => {
  await open(page, '/jails/web/shell')
  await expect(page).toHaveURL(/\/jails\/web\?tab=console$/)
  await expect(page.getByTestId('terminal')).toContainText('JailOps demo shell')
  await expect(page.getByTestId('exec-shell')).toContainText('/bin/sh as root')
  await expect(page.getByTestId('exec-cli-cmd')).toHaveText('jailops shell web --project web')
  await page.getByTestId('terminal').click()
  await page.keyboard.type('hostname')
  await page.keyboard.press('Enter')
  await expect(page.getByTestId('terminal')).toContainText('web.example.net')
  // a reload does not open a second session by itself: the request was taken off the address
  await page.reload()
  await page.waitForSelector('.shell')
  await expect(page.getByTestId('exec-open')).toBeVisible()
  // the jail remembers its tab: the list's link opens it on the console again
  await open(page, '/jails/web')
  await expect(page).toHaveURL(/\/jails\/web\?tab=console$/)
})

test('the Shell button of a list row and of the jail page', async ({ page }) => {
  await open(page, '/jails')
  await page.locator('a[data-shell="db"]').click()
  await expect(page).toHaveURL(/\/jails\/db\?tab=console$/)
  await expect(page.getByTestId('exec-tab')).toContainText('Connected')
  await page.getByTestId('exec-close').click()
  await page.getByRole('tab', { name: 'Overview' }).click()
  await page.getByTestId('jail-shell').click()
  await expect(page).toHaveURL(/\/jails\/db\?tab=console$/)
  await expect(page.getByTestId('exec-tab')).toContainText('Connected')
  // a stopped jail offers Start and open shell
  await open(page, '/jails/search')
  await expect(page.getByTestId('jail-shell')).toHaveText('Start and open shell')
  await page.getByTestId('jail-shell').click()
  await expect(page.getByTestId('exec-waiting').or(page.getByTestId('terminal').filter({ hasText: 'JailOps demo shell' }))).toBeVisible()
  await expect(page.getByTestId('terminal')).toContainText('JailOps demo shell', { timeout: 15000 })
})

test('labels: add and remove on the jail page, a chip filters the list, the filter is in the address', async ({ page }) => {
  await open(page, '/jails/build')
  const box = page.getByTestId('jail-labels')
  await expect(box.locator('[data-label="env=dev"]')).toBeVisible()
  await page.getByTestId('labels-edit').click()
  await page.getByTestId('label-key').fill('Bad key')
  // aria-disabled while something is missing: a click explains instead of doing nothing
  await page.getByTestId('label-add').click({ force: true })
  await expect(page.locator('#lbl-key-err')).toContainText("Letters, digits, '-', '_' and '.'")
  await expect(page.getByTestId('label-key')).toBeFocused()
  await page.getByTestId('label-key').fill('tier')
  await page.getByTestId('label-value').fill('edge')
  await page.getByTestId('label-add').click()
  await expect(page.getByTestId('labels-editor').locator('[data-label="tier=edge"]')).toBeVisible()
  await expect(page.getByTestId('labels-status')).toContainText('tier=edge')
  await page.getByRole('button', { name: 'Remove label env=dev' }).click()
  await expect(page.getByTestId('labels-editor').locator('[data-label="env=dev"]')).toHaveCount(0)
  await page.getByTestId('labels-done').click()
  await box.locator('button[data-label="tier=edge"]').click()
  await expect(page).toHaveURL(/\/jails\?q=tier(%3D|=)edge$/)
  await expect(page.locator('[data-test="jails-table"] tbody tr')).toHaveCount(1)
  await expect(page.locator('[data-jail="build"]')).toBeVisible()
  await expect(page.getByTestId('filter-count')).toHaveText('1 of 13 jails')

  // the address is the filter: a link with -key=value and key: works, and the back button undoes a chip
  await open(page, '/jails?q=' + encodeURIComponent('env=prod -team=web'))
  await expect(page.getByTestId('jails-filter')).toHaveValue('env=prod -team=web')
  await expect(page.locator('[data-jail="db"]')).toBeVisible()
  await expect(page.locator('[data-jail="web"]')).toHaveCount(0)
  await expect(page.getByTestId('filter-terms').locator('[data-term]')).toHaveCount(2)
  await page.locator('[data-jail="db"] button[data-label="team=data"]').click()
  await expect(page).toHaveURL(/team(%3D|=)data/)
  await expect(page.locator('[data-test="jails-table"] tbody tr')).toHaveCount(2)
  await page.goBack()
  await expect(page.getByTestId('jails-filter')).toHaveValue('env=prod -team=web')
  await page.getByTestId('filter-clear').click()
  await expect(page.locator('[data-test="jails-table"] tbody tr')).toHaveCount(13)

  // typing suggests keys and values; the last filter comes back on a bare /jails
  await page.getByTestId('jails-filter').fill('')
  await page.getByTestId('jails-filter').pressSequentially('ap')
  await expect(page.getByTestId('filter-suggestions')).toContainText('app=')
  await page.keyboard.press('ArrowDown')
  await page.keyboard.press('Enter')
  await expect(page.getByTestId('jails-filter')).toHaveValue('app=')
  await page.locator('[data-sugg="app=nginx"]').click()
  await expect(page).toHaveURL(/q=app(%3D|=)nginx/)
  await expect(page.locator('[data-test="jails-table"] tbody tr')).toHaveCount(2)
  await open(page, '/jails')
  await expect(page.getByTestId('jails-filter')).toHaveValue('app=nginx')
})

test('bulk labels: set one on the selected jails, then remove it again', async ({ page }) => {
  await open(page, '/jails')
  await page.getByLabel('Select git').check()
  await page.getByLabel('Select worker').check()
  await page.getByTestId('bulk-labels').click()
  const dlg = page.getByRole('dialog')
  await expect(dlg).toContainText('Labels of 2 jails')
  await page.getByTestId('bl-key').fill('backup')
  await page.getByTestId('bl-value').fill('nightly')
  await expect(page.getByTestId('bl-apply')).toHaveText('Set backup=nightly on 2 jails')
  await page.getByTestId('bl-apply').click()
  await expect(dlg).toHaveCount(0)
  // the demo keeps its data in the page: filter in place instead of loading the address again
  await page.getByTestId('jails-filter').fill('backup=nightly')
  await page.getByTestId('jails-filter').press('Enter')
  await expect(page.locator('[data-test="jails-table"] tbody tr')).toHaveCount(2)
  await page.getByLabel('Select all shown').check()
  await page.getByTestId('bulk-labels').click()
  await page.getByTestId('bl-remove').check()
  await page.getByTestId('bl-drop').selectOption('backup')
  await page.getByTestId('bl-apply').click()
  await expect(page.getByTestId('jails-table')).toHaveCount(0, { timeout: 10000 })
  await expect(page.locator('main')).toContainText('No jails match.')
})

test('a phone keeps the switcher and the filtered list inside the screen', async ({ page }, info) => {
  test.skip(info.project.name !== 'phone', 'phone layout')
  await open(page, '/jails?q=env%3Dprod')
  const over = () => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(await over()).toBeLessThanOrEqual(0)
  await page.getByTestId('search-open-top').click()
  await input(page).fill('web')
  const vw = page.viewportSize()!.width
  for (const el of await page.locator('[role="option"] [data-act]').all()) {
    const b = (await el.boundingBox())!
    expect(b.x + b.width).toBeLessThanOrEqual(vw)
    expect(b.height).toBeGreaterThanOrEqual(36)
  }
  expect(await over()).toBeLessThanOrEqual(0)
})
