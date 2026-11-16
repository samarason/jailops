import { test, expect, type Page } from '@playwright/test'

// The firewall test page: the form, each kind of answer, the flow, the address of a result, the copy button. Demo mode;
// the demo walks its own policies like the server walks the rendered anchor (web-default is the project's mandatory
// policy, db-internal is the database's, mail-edge has a raw PF fragment).

async function open(page: Page, path: string): Promise<void> {
  await page.goto('/?demo')
  await page.waitForSelector('.shell')
  await page.evaluate((p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')) }, path)
  await page.waitForLoadState('networkidle')
}

async function ask(page: Page, from: string, to: string, port: string): Promise<void> {
  await page.getByTestId('fwtest-from').fill(from)
  await page.getByTestId('fwtest-to').fill(to)
  await page.getByTestId('fwtest-port').fill(port)
  await page.getByTestId('fwtest-run').click()
  await expect(page.getByTestId('fwtest-result')).toBeVisible()
}

const verdict = (page: Page) => page.getByTestId('verdict-word')

test('the Test tab is next to policies and address sets, and an empty form asks for the two ends', async ({ page }) => {
  await open(page, '/firewall')
  await page.locator('[data-tab="test"]').click()
  await expect(page).toHaveURL(/tab=test/)
  await expect(page.getByTestId('fwtest-form')).toBeVisible()
  await page.getByTestId('fwtest-run').click()
  await expect(page.getByText('Name where the connection starts and where it goes.').first()).toBeVisible()
  await expect(page.getByText('tcp and udp need a port.')).toBeVisible()
  await expect(page.getByTestId('fwtest-result')).toHaveCount(0)
  // a wrong end is said as you type
  await page.getByTestId('fwtest-from').fill('10.20.0')
  await expect(page.getByText('A jail (jail:web), one address, or host.').first()).toBeVisible()
  await page.getByTestId('fwtest-port').fill('70000')
  await expect(page.getByText('The port is 1 to 65535.')).toBeVisible()
})

test('a connection that passes: the rule that lets it in is named', async ({ page }) => {
  await open(page, '/firewall?tab=test')
  await ask(page, 'jail:web', 'jail:db', '5432')
  await expect(verdict(page)).toHaveText('PASS')
  const to = page.getByTestId('hop-destination').first()
  await expect(to).toContainText('PASS')
  await expect(to).toContainText('policy db-internal, rule 1: postgres from web')
  await expect(page.getByTestId('hop-source').first()).toContainText('the default of the anchor')
  await expect(page.getByTestId('node-to').first()).toContainText('Goes to')
  // IPv4 and IPv6 are two cases
  await expect(page.getByTestId('case-4')).toBeVisible()
  await expect(page.getByTestId('case-6')).toBeVisible()
  // the question is in the address, and the command is the same question
  await expect(page).toHaveURL(/from=jail%3Aweb|from=jail:web/)
  await expect(page.locator('#copy-Command')).toHaveValue('jailops firewall test --from jail:web --to jail:db --port 5432')
})

test('blocked by the default of the anchor, and the stop is drawn', async ({ page }) => {
  await open(page, '/firewall?tab=test')
  await ask(page, 'jail:web', 'jail:db', '5433')
  await expect(verdict(page)).toHaveText('BLOCK')
  await expect(page.getByTestId('hop-destination').first()).toContainText('BLOCK')
  await expect(page.getByTestId('hop-destination').first()).toContainText('the default of the anchor')
  await expect(page.getByTestId('node-to').first()).toContainText('Not reached')
})

test('a deny rule wins over the allow rule of the same jail, and the rule passed over is listed', async ({ page }) => {
  await open(page, '/firewall?tab=test')
  await ask(page, '192.0.2.66', 'jail:web', '80')
  await expect(verdict(page)).toHaveText('BLOCK')
  const hop = page.getByTestId('hop-destination').first()
  await expect(hop).toContainText('rule 4: a scanner that kept coming back')
  await hop.getByText('Details').click()
  await expect(page.getByTestId('skipped').first()).toContainText('a deny rule wins over every allow rule')
  await expect(page.getByTestId('skipped').first()).toContainText('rule 1')
  // the same address on another port is not the scanner's business
  await page.getByTestId('fwtest-port').fill('443')
  await page.getByTestId('fwtest-run').click()
  await expect(verdict(page)).toHaveText('PASS')
})

test('a rule that is switched off lets nothing through, and the test says it was passed over', async ({ page }) => {
  await open(page, '/firewall?tab=test')
  await ask(page, '192.0.2.7', 'jail:web', '21')
  await expect(verdict(page)).toHaveText('BLOCK')
  const hop = page.getByTestId('hop-destination').first()
  await expect(hop).toContainText('the default of the anchor')
  await hop.getByText('Details').click()
  await expect(page.getByTestId('skipped').first()).toContainText('the rule is switched off')
})

test('a raw PF fragment: the test cannot say, and does not guess', async ({ page }) => {
  await open(page, '/firewall?tab=test')
  await ask(page, 'jail:web', 'jail:mail', '26')
  await expect(verdict(page)).toHaveText('CANNOT SAY')
  await expect(page.getByTestId('hop-destination').first()).toContainText('raw PF fragment')
  await expect(page.getByTestId('fwtest-caveats')).toContainText('new connection')
})

test('a ping is tested as an echo request, and the answer says so', async ({ page }) => {
  await open(page, '/firewall?tab=test')
  await page.getByTestId('fwtest-from').fill('jail:web')
  await page.getByTestId('fwtest-to').fill('jail:db')
  await page.getByTestId('fwtest-proto').selectOption('icmp')
  await expect(page.getByTestId('fwtest-port')).toHaveCount(0)
  await expect(page.getByTestId('fwtest-icmp')).toBeVisible()
  await page.getByTestId('fwtest-run').click()
  await expect(page.getByTestId('fwtest-result')).toBeVisible()
  await expect(page.getByTestId('fwtest-caveats')).toContainText('echo request')
  await expect(page.locator('#copy-Command')).toHaveValue('jailops firewall test --from jail:web --to jail:db --proto icmp')
})

test('a jail that does not exist is an error in the usual place', async ({ page }) => {
  await open(page, '/firewall?tab=test')
  await page.getByTestId('fwtest-from').fill('jail:nobody')
  await page.getByTestId('fwtest-to').fill('jail:db')
  await page.getByTestId('fwtest-port').fill('5432')
  await page.getByTestId('fwtest-run').click()
  await expect(page.getByTestId('error-panel')).toContainText('jail "nobody" not found')
  await expect(page.getByTestId('fwtest-result')).toHaveCount(0)
})

test('a link to a result asks at once, and swap turns the question round', async ({ page }) => {
  await open(page, '/firewall/test?from=jail:web&to=jail:db&port=5432')
  await expect(page).toHaveURL(/\/firewall\?/)
  await expect(page.getByTestId('fwtest-from')).toHaveValue('jail:web')
  await expect(verdict(page)).toHaveText('PASS')
  await page.getByTestId('fwtest-swap').click()
  await expect(page.getByTestId('fwtest-from')).toHaveValue('jail:db')
  await expect(page.getByTestId('fwtest-to')).toHaveValue('jail:web')
  // the form changed since the answer: the page says so until it is asked again
  await expect(page.getByTestId('fwtest-stale')).toBeVisible()
  await page.getByTestId('fwtest-run').click()
  await expect(page.getByTestId('fwtest-stale')).toHaveCount(0)
})

test('the flow lies across on a desktop and down on a phone, nothing runs off the page', async ({ page }) => {
  await open(page, '/firewall?tab=test&from=jail:web&to=jail:db&port=5432')
  await expect(verdict(page)).toHaveText('PASS')
  const boxes = await page.locator('[data-test="case-4"] .ft-flow > li:not(.ft-arrow)').evaluateAll((els) => els.map((e) => { const r = e.getBoundingClientRect(); return { x: r.x, y: r.y } }))
  expect(boxes).toHaveLength(4)
  const wide = (page.viewportSize()?.width ?? 0) > 800
  if (wide) expect(new Set(boxes.map((b) => Math.round(b.y))).size).toBe(1)
  else for (let i = 1; i < boxes.length; i++) expect(boxes[i].y).toBeGreaterThan(boxes[i - 1].y)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
})

test('the page is usable by keyboard: Enter in a field runs the test', async ({ page }) => {
  await open(page, '/firewall?tab=test')
  await page.getByTestId('fwtest-from').fill('jail:web')
  await page.getByTestId('fwtest-to').fill('jail:db')
  await page.getByTestId('fwtest-port').fill('5432')
  await page.getByTestId('fwtest-port').press('Enter')
  await expect(verdict(page)).toHaveText('PASS')
  await expect(page.getByTestId('fwtest-verdict')).toBeFocused()
})
