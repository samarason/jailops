import { test, expect, type Page } from '@playwright/test'

// The app catalog, the installation and the jail log viewer, in demo mode.

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

test('the store filters by search and category and shows an invalid definition with its reason', async ({ page }) => {
  const problems = watch(page)
  await open(page, '/apps')
  const cards = page.locator('[data-test="app-grid"] [data-app]')
  await expect(cards).toHaveCount(10)
  await expect(page.locator('[data-app="wiki"]')).toContainText('Invalid')
  await expect(page.locator('[data-app="wiki"]').getByTestId('invalid-reason')).toContainText('base system')
  await expect(page.locator('[data-app="wiki"]').getByRole('button', { name: 'Install' })).toHaveCount(0)
  await expect(page.locator('[data-app="nginx"]')).toContainText('80/tcp')
  // a definition of the host's own directory carries the local chip, the packaged ones do not
  await expect(page.locator('[data-app="memcached"]').getByTestId('app-local')).toHaveText('local')
  await expect(page.locator('[data-app="nginx"]').getByTestId('app-local')).toHaveCount(0)
  await expect(page.locator('[data-app="memcached"]')).toContainText('11211/tcp')

  await page.locator('[data-category="database"]').click()
  await expect(page.locator('[data-category="database"]')).toHaveAttribute('aria-pressed', 'true')
  await expect(cards).toHaveCount(3)
  await expect(page.locator('[data-app="postgresql"]')).toBeVisible()
  await page.getByTestId('apps-search').fill('key-value')
  await expect(cards).toHaveCount(1)
  await expect(page.locator('[data-app="valkey"]')).toBeVisible()
  await page.getByTestId('apps-search').fill('nothing matches this')
  await expect(page.getByTestId('apps-nomatch')).toBeVisible()
  await page.getByRole('button', { name: 'Clear the search' }).click()
  await expect(cards).toHaveCount(10)
  // DNS on UDP and TCP; the categories added with nsd and isms
  await page.locator('[data-category="network"]').click()
  await expect(cards).toHaveCount(1)
  await expect(page.locator('[data-app="nsd"]')).toContainText('53/udp')
  await expect(page.locator('[data-app="nsd"]')).toContainText('53/tcp')
  await page.locator('[data-category="security"]').click()
  await expect(cards).toHaveCount(1)
  await expect(page.locator('[data-app="isms"]')).toContainText('Security')
  await page.locator('[data-category="security"]').click()
  await expect(cards).toHaveCount(10)

  // the card is a link to the detail, reachable by keyboard
  await page.locator('[data-app="forgejo"] a').focus()
  await page.keyboard.press('Enter')
  await expect(page.locator('main h1')).toHaveText('Forgejo')
  await expect(page.locator('[data-section="ports"]')).toContainText('3000/tcp')
  await expect(page.getByTestId('homepage')).toHaveAttribute('rel', /noopener/)
  expect(problems).toEqual([])
})

test('install end to end: preview the steps, install, success report, listed under Installed', async ({ page }) => {
  const problems = watch(page)
  await open(page, '/apps/valkey')
  await page.getByTestId('app-install').click()
  const dialog = page.getByTestId('install-dialog')
  await expect(page.locator('#inst-jail')).toHaveValue('valkey')
  await expect(page.locator('#inst-mem')).toHaveValue('512M')
  await page.locator('#inst-jail').fill('Bad Name')
  await expect(dialog.getByRole('alert')).toContainText('Lowercase letters, digits and hyphens')
  await expect(page.getByTestId('install-go')).toHaveAttribute('aria-disabled', 'true')
  await expect(page.getByTestId('install-why')).toContainText('Lowercase')
  await page.locator('#inst-jail').fill('web')
  await expect(dialog.getByRole('alert')).toContainText('exists')
  await page.locator('#inst-jail').fill('cache-kv')
  // the project has several networks: one must be chosen
  await page.locator('#inst-net').selectOption('lan')
  await page.getByTestId('install-preview').click()
  const plan = page.getByTestId('install-plan')
  await expect(plan).toContainText('create-jail')
  await expect(plan).toContainText('pkg -r')
  await expect(plan).toContainText('health-check')
  await expect(plan.locator('li').nth(-2)).toContainText('app-installed')
  await expect(plan.locator('li').last()).toContainText('enable-autostart')

  await page.getByTestId('install-go').click()
  await expect(page.getByTestId('install-steps')).toBeVisible()
  await expect(page.getByTestId('install-steps').locator('[data-state="running"]')).toHaveCount(1)
  await expect(page.getByTestId('install-ok')).toContainText('installed as jail cache-kv', { timeout: 15_000 })
  await expect(page.getByTestId('install-steps').locator('[data-state="done"]')).toHaveCount(await page.getByTestId('install-steps').locator('li').count())
  await expect(page.getByTestId('install-ports')).toContainText(':6379')
  await expect(page.getByTestId('install-rollback')).toContainText('app-installed')
  await expect(page.getByLabel('Rollback command')).toHaveValue('jailops jail rollback cache-kv --all --snapshot app-installed')
  await page.getByTestId('install-close').click()

  await expect(page.getByTestId('installed-as')).toContainText('cache-kv')
  // the demo keeps its state for the page's lifetime: navigate inside the console, do not reload
  await page.getByRole('link', { name: 'All apps' }).click()
  await page.locator('[data-tab="installed"]').click()
  const row = page.locator('[data-installed="cache-kv"]')
  await expect(row).toContainText('Valkey')
  await expect(row).toContainText('9.1.2')
  await expect(row.locator('[data-state="running"]')).toBeVisible()
  // nginx's exposed http port is linked on the jail's first address, in a new tab
  const openLink = page.locator('[data-installed="web"]').getByTestId('open-web')
  await expect(openLink).toHaveAttribute('href', 'http://10.20.0.11/')
  await expect(openLink).toHaveAttribute('target', '_blank')
  await expect(openLink).toHaveAttribute('rel', /noopener/)
  await expect(page.locator('[data-installed="db"]')).toContainText('definition changed')
  expect(problems).toEqual([])
})

test('isms comes from the jailops repository and is not started, so its plan has no health check', async ({ page }) => {
  const problems = watch(page)
  await open(page, '/apps/isms')
  await expect(page.locator('main h1')).toHaveText('isms')
  await expect(page.locator('[data-section="ports"]')).toContainText('8080/tcp')
  await page.getByTestId('app-install').click()
  await page.locator('#inst-net').selectOption('lan')
  await page.getByTestId('install-preview').click()
  const plan = page.getByTestId('install-plan')
  await expect(plan).toContainText('install-packages-jailops')
  await expect(plan).toContainText('install -y -r jailops isms')
  await expect(plan).not.toContainText('start-service')
  await expect(plan).not.toContainText('health-check')
  await expect(plan.locator('li').nth(-2)).toContainText('app-installed')
  await expect(plan.locator('li').last()).toContainText('enable-autostart')
  expect(problems).toEqual([])
})

test('a failed installation reports the step and the kept jail', async ({ page }) => {
  await open(page, '/apps/nginx')
  await page.getByTestId('app-install').click()
  await page.locator('#inst-jail').fill('fail-web')
  await page.locator('#inst-net').selectOption('lan')
  await page.getByTestId('install-go').click()
  await expect(page.getByTestId('error-panel')).toContainText('health-check', { timeout: 15_000 })
  await expect(page.getByTestId('error-hint')).toContainText('stopped for inspection')
  await expect(page.getByTestId('install-kept')).toContainText('fail-web')
  await expect(page.getByTestId('install-steps').locator('[data-state="failed"]')).toContainText('health-check')
  await page.getByTestId('install-kept').getByRole('link').click()
  await expect(page.locator('main h1')).toHaveText('fail-web')
})

test('jail logs: list, tail, grep, follow appends lines, controls stay inert', async ({ page }) => {
  const problems = watch(page)
  await open(page, '/jails/web')
  await page.locator('[data-tab="logs"]').click()
  const files = page.getByTestId('log-files')
  await expect(files.locator('[data-file="messages"]')).toContainText('active')
  await expect(files.locator('[data-file="messages.0"]')).toContainText('rotated')
  await expect(files.locator('[data-file="messages.1.gz"]')).toBeDisabled()
  await expect(files).toContainText('Compressed copies cannot be read')
  const view = page.getByTestId('log-view')
  await expect(view).toHaveAttribute('role', 'log')
  await expect(view).toHaveAttribute('aria-live', 'off')
  await expect(page.getByTestId('log-count')).toContainText('200 lines')

  await page.getByTestId('log-tail').selectOption('100')
  await expect(page.getByTestId('log-count')).toContainText('100 lines')
  await page.getByTestId('log-grep').fill('checkpoint')
  await page.getByTestId('log-apply').click()
  await expect(view.locator('.log-t').first()).toContainText('checkpoint')
  for (const t of await view.locator('.log-t').allTextContents()) expect(t.toLowerCase()).toContain('checkpoint')
  await page.getByTestId('log-grep').fill('')
  await page.getByTestId('log-apply').click()

  // the daemon log carries an ANSI colour sequence and a bell: shown as plain text
  await files.locator('[data-file="daemon.log"]').click()
  await expect(view).toContainText('level=WARN')
  expect(await view.evaluate((el) => /[\x00-\x08\x0b-\x1f\x7f-\x9f]/.test(el.textContent ?? ''))).toBe(false)

  await files.locator('[data-file="nginx/access.log"]').click()
  await expect(view).toContainText('GET /')
  const before = await view.locator('.log-t').count()
  await page.getByTestId('log-follow').click()
  await expect(page.getByTestId('log-follow')).toHaveAttribute('aria-pressed', 'true')
  await expect.poll(async () => view.locator('.log-t').count(), { timeout: 10_000 }).toBeGreaterThan(before)
  // scrolled away from the end, new lines are counted on the jump button
  await view.evaluate((el) => { el.scrollTop = 0; el.dispatchEvent(new Event('scroll')) })
  await expect(page.getByTestId('log-new')).toBeVisible({ timeout: 10_000 })
  await page.getByTestId('log-jump').click()
  await expect(page.getByTestId('log-jump')).toHaveCount(0)
  await page.getByTestId('log-follow').click()
  await expect(page.getByTestId('log-follow')).toHaveAttribute('aria-pressed', 'false')
  expect(problems).toEqual([])
})

test('jail logs: a stopped jail is not mounted and the hint says how to mount it', async ({ page }) => {
  await open(page, '/jails/build?tab=logs')
  await expect(page.getByTestId('logs-not-mounted')).toBeVisible()
  await expect(page.getByTestId('error-hint')).toContainText('zfs mount')
})

test('an app detail links its log files to the log viewer of the jail it is installed as', async ({ page }) => {
  await open(page, '/apps/nginx')
  await expect(page.getByTestId('installed-as')).toContainText('web')
  await page.locator('[data-log="access"]').getByTestId('open-log').click()
  await expect(page.locator('main h1')).toHaveText('web')
  await expect(page.locator('[data-file="nginx/access.log"]')).toHaveAttribute('aria-current', 'true')
  await expect(page.getByTestId('log-view')).toContainText('HTTP/1.1')
})

test('a local definition says so on its page', async ({ page }) => {
  const problems = watch(page)
  await open(page, '/apps/memcached')
  await expect(page.locator('main h1')).toHaveText('memcached')
  await expect(page.getByTestId('app-local')).toHaveText('local')
  await expect(page.getByTestId('app-local')).toHaveAttribute('title', /apps\.local_dir/)
  await open(page, '/apps/nginx')
  await expect(page.locator('main h1')).toHaveText('nginx')
  await expect(page.getByTestId('app-local')).toHaveCount(0)
  expect(problems).toEqual([])
})
