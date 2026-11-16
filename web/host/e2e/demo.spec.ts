import { test, expect, type Page } from '@playwright/test'

const routes = ['/', '/doctor', '/jails', '/jails/web', '/jails/mail', '/jails/vault', '/projects', '/projects/shop', '/storage', '/profiles', '/updates', '/images', '/apps', '/apps?tab=installed', '/apps/nginx', '/apps/postgresql', '/apps/isms', '/apps/nsd', '/apps/mail', '/apps/memcached', '/apps/wiki', '/jails/web?tab=logs', '/jails/build?tab=logs', '/networks', '/firewall', '/backups', '/hosts', '/operations', '/events', '/audit', '/access', '/host', '/networks/wireguard']

function watch(page: Page): string[] {
  const problems: string[] = []
  page.on('console', (m) => m.type() === 'error' && problems.push(m.text()))
  page.on('pageerror', (e) => problems.push(String(e)))
  return problems
}

async function open(page: Page, path: string): Promise<void> {
  await page.goto('/?demo')
  await page.waitForSelector('.shell')
  if (path !== '/') {
    await page.evaluate((p) => {
      history.pushState({}, '', p)
      dispatchEvent(new PopStateEvent('popstate'))
    }, path)
  }
  await page.waitForLoadState('networkidle')
}

for (const scheme of ['light', 'dark'] as const) {
  test.describe(scheme, () => {
    test.use({ colorScheme: scheme })
    for (const r of routes) {
      test(`${r}: renders without console errors or horizontal overflow`, async ({ page }, info) => {
        const problems = watch(page)
        await open(page, r)
        await expect(page.locator('main h1').first()).toBeVisible()
        const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
        expect(over, 'horizontal page overflow in px').toBeLessThanOrEqual(0)
        expect(problems).toEqual([])
        if (process.env.SHOTS) await page.screenshot({ path: `${process.env.SHOTS}/${info.project.name}-${scheme}-${r.replace(/\//g, '_') || '_'}.png`, fullPage: true })
      })
    }
  })
}

test('login view shows and signs in with a token', async ({ page }) => {
  const problems = watch(page)
  await page.goto('/?demo=login')
  await expect(page.getByRole('heading', { name: 'JailOps' })).toBeVisible()
  await page.getByLabel('Token').fill('jot_demo')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.locator('main h1')).toHaveText('Overview')
  expect(problems.filter((p) => !p.includes('401'))).toEqual([])
})

test('data rollback needs the jail name and shows the bytes at stake', async ({ page }) => {
  await open(page, '/jails/web')
  await page.getByRole('button', { name: 'Roll back' }).first().click()
  const go = page.getByTestId('rollback-go')
  await expect(go).toHaveAttribute('aria-disabled', 'false') // root scope
  await page.getByLabel(/^Data/).check()
  await expect(go).toHaveAttribute('aria-disabled', 'true')
  await expect(page.getByTestId('stake')).not.toHaveText('0 B')
  await page.getByLabel(/Type the jail name/).fill('wrong')
  await expect(go).toHaveAttribute('aria-disabled', 'true')
  await page.getByLabel(/Type the jail name/).fill('web')
  await expect(go).toHaveAttribute('aria-disabled', 'false')
  await go.click()
  await expect(page.locator('.toast').first()).toBeVisible()
})

test('restore wizard blocks the real restore until the preflight passes', async ({ page }) => {
  await open(page, '/backups')
  await page.locator('[data-backup="db-20261021120000-44dd55ee"]').getByRole('button', { name: 'Restore' }).click()
  const real = page.getByTestId('restore-go')
  await expect(real).toBeDisabled()
  await page.getByTestId('preflight-run').click()
  await expect(page.getByTestId('preflight')).toContainText('network dmz-old')
  await expect(real).toBeDisabled()
  await page.getByLabel('On the target: dmz-old').fill('backend')
  await page.getByLabel('Restore as (new name)').fill('db-restored')
  await page.getByTestId('preflight-run').click()
  await expect(page.getByTestId('preflight')).toContainText('Preflight passed')
  await expect(real).toBeEnabled()
})

test('a new token is shown once', async ({ page }) => {
  await open(page, '/access')
  await page.getByRole('tab', { name: 'API tokens' }).click()
  await page.getByRole('button', { name: 'New token' }).click()
  await page.locator('#nt-name').fill('e2e')
  // nothing red before an attempt; the reason sits next to the button, and a click shows it at the field
  await expect(page.getByTestId('scope-required')).toHaveCount(0)
  await expect(page.getByTestId('token-why')).toContainText('Choose at least one project')
  await page.getByRole('button', { name: 'Create token' }).click({ force: true })
  await expect(page.getByTestId('scope-required')).toBeVisible()
  await expect(page.locator('#nt-scope-first')).toBeFocused()
  await page.getByTestId('scope').getByLabel('web').check()
  await page.getByRole('button', { name: 'Create token' }).click()
  await expect(page.getByLabel('Name', { exact: true }).last()).toHaveValue(/^jot_/)
  await page.getByTestId('secret-done').click()
  await expect(page.getByText('jot_', { exact: false })).toHaveCount(0)
})

test('firewall validation errors from the API appear inline', async ({ page }) => {
  await open(page, '/firewall')
  await page.getByRole('button', { name: 'Add rule' }).click()
  await page.locator('[data-rule="3"]').getByLabel('Direction').selectOption('out')
  await page.locator('[data-rule="3"]').getByLabel('Port forward').check()
  // Save says why it does nothing yet, and a click still shows the field errors
  await expect(page.getByTestId('save-why')).toContainText('Fix the highlighted rules')
  await page.getByTestId('save-policy').click({ force: true })
  await expect(page.getByTestId('field-error').first()).toContainText('inbound')
})

test('the host console names itself and has no backup-node views', async ({ page }) => {
  await open(page, '/')
  await expect(page).toHaveTitle('Overview - JailOps host console')
  await expect(page.locator('.brand-side')).toContainText('host console')
  await expect(page.getByRole('link', { name: 'Maintenance' })).toHaveCount(0)
  await expect(page.getByRole('link', { name: 'Deletions' })).toHaveCount(0)
})

test('phone width: the menu opens and navigates', async ({ page }, info) => {
  test.skip(info.project.name !== 'phone')
  await open(page, '/')
  await page.getByRole('button', { name: 'Menu' }).click()
  await page.getByRole('link', { name: 'Jails' }).click()
  await expect(page.locator('main h1')).toHaveText('Jails')
})

test('doctor lists failing checks first with their hint', async ({ page }) => {
  await open(page, '/doctor')
  await expect(page.getByTestId('doctor-status')).toHaveText('Failing')
  await expect(page.locator('tbody tr').first()).toHaveAttribute('data-check', 'pf.anchor.mail')
  await expect(page.locator('[data-check="pf.anchor.mail"]')).toContainText('Fix the syntax error')
})

async function tabOf(page: Page, name: string): Promise<void> {
  await page.locator(`[data-tab="${name}"]`).click()
}

test('the project switcher scopes every project-level list and a cross-project id is plain not found', async ({ page }) => {
  await open(page, '/jails')
  await expect(page.getByTestId('project-select')).toHaveValue('web')
  await expect(page.locator('[data-test="jails-table"]')).not.toContainText('stg-web')
  await page.getByTestId('project-select').selectOption('staging')
  await expect(page.locator('[data-test="jails-table"]')).toContainText('stg-web')
  await expect(page.locator('[data-test="jails-table"]')).not.toContainText('mail')
  await expect(page.getByTestId('switcher-quota')).toBeVisible()
  await page.evaluate(() => { history.pushState({}, '', '/jails/mail'); dispatchEvent(new PopStateEvent('popstate')) })
  await expect(page.getByText('This jail does not exist.')).toBeVisible()
  await page.reload()
  await page.waitForSelector('.shell')
  await expect(page.getByTestId('project-select')).toHaveValue('staging')
})

test('projects: quotas with usage, whole-network grants, per-host state of a fleet project', async ({ page }) => {
  await open(page, '/projects/shop')
  await expect(page.locator('[data-quota="jails"]')).toBeVisible()
  await expect(page.locator('[data-section="networks"]')).toContainText('shop')
  await expect(page.locator('[data-section="networks"]')).not.toContainText('sub-range')
  await expect(page.locator('[data-section="storage"]')).toContainText('500G')
  await expect(page.getByTestId('mandatory-policy')).toHaveText('web-default')
  await expect(page.locator('[data-host="bsd02"]')).toContainText('Not applied')
  await expect(page.locator('[data-host="bsd03"]')).toContainText('Offline')
})

test('a project has several mandatory policies, shown in the order they are rendered', async ({ page }) => {
  await open(page, '/projects/shop')
  await page.getByTestId('edit-project').click()
  await expect(page.locator('#pf-fw')).toHaveValue('web-default')
  await page.locator('#pf-fw').fill('web-default, monitoring')
  await page.getByTestId('project-save').click()
  await expect(page.getByTestId('mandatory-policy')).toHaveText('web-default, monitoring')
})

test('creating a project can ask for a dedicated network', async ({ page }) => {
  await open(page, '/projects')
  await page.getByTestId('new-project').click()
  await page.locator('#pf-name').fill('lab')
  await page.getByTestId('new-network').check()
  await page.getByTestId('project-save').click()
  await expect(page.locator('[data-project="lab"]')).toBeVisible()
})

test('storage shows health, usage and which projects use it; a network shows the one project it belongs to', async ({ page }) => {
  await open(page, '/storage')
  await expect(page.locator('[data-storage="fast"]').getByTestId('health')).toHaveText('Degraded')
  await expect(page.locator('[data-storage="fast"]').getByTestId('storage-projects')).toContainText('shop')
  await open(page, '/networks')
  await expect(page.locator('[data-network="lan"]').getByTestId('net-projects')).toContainText('web')
  await expect(page.locator('[data-network="lan"]').locator('[data-holder]')).toHaveCount(1)
})

test('a trust token is shown once with the exact command; an identity needs a scope', async ({ page }) => {
  await open(page, '/access?tab=trust')
  await page.getByLabel('Client name').fill('laptop2')
  await expect(page.getByTestId('scope-required')).toHaveCount(0)
  await expect(page.getByTestId('trust-create')).toHaveAttribute('aria-disabled', 'true')
  await page.getByTestId('trust-create').click({ force: true })
  await expect(page.getByTestId('scope-required')).toBeVisible()
  await page.getByTestId('global-toggle').check()
  await expect(page.getByTestId('global-warning')).toBeVisible()
  await expect(page.getByTestId('trust-create')).toHaveAttribute('aria-disabled', 'false')
  await page.getByTestId('global-toggle').uncheck()
  await page.getByTestId('scope').getByLabel('shop').check()
  await page.getByTestId('trust-create').click()
  const cmd = page.getByLabel('command')
  await expect(cmd).toHaveValue(/^jailops remote add .+ --token jbc_/)
  await page.getByTestId('secret-done').click()
  await expect(page.getByLabel('command')).toHaveCount(0)
})

test('certificates show project and global badges and revoking needs the name', async ({ page }) => {
  await open(page, '/access')
  await tabOf(page, 'certs')
  await expect(page.locator('[data-cert="hub-client"]').getByTestId('global-badge')).toBeVisible()
  await expect(page.locator('[data-cert="laptop"]')).toContainText('shop')
  await expect(page.locator('[data-cert="stale-cert"]')).toContainText('no projects')
  await page.locator('[data-cert="laptop"]').getByTestId('cert-revoke').click()
  await expect(page.getByTestId('confirm')).toHaveAttribute('aria-disabled', 'true')
  await page.getByLabel(/Type the name/).fill('laptop')
  await expect(page.getByTestId('confirm')).toHaveAttribute('aria-disabled', 'false')
})

test('sessions can be revoked and whoami shows the scope', async ({ page }) => {
  await open(page, '/access')
  await tabOf(page, 'sessions')
  await page.locator('[data-session="ses-2"]').getByRole('button', { name: 'Revoke' }).click()
  await page.getByTestId('confirm').click()
  await expect(page.locator('[data-session="ses-2"]')).toHaveCount(0)
  await tabOf(page, 'whoami')
  await expect(page.getByTestId('whoami-panel')).toContainText('Global')
})

test('configuration: typed validation inline, restart badge, and a banner that says the jail was not restarted', async ({ page }) => {
  await open(page, '/jails/web')
  await tabOf(page, 'config')
  await expect(page.locator('[data-key="limits.cpu"]').getByTestId('restart-badge')).toBeVisible()
  await expect(page.locator('[data-key="limits.pids"]')).toBeVisible()
  await page.locator('[data-key="limits.memory"] input').fill('lots')
  await expect(page.locator('[data-key="limits.memory"]').getByTestId('config-error')).toBeVisible()
  await page.locator('[data-key="limits.memory"] input').fill('4G')
  await page.locator('[data-key="limits.cpu"] input').fill('4')
  await page.locator('[data-key="limits.disk"] input').fill('30G')
  await page.locator('[data-key="shell"] input').fill('/usr/local/bin/bash')
  await page.getByTestId('config-save').click()
  const banner = page.getByTestId('restart-banner')
  await expect(banner).toContainText('NOT restarted')
  await expect(banner).toContainText('limits.cpu')
  await expect(banner).not.toContainText('limits.disk')
  await expect(page.getByTestId('restart-now')).toBeVisible()
})

test('configuration: an invalid value from the server is shown, nothing is saved silently', async ({ page }) => {
  await open(page, '/jails/web')
  await tabOf(page, 'config')
  await page.locator('[data-key="nic.eth0.mtu"] input').fill('20')
  await page.getByTestId('config-save').click()
  await expect(page.getByTestId('error-panel')).toContainText('between 576 and 9216')
})

test('devices show which profile each value comes from', async ({ page }) => {
  await open(page, '/jails/web')
  await tabOf(page, 'devices')
  await expect(page.locator('[data-device="nic.eth0"]')).toContainText('1500')
  await expect(page.locator('[data-device="nic.eth0"] [data-field="nic.eth0.mtu"]').getByTestId('origin')).toContainText('this jail')
  await expect(page.locator('[data-kind="disk"]')).toContainText('content')
})

test('profiles: unknown keys are refused inline', async ({ page }) => {
  await open(page, '/profiles')
  await expect(page.locator('[data-profile="web-limits"]')).toBeVisible()
  await page.getByTestId('new-profile').click()
  await page.locator('#pr-name').fill('mine')
  await page.getByLabel('Key').first().fill('bogus.key')
  await expect(page.getByTestId('profile-issue')).toBeVisible()
  await expect(page.getByTestId('profile-save')).toHaveAttribute('aria-disabled', 'true')
  await page.getByLabel('Key').first().fill('limits.cpu')
  await page.getByLabel('Value').first().fill('2')
  await expect(page.getByTestId('profile-save')).toHaveAttribute('aria-disabled', 'false')
})

test('console: opens a shell, types and shows output', async ({ page }) => {
  await open(page, '/jails/web')
  await tabOf(page, 'console')
  await page.getByTestId('exec-open').click()
  await expect(page.getByTestId('terminal')).toContainText('JailOps demo shell')
  await page.getByTestId('terminal').click()
  await page.keyboard.type('hostname')
  await page.keyboard.press('Enter')
  await expect(page.getByTestId('terminal')).toContainText('web.example.net')
  await page.getByTestId('exec-copy').click()
})

test('updates: apply is blocked until the dry-run preview has run', async ({ page }) => {
  await open(page, '/jails/web')
  await tabOf(page, 'updates')
  await expect(page.getByTestId('available')).toContainText('2 packages')
  await expect(page.getByTestId('history')).toContainText('Rolled back')
  await page.getByTestId('update-apply').click()
  await expect(page.getByTestId('update-go')).toBeDisabled()
  await page.getByTestId('update-preview').click()
  await expect(page.getByTestId('update-plan')).toContainText('snapshot')
  await expect(page.getByTestId('update-go')).toBeEnabled()
})

test('fleet updates: batch apply per project needs the project name', async ({ page }) => {
  await open(page, '/updates')
  await expect(page.locator('[data-jail="web"]')).toContainText('packages')
  await page.getByTestId('apply-project').click()
  await expect(page.getByTestId('batch-go')).toBeDisabled()
  await page.getByLabel(/Type the project name/).fill('web')
  await expect(page.getByTestId('batch-go')).toBeEnabled()
})

test('provisioning panel shows the declaration and whether it completed', async ({ page }) => {
  await open(page, '/jails/mail')
  await expect(page.getByTestId('provision-state')).toContainText('has not completed')
  await open(page, '/jails/web')
  await expect(page.getByTestId('provision-state')).toContainText('completed')
  await expect(page.getByTestId('provision-panel')).toContainText('templates/nginx.conf')
})

test('backup key: status, create shows the recovery key once, the dialog cannot close without confirming', async ({ page }) => {
  await open(page, '/backups')
  await page.getByRole('tab', { name: 'Backup key' }).click()
  await expect(page.getByTestId('key-status')).toHaveText('Key present')
  await expect(page.getByTestId('key-loss')).toContainText('Losing the key means losing every backup')
  await page.getByTestId('key-escrow').click()
  await expect(page.getByTestId('key-status')).toHaveText('Key escrowed')
})

test('backup run and verify go through the async flow', async ({ page }) => {
  await open(page, '/backups')
  await page.getByRole('tab', { name: 'Policies' }).click()
  await page.getByRole('button', { name: 'Run now' }).first().click()
  await expect(page.locator('.toast').first()).toBeVisible()
})

test('a first visit has no project: the project pages say so and nothing project-level is requested', async ({ page }) => {
  const problems = watch(page)
  const projectLevel: string[] = []
  page.on('request', (r) => { if (/\/api\/v1\/(jails|profiles|firewall|updates)/.test(r.url())) projectLevel.push(r.url()) })
  await page.goto('/?demo=fresh')
  await page.waitForSelector('.shell')
  await page.evaluate(() => { history.pushState({}, '', '/jails'); dispatchEvent(new PopStateEvent('popstate')) })
  await expect(page.getByTestId('no-project')).toBeVisible()
  await expect(page.getByTestId('project-select')).toHaveValue('')
  await page.getByTestId('project-select').selectOption('web')
  await expect(page.locator('[data-test="jails-table"]')).toContainText('mail')
  await page.reload()
  await page.waitForSelector('.shell')
  await expect(page.getByTestId('project-select')).toHaveValue('web')
  expect(problems.filter((p) => !p.includes('400'))).toEqual([])
})

test('a network cannot be granted to a second project', async ({ page }) => {
  await open(page, '/projects/staging')
  await page.getByTestId('edit-project').click()
  await page.getByRole('button', { name: 'Grant a network' }).click()
  await page.locator('.grant-row:not(.grant-sto)').last().locator('select').selectOption('lan')
  await page.getByTestId('project-save').click()
  await expect(page.getByText(/already granted to project web/).first()).toBeVisible()
})

test('first run on an empty host: the console guides storage, project, image, jail and creates a jail', async ({ page }) => {
  const problems = watch(page)
  await page.goto('/?demo=empty')
  await page.waitForSelector('.shell')
  const gs = page.getByTestId('getting-started')
  await expect(gs).toBeVisible()
  await expect(gs.locator('[data-step]')).toHaveCount(4)
  await expect(gs.locator('[data-done="true"]')).toHaveCount(0)
  // storage, then a project, through the normal pages
  await page.goto('/storage?demo=empty')
  await page.getByTestId('new-storage').click()
  await page.getByLabel('Name').fill('default')
  await page.getByLabel(/Dataset/).fill('tank/jailops')
  await expect(page.getByLabel(/encrypt/i)).toHaveCount(0) // encrypted storage is not implemented: not offered
  expect(problems.filter((p) => !p.includes('400'))).toEqual([])
})

test('create jail form validates the name and explains what is missing', async ({ page }) => {
  await open(page, '/jails')
  await page.getByTestId('new-jail').click()
  await page.locator('#jc-name').fill('Bad Name')
  await page.locator('#jc-name').blur()
  await expect(page.getByRole('alert')).toContainText('Lowercase letters, digits and hyphens')
  await expect(page.getByTestId('jail-create-go')).toHaveAttribute('aria-disabled', 'true')
  await page.locator('#jc-name').fill('newjail')
  await expect(page.getByTestId('jail-create-go')).toHaveAttribute('aria-disabled', 'false')
  await page.getByTestId('jail-create-go').click()
  await expect(page.locator('[data-test="jails-table"]')).toContainText('newjail')
})

test('IPv6 addresses are compressed, copyable and the network mode is a badge', async ({ page }) => {
  await open(page, '/networks')
  await expect(page.locator('[data-network="edge"] [data-ipv6-mode="proxy"]')).toBeVisible()
  await expect(page.locator('[data-network="lan"]').getByRole('button', { name: /^Copy 2001:db8:20:1::\/80$/ })).toBeVisible()
})

test('network form: proxy mode explains itself, validates inline and creates the network', async ({ page }) => {
  await open(page, '/networks')
  await page.getByTestId('new-network').click()
  await page.getByTestId('net-create-go').click({ force: true })
  await expect(page.locator('#nf-name-e')).toContainText('Required')
  await page.locator('#nf-name').fill('dmz')
  await page.locator('#nf-v4s').fill('10.99.0.0/24')
  await expect(page.locator('#nf-v4g')).toHaveValue('10.99.0.1') // suggested
  await page.locator('#nf-v4g').fill('10.50.0.1')
  await page.locator('#nf-v4g').blur()
  await page.getByTestId('net-create-go').click({ force: true })
  await expect(page.locator('#nf-v4g-e')).toContainText('inside the subnet')
  await page.locator('#nf-v4g').fill('10.99.0.1')
  await page.getByTestId('nf-mode').selectOption('proxy')
  await expect(page.getByTestId('mode-help')).toContainText('pf.conf')
  await page.locator('#nf-v6s').fill('2001:db8:77::/64')
  await page.locator('#nf-v6r').fill('2001:db8:77::100-2001:db8:77::1ff')
  await page.getByTestId('net-create-go').click({ force: true })
  await expect(page.locator('#nf-up-e')).toContainText('uplink')
  await page.locator('#nf-up').fill('em1')
  await page.getByTestId('net-create-go').click({ force: true })
  await expect(page.locator('[data-network="dmz"] [data-ipv6-mode="proxy"]')).toBeVisible()
})

test('phone: the jail spec table has no clipped column', async ({ page, isMobile }) => {
  test.skip(!isMobile, 'phone only')
  await open(page, '/jails/web')
  const t = page.getByTestId('spec-status')
  const box = await t.boundingBox()
  expect(await t.evaluate((el) => el.parentElement!.scrollWidth - el.parentElement!.clientWidth)).toBeLessThanOrEqual(0)
  expect(box!.width).toBeLessThanOrEqual(page.viewportSize()!.width)
})
