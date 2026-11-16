import { test, expect, type Page } from '@playwright/test'
import { audit } from '../../shared/a11y'

// Volumes in demo mode: the list, a volume's page, attach and detach on a jail's page, and the create dialog.

async function open(page: Page, path: string): Promise<void> {
  await page.goto('/?demo')
  await page.waitForSelector('.shell')
  if (path !== '/') {
    await page.evaluate((p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')) }, path)
  }
  await page.waitForLoadState('networkidle')
}

test('the list shows what attaches each volume and warns about two writers', async ({ page }) => {
  await open(page, '/volumes')
  await expect(page.locator('[data-volume="pgdata"]')).toContainText('db')
  await expect(page.locator('[data-volume="archive"]')).toContainText('No jail')
  await expect(page.locator('[data-volume="secrets"]')).toContainText('Locked')
})

test('a volume is attached to a stopped jail and detached again, and a running one is refused', async ({ page }) => {
  await open(page, '/jails/build')
  await page.getByTestId('attach-volume-open').click()
  const dlg = page.getByRole('dialog')
  await dlg.getByTestId('attach-volume').selectOption('archive')
  await dlg.getByTestId('attach-mount').fill('/srv/archive')
  expect(await audit(page)).toEqual([])
  await dlg.getByTestId('attach-go').click()
  await expect(page.locator('[data-volume="archive"]')).toContainText('/srv/archive')
  await page.locator('[data-detach="archive"]').click()
  await page.getByRole('dialog').getByTestId('confirm').click()
  await expect(page.locator('[data-volume="archive"]')).toHaveCount(0)
  await open(page, '/jails/web')
  await expect(page.getByTestId('attach-volume-open')).toBeDisabled()
})

test('a snapshot is taken, and a volume that is attached is not deleted', async ({ page }) => {
  await open(page, '/volumes/pgdata')
  await page.getByTestId('volume-snapshot').click()
  await page.getByTestId('vs-name').fill('before-move')
  await page.getByTestId('vs-go').click()
  await expect(page.locator('[data-snapshot="before-move"]')).toBeVisible()
  await page.getByTestId('volume-delete').click()
  await page.getByRole('dialog').locator('input').fill('pgdata')
  await page.getByTestId('confirm').click()
  await expect(page.getByTestId('error-panel').getByText(/attached to db/)).toBeVisible()
})

test('phone: the volumes list has no clipped column', async ({ page, isMobile }) => {
  test.skip(!isMobile, 'phone only')
  await open(page, '/volumes')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
})

test('a directory of the host shows its path and state, and a lost mount is called out', async ({ page }) => {
  await open(page, '/volumes')
  await expect(page.locator('[data-volume="storagebox"]')).toContainText('/mnt/storagebox/backups')
  await expect(page.locator('[data-volume="storagebox"]')).toContainText('Host directory')
  await expect(page.locator('[data-volume="office-nas"]')).toContainText('Lost')
  await open(page, '/volumes/office-nas')
  await expect(page.getByTestId('lost-callout')).toContainText('/mnt/office-nas/share')
  await expect(page.getByTestId('hostdir-overview')).toContainText('the directory is not on a mount')
  // a directory has no snapshots, and deleting it forgets the volume without destroying anything
  await expect(page.getByTestId('volume-snapshot')).toHaveCount(0)
  await page.getByTestId('volume-delete').click()
  await expect(page.getByRole('dialog')).toContainText('left as they are')
  expect(await audit(page)).toEqual([])
})

test('a volume of a host directory is made with a path and a watch', async ({ page }) => {
  await open(page, '/volumes')
  await page.getByTestId('new-volume').click()
  const dlg = page.getByRole('dialog')
  await dlg.getByTestId('vc-name').fill('storage2')
  await dlg.getByTestId('vc-hostdir').check()
  await expect(dlg.getByTestId('vc-uid')).toHaveCount(0)
  await expect(dlg.getByTestId('vc-encrypted')).toHaveCount(0)
  await dlg.getByTestId('vc-path').fill('not-a-path')
  await dlg.getByTestId('vc-path').blur()
  await expect(dlg.locator('#vc-path-e')).toContainText('absolute path')
  await dlg.getByTestId('vc-path').fill('/mnt/storage2/data')
  await dlg.getByTestId('vc-watch').check()
  await dlg.getByTestId('vc-onloss').selectOption('stop')
  expect(await audit(page)).toEqual([])
  await dlg.getByTestId('volume-create-go').click()
  await expect(page.locator('[data-volume="storage2"]')).toContainText('/mnt/storage2/data')
  await page.locator('[data-volume="storage2"] a').first().click()
  await expect(page.getByTestId('hostdir-overview')).toContainText('on loss: Stop the running jails')
})

test('a directory of the host is attached without the copy option', async ({ page }) => {
  await open(page, '/jails/build')
  await page.getByTestId('attach-volume-open').click()
  const dlg = page.getByRole('dialog')
  await dlg.getByTestId('attach-volume').selectOption('office-nas')
  await expect(dlg.getByTestId('attach-copy')).toHaveCount(0)
  await dlg.getByTestId('attach-mount').fill('/srv/share')
  await dlg.getByTestId('attach-go').click()
  await expect(page.locator('[data-volume="office-nas"]')).toContainText('/srv/share')
})
