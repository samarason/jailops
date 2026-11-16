import { test, expect, type Page } from '@playwright/test'

// Backups of volumes in demo mode: a volume is a backup of its own, listed apart from the jails, restored as a new volume,
// and a policy can run without volumes.

async function open(page: Page, path: string): Promise<void> {
  await page.goto('/?demo')
  await page.waitForSelector('.shell')
  if (path !== '/') {
    await page.evaluate((p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')) }, path)
  }
  await page.waitForLoadState('networkidle')
}

test('a volume has its own group of backups, marked as a volume', async ({ page }) => {
  await open(page, '/backups')
  const group = page.locator('[data-jail="pgdata"][data-kind="volume"]')
  await expect(group).toContainText('volume')
  await expect(group.getByTestId('volume-backup')).toBeVisible()
  await expect(page.locator('[data-jail="web"][data-kind="jail"]')).toBeVisible()
})

test('a volume backup restores as a new volume and never over an existing one', async ({ page }) => {
  await open(page, '/backups')
  await page.locator('[data-backup="pgdata-20261021120000-f5a6b7c8"]').getByRole('button', { name: 'Restore' }).click()
  const real = page.getByTestId('restore-go')
  await expect(real).toBeDisabled()
  // a volume has no addresses, no networks and no replace
  await expect(page.getByLabel('Replace an existing jail of the same name')).toHaveCount(0)
  await expect(page.getByLabel('Keep the addresses in the bundle')).toHaveCount(0)
  await page.getByTestId('preflight-run').click()
  await expect(page.getByTestId('preflight')).toContainText('already exists')
  await expect(real).toBeDisabled()
  await page.getByLabel('Restore as (new name)').fill('pgdata-copy')
  await page.getByTestId('preflight-run').click()
  await expect(page.getByTestId('preflight')).toContainText('Preflight passed')
  await expect(page.getByTestId('preflight')).toContainText('creates volume pgdata-copy')
  await expect(real).toBeEnabled()
})

test('a jail restore can leave the missing volumes out', async ({ page }) => {
  await open(page, '/backups')
  await page.locator('[data-backup="db-20261021120000-44dd55ee"]').getByRole('button', { name: 'Restore' }).click()
  await expect(page.getByTestId('restore-no-volumes')).toBeVisible()
  await page.getByTestId('restore-no-volumes').check()
  await expect(page.getByTestId('restore-no-volumes')).toBeChecked()
})

test('a policy runs with or without its volumes', async ({ page }) => {
  await open(page, '/backups?tab=policies')
  const row = page.getByRole('row', { name: /nightly/ })
  await expect(row.getByRole('button', { name: 'Run now' })).toBeVisible()
  await row.getByTestId('run-no-volumes').click()
  await expect(page.locator('.toast').first()).toBeVisible()
})
