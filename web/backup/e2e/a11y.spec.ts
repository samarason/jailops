import { test, expect } from '@playwright/test'
import { audit } from '../../shared/a11y'

const routes = ['/', '/hosts', '/snapshots', '/deletions', '/retention', '/maintenance', '/audit', '/access']

for (const scheme of ['light', 'dark'] as const) {
  test.describe(`a11y ${scheme}`, () => {
    test.use({ colorScheme: scheme })
    for (const r of routes) {
      test(`${r}: names, labels, ids, landmarks and AA contrast`, async ({ page }) => {
        await page.goto('/?demo')
        await page.waitForSelector('.shell')
        if (r !== '/') await page.evaluate((p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')) }, r)
        await page.waitForLoadState('networkidle')
        await expect(page.locator('main h1').first()).toBeVisible()
        expect(await audit(page)).toEqual([])
      })
    }
  })
}

// Dialogs: the retention policy form (after a submit attempt, so its messages are on screen), host enrolment and a
// typed confirmation.
const dialogs: Array<[string, string, string[]]> = [
  ['/retention', 'add policy', ['[data-test="add-policy"]', 'force:[data-test="policy-save"]']],
  ['/hosts', 'enrol', ['[data-test="enrol"]']],
  ['/maintenance', 'mode', ['[data-mode="offline"]']],
  ['/access?tab=tokens', 'tokens tab', []],
]
for (const scheme of ['light', 'dark'] as const) {
  for (const [r, name, clicks] of dialogs) {
    test(`a11y ${scheme}: ${r} ${name}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme })
      await page.goto('/?demo')
      await page.waitForSelector('.shell')
      await page.evaluate((p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')) }, r)
      await page.waitForLoadState('networkidle')
      for (const c of clicks) await page.locator(c.replace(/^force:/, '')).first().click({ force: c.startsWith('force:') })
      expect(await audit(page)).toEqual([])
    })
  }
}
