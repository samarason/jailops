import { test, expect, type Page } from '@playwright/test'

// Images from the console: the empty Images page, the Create image dialog with its build followed as an operation, a
// failed build and its retry, the install and create forms of a host without an image (`?demo=empty`,
// `?demo=noimage`), the nightly upgrade of an image (`?demo=nightlyfail` for a failed night) and the image of a new
// host release (`?demo=newrelease`). Runs on desktop and phone.

async function go(page: Page, demo: string, path: string): Promise<void> {
  await page.goto(`/?demo=${demo}`)
  await page.waitForSelector('.shell')
  await page.evaluate((p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')) }, path)
}

test('an empty Images page explains images and creates the base image', async ({ page }) => {
  await go(page, 'empty', '/images')
  const empty = page.getByTestId('images-empty')
  await expect(empty).toContainText('An image is the base system jails and apps start from')
  await empty.getByTestId('image-new-empty').click()
  const dialog = page.getByTestId('image-create')
  await expect(page.getByTestId('image-name')).toHaveValue('freebsd-15-1')
  await expect(page.getByTestId('image-release-choice')).toContainText('15.1-RELEASE (this host)')
  await expect(page.getByTestId('image-arch')).toHaveValue('amd64')
  await expect(page.getByTestId('image-alias')).toHaveCount(0)
  await expect(page.getByTestId('image-auto')).not.toBeChecked() // the nightly upgrade is the owner's choice
  await page.getByTestId('image-auto').check()
  await expect(page.getByTestId('image-at')).toHaveValue('03:00')
  await expect(page.getByTestId('image-packages')).toBeChecked()
  await expect(page.getByTestId('image-build')).toBeChecked()
  await expect(dialog).toContainText('takes a few minutes')

  // the release follows the server's rule, and nothing older than 15.1
  await page.getByTestId('image-release-choice').selectOption('other')
  await page.getByTestId('image-release').fill('14.3-RELEASE')
  await page.getByTestId('image-create-go').click({ force: true }) // aria-disabled: it names the problem and focuses it
  await expect(dialog).toContainText('JailOps supports FreeBSD 15.1 and later.')
  await expect(page.getByTestId('image-release')).toBeFocused()
  await page.getByTestId('image-release-choice').selectOption('host')

  await page.getByTestId('image-create-go').click()
  await expect(page.getByTestId('image-progress')).toBeVisible()
  await expect(page.getByTestId('image-progress')).toContainText('Building the first generation of freebsd-15-1')
  await expect(page.getByTestId('image-done')).toHaveText('The image freebsd-15-1 is ready.', { timeout: 15000 })
  await page.getByTestId('image-close').click()
  const img = page.locator('[data-image="freebsd-15-1"]')
  await expect(img.getByTestId('image-release')).toContainText('Release 15.1-RELEASE freebsd amd64 · 1 generation')
  await expect(img.getByTestId('auto-upgrade-on')).toBeChecked()
  await expect(img.getByTestId('auto-upgrade-next')).toContainText('Next run:')
  await expect(page.getByTestId('images-empty')).toHaveCount(0)
  await expect(page.getByTestId('image-new')).toBeVisible()
})

test('a failed build says what to check and is built again', async ({ page }) => {
  await go(page, 'empty', '/images')
  await page.getByTestId('image-new-empty').click()
  await page.getByTestId('image-name').fill('flaky')
  await page.getByTestId('image-create-go').click()
  await expect(page.getByTestId('image-failed')).toHaveText('The image flaky is defined, but its first generation was not built.', { timeout: 15000 })
  await expect(page.getByTestId('image-check')).toContainText('pkg.freebsd.org')
  await expect(page.getByTestId('image-name')).toBeDisabled()
  await page.getByTestId('image-retry').click()
  await expect(page.getByTestId('image-done')).toBeVisible({ timeout: 15000 })
})

test('the install dialog of a host without an image offers the base image', async ({ page }) => {
  await go(page, 'noimage', '/apps/nginx')
  await page.getByTestId('app-install').click()
  const note = page.getByTestId('install-no-image')
  await expect(note).toContainText('There is no image yet')
  await expect(page.getByTestId('install-go')).toHaveJSProperty('disabled', true)
  await expect(page.getByTestId('install-why')).toHaveText('Create the base image first.')
  await note.getByTestId('install-make-image').click()
  await expect(page.getByTestId('image-create')).toBeVisible()
  await page.getByTestId('image-create-go').click()
  await expect(page.getByTestId('image-done')).toBeVisible({ timeout: 15000 })
  await page.getByTestId('image-close').click()
  await expect(page.getByTestId('install-no-image')).toHaveCount(0)
  await expect(page.getByTestId('install-go')).toHaveJSProperty('disabled', false)
})

test('the jail form of a host without an image offers the base image', async ({ page }) => {
  await go(page, 'noimage', '/jails')
  await page.getByTestId('new-jail').click()
  await expect(page.getByTestId('jail-missing')).toContainText('There is no image to start from')
  await page.getByTestId('jail-make-image').click()
  await page.getByTestId('image-create-go').click()
  await expect(page.getByTestId('image-done')).toBeVisible({ timeout: 15000 })
  await page.getByTestId('image-close').click()
  await expect(page.locator('#jc-image')).toHaveValue('freebsd-15-1')
  await expect(page.locator('#jc-image option').first()).toHaveText('freebsd-15-1 (15.1-RELEASE)')
})

test('an image card turns the nightly upgrade on and off and shows its runs', async ({ page }) => {
  await go(page, 'x', '/images')
  const card = page.locator('[data-image="freebsd-15-1"]').getByTestId('auto-upgrade')
  await expect(card.getByTestId('auto-upgrade-on')).toBeChecked()
  await expect(card.getByTestId('auto-upgrade-summary')).toHaveText('Every night at 03:00 (host time), with the packages inside the jails.')
  await expect(card.getByTestId('auto-upgrade-runs').locator('tbody tr')).toHaveCount(3)
  await expect(card.getByTestId('auto-upgrade-runs')).toContainText('5 moved, 5 with packages upgraded')
  await expect(card.getByTestId('auto-upgrade-failed')).toHaveCount(0)

  // another time: Save appears, and the time is checked first
  await card.getByTestId('auto-upgrade-at').fill('04:30')
  await card.getByTestId('auto-upgrade-packages').uncheck()
  await card.getByTestId('auto-upgrade-save').click()
  await expect(card.getByTestId('auto-upgrade-summary')).toHaveText('Every night at 04:30 (host time).')
  await expect(card.getByTestId('auto-upgrade-save')).toHaveCount(0)

  // off: no next run, the runs stay
  await card.getByTestId('auto-upgrade-on').uncheck()
  await expect(card.getByTestId('auto-upgrade-at')).toHaveCount(0)
  await card.getByTestId('auto-upgrade-save').click()
  await expect(card).toHaveAttribute('data-enabled', 'false')
  await expect(card.getByTestId('auto-upgrade-next')).toHaveCount(0)
  await expect(card.getByTestId('auto-upgrade-runs')).toBeVisible()
  // the Linux image has none: nothing shows but the box
  await expect(page.locator('[data-image="alpine-3-22"]').getByTestId('auto-upgrade-on')).not.toBeChecked()
})

test('a failed night is shown plainly on the card', async ({ page }) => {
  await go(page, 'nightlyfail', '/images')
  const card = page.locator('[data-image="freebsd-15-1"]')
  const n = card.getByTestId('auto-upgrade-failed')
  await expect(n).toBeVisible()
  await expect(n).toHaveAttribute('role', 'alert')
  await expect(n).toContainText('The last nightly upgrade failed')
  await expect(n).toContainText('jail db: health check /usr/local/bin/check exited 1')
  await expect(card.getByTestId('auto-upgrade-runs').locator('tbody tr').first()).toContainText('Failed')
})

test('a host on a new release is offered its image, from Overview and from Images', async ({ page }) => {
  await go(page, 'newrelease', '/')
  const note = page.getByTestId('new-release')
  await expect(note).toContainText('This host runs FreeBSD 15.2-RELEASE')
  await expect(note).toContainText('A new release is a new image')
  await note.getByTestId('new-release-go').click()
  await expect(page).toHaveURL(/\/images/)
  const dialog = page.getByTestId('image-create')
  await expect(dialog).toBeVisible()
  await expect(page.getByTestId('image-name')).toHaveValue('freebsd-15-2')
  await expect(page.getByTestId('image-release-choice')).toContainText('15.2-RELEASE (this host)')
  await expect(page.getByTestId('image-auto')).not.toBeChecked()
  await page.getByTestId('image-create-go').click()
  await expect(page.getByTestId('image-done')).toHaveText('The image freebsd-15-2 is ready.', { timeout: 15000 })
  await page.getByTestId('image-close').click()
  // the image exists: the notice is gone, and apps get the new release first
  await expect(page.locator('[data-image="freebsd-15-2"]')).toBeVisible()
  await expect(page.getByTestId('new-release')).toHaveCount(0)
  await page.evaluate(() => { history.pushState({}, '', '/apps/nginx'); dispatchEvent(new PopStateEvent('popstate')) })
  await page.getByTestId('app-install').click()
  await expect(page.getByTestId('install-image')).toHaveValue('freebsd-15-2')
  await expect(page.getByTestId('install-image').locator('option')).toHaveText(['freebsd-15-2 (15.2-RELEASE)', 'freebsd-15-1 (15.1-RELEASE)'])
})

test('a generation shows the FreeBSD version of its packages, and the jail list its patch level', async ({ page }, info) => {
  await go(page, 'x', '/images')
  const versions = page.locator('[data-image="freebsd-15-1"]').getByTestId('generation-freebsd')
  await expect(versions).toHaveText(['15.1-RELEASE-p6', '15.1-RELEASE-p5', '15.1-RELEASE-p4', '15.1-RELEASE-p3'])
  await expect(page.locator('[data-image="alpine-3-22"]').getByTestId('generation-freebsd')).toHaveText(['-'])
  if (info.project.name === 'phone') return // the image column of the jail list is a desktop column
  await go(page, 'x', '/jails')
  await expect(page.locator('[data-jail="web"]').getByTestId('jail-generation')).toHaveText('#g4 · p6')
  await expect(page.locator('[data-jail="mail"]').getByTestId('jail-generation')).toHaveText('#g3 · p5')
})
