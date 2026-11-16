import { test, expect, type Page } from '@playwright/test'

// The certificate panel of the Host page in demo mode: the self-signed certificate, an upload with its checks, ACME
// with the terms checkbox (a wildcard is refused), the request turning valid, and the way back to self-signed.

const CERT = '-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUdemo\n-----END CERTIFICATE-----'
const KEY = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49demo\n-----END PRIVATE KEY-----'

async function open(page: Page): Promise<void> {
  await page.goto('/?demo')
  await page.waitForSelector('.shell')
  await page.evaluate(() => { history.pushState({}, '', '/host'); dispatchEvent(new PopStateEvent('popstate')) })
  await expect(page.getByTestId('cert-panel')).toBeVisible()
}

test('the panel shows the self-signed certificate and how clients pin it', async ({ page }) => {
  await open(page)
  await expect(page.getByTestId('cert-source')).toHaveText('Self-signed')
  await expect(page.getByTestId('cert-current')).toContainText('bsd01.example.net')
  await expect(page.getByTestId('cert-current')).toContainText('itself (self-signed)')
  await expect(page.locator('#copy-remote-add')).toHaveValue(/--fingerprint [0-9a-f]{64} --token-file -$/)
  await expect(page.getByTestId('cert-self')).toHaveCount(0)
})

test('an upload is checked, refused by the server with its reason, then used', async ({ page }) => {
  await open(page)
  await page.getByTestId('cert-upload').click()
  await page.getByTestId('cu-host').fill('')
  await page.getByTestId('cu-go').click()
  await expect(page.getByTestId('cu-cert')).toHaveAttribute('aria-invalid', 'true')
  await expect(page.getByTestId('cu-key')).toHaveAttribute('aria-invalid', 'true')
  await expect(page.getByRole('dialog')).toContainText('the name clients use to reach the console')
  await page.getByTestId('cu-cert').fill(CERT)
  await page.getByTestId('cu-key').fill(KEY.replace('demo', 'WRONGKEY'))
  await page.getByTestId('cu-host').fill('console.example.com')
  await page.getByTestId('cu-go').click()
  await expect(page.getByRole('dialog')).toContainText('the key does not match the certificate')
  await page.getByTestId('cu-key').fill(KEY)
  await page.getByTestId('cu-go').click()
  await expect(page.getByTestId('cert-source')).toHaveText('Uploaded')
  await expect(page.getByTestId('cert-current')).toContainText('console.example.com')
})

test('ACME needs the terms, refuses a wildcard, turns valid and needs no pin; self-signed again warns', async ({ page }) => {
  await open(page)
  await page.getByTestId('cert-acme-btn').click()
  await page.getByTestId('ca-domains').fill('*.example.com')
  await page.getByTestId('ca-go').click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toContainText('wildcard names need the dns-01 challenge')
  await expect(dialog).toContainText("agree to the CA's terms of service first")
  await expect(page.getByTestId('ca-terms')).toHaveAttribute('aria-invalid', 'true')
  await page.getByTestId('ca-domains').fill('console.example.com')
  await page.getByTestId('ca-email').fill('ops@example.com')
  await page.getByTestId('ca-staging').check()
  await expect(page.getByTestId('ca-directory')).toHaveText('https://acme-staging-v02.api.letsencrypt.org/directory')
  await page.getByTestId('ca-staging').uncheck()
  await page.getByTestId('ca-terms').check()
  await page.getByTestId('ca-go').click()
  await expect(page.getByTestId('cert-source')).toHaveText('ACME')
  await expect(page.getByTestId('acme-state')).toHaveText('Valid')
  await expect(page.getByTestId('cert-current')).toContainText('Signed by a CA the host trusts')
  await expect(page.getByTestId('acme-apply-fw')).toContainText('redirect port 80')
  await expect(page.locator('#copy-remote-add')).toHaveValue('jailops remote add bsd01 https://console.example.com:39110 --token-file -')

  await page.getByTestId('cert-self').click()
  await expect(page.getByTestId('self-warning')).toContainText('Browsers will warn again')
  await page.getByTestId('confirm').click()
  await expect(page.getByTestId('cert-source')).toHaveText('Self-signed')
})
