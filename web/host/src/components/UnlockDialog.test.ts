import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import UnlockDialog from './UnlockDialog.vue'
import PassphraseDialog from './PassphraseDialog.vue'
import { Client, getClient, setClient, type RawRequest, type Transport } from '@jailops/shared/api/client'
import { POLL_MS } from '@jailops/shared/composables/ops'
import { demoTransport } from '@/demo/transport'
import { demoVaultPassphrase } from '@/demo/data'

const WRONG = 'wrong-marker-passphrase'

/** The demo server, recording every request it is sent. */
function recorded(): { sent: RawRequest[] } {
  const inner = demoTransport({ speed: 1000 })
  const sent: RawRequest[] = []
  const t: Transport = { request: (r) => { sent.push(r); return inner.request(r) }, stream: (p, h) => inner.stream(p, h) }
  const c = new Client(t)
  c.setRequestFilter((p) => p + (p.includes('?') ? '&' : '?') + 'project=web')
  setClient(c)
  return { sent }
}

/** Let the pending promises and timers run, and wait until `until` holds (up to twenty seconds: a loaded CI machine is slow). */
async function settle(until?: () => boolean): Promise<void> {
  const deadline = Date.now() + 20000
  for (let i = 0; i < 20 || (until && !until() && Date.now() < deadline); i++) {
    await flushPromises()
    await new Promise((r) => setTimeout(r, 5))
  }
}

describe('UnlockDialog', () => {
  const before = getClient()
  const poll = POLL_MS.value
  beforeEach(() => {
    POLL_MS.value = 1
    localStorage.clear()
    sessionStorage.clear()
  })
  afterEach(() => {
    setClient(before)
    POLL_MS.value = poll
  })

  it('hides the passphrase until asked, never echoes it and clears it', async () => {
    const { sent } = recorded()
    const w = mount(UnlockDialog, { props: { open: true, volume: 'secrets' }, global: { stubs: { Teleport: true } } })
    await w.vm.$nextTick()
    const input = () => w.get('[data-test="unlock-pass"]')
    expect(input().attributes('type')).toBe('password')
    expect(input().attributes('autocomplete')).toBe('off')
    await w.get('[data-test="unlock-show"]').trigger('click')
    expect(input().attributes('type')).toBe('text')
    expect(w.get('[data-test="unlock-show"]').attributes('aria-label')).toBe('Hide the passphrase')
    await w.get('[data-test="unlock-show"]').trigger('click')

    await input().setValue(WRONG)
    await w.get('form').trigger('submit')
    await settle(() => w.find('[data-test="unlock-error"]').exists())
    expect(w.get('[data-test="unlock-error"]').text()).toBe('The passphrase is not correct.')
    expect(w.html()).not.toContain(WRONG)
    expect((input().element as HTMLInputElement).value).toBe('')
    const body = sent.find((r) => r.path.includes('/unlock'))?.body
    expect(body).toEqual({ passphrase: WRONG })
    expect(w.emitted('done')).toBeFalsy()

    await input().setValue(demoVaultPassphrase)
    await w.get('[data-test="unlock-start"]').setValue(true)
    await w.get('form').trigger('submit')
    await settle(() => !!w.emitted('done'))
    expect(sent.filter((r) => r.path.includes('/unlock')).at(-1)?.body).toEqual({ passphrase: demoVaultPassphrase, start: true })
    expect(w.emitted('done')).toBeTruthy()
    expect(w.emitted('close')).toBeTruthy()
    for (const r of sent) expect(r.path).not.toContain(demoVaultPassphrase)
    expect(sent.find((r) => r.path.includes('/unlock'))?.path).toBe('/volumes/secrets/unlock?project=web')
    const stored = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage })
    expect(stored).not.toContain(demoVaultPassphrase)
    expect(stored).not.toContain(WRONG)
  })

  it('forgets a typed passphrase when the dialog closes', async () => {
    recorded()
    const w = mount(UnlockDialog, { props: { open: true, volume: 'secrets' }, global: { stubs: { Teleport: true } } })
    await w.get('[data-test="unlock-pass"]').setValue('typed-but-not-sent')
    await w.setProps({ open: false })
    await w.setProps({ open: true })
    expect((w.get('[data-test="unlock-pass"]').element as HTMLInputElement).value).toBe('')
    expect(w.html()).not.toContain('typed-but-not-sent')
  })

  it('shows the lockout hint after five wrong passphrases', async () => {
    recorded()
    const w = mount(UnlockDialog, { props: { open: true, volume: 'secrets' }, global: { stubs: { Teleport: true } } })
    for (let i = 0; i < 6; i++) {
      await w.get('[data-test="unlock-pass"]').setValue(WRONG)
      await w.get('form').trigger('submit')
      await settle(() => i < 5 || (w.find('[data-test="unlock-error"]').exists() && w.get('[data-test="unlock-error"]').text().includes('Too many')))
    }
    const t = w.get('[data-test="unlock-error"]').text()
    expect(t).toContain('Too many wrong passphrases')
    expect(t).toMatch(/wait \d+s/)
    expect(t).not.toContain(WRONG)
  })
})

describe('PassphraseDialog', () => {
  const before = getClient()
  afterEach(() => setClient(before))
  it('checks length and match before sending, and sends old and new once', async () => {
    POLL_MS.value = 1
    const { sent } = recorded()
    const w = mount(PassphraseDialog, { props: { open: true, volume: 'secrets' }, global: { stubs: { Teleport: true } } })
    await w.get('#pc-old').setValue(demoVaultPassphrase)
    await w.get('#pc-new').setValue('short')
    expect(w.get('[data-test="pass-error"]').text()).toBe('Use at least 12 characters.')
    await w.get('#pc-new').setValue('a-new-long-passphrase')
    await w.get('#pc-again').setValue('a-new-long-passphrasX')
    expect(w.get('[data-test="pass-go"]').attributes('disabled')).toBeDefined()
    await w.get('#pc-again').setValue('a-new-long-passphrase')
    await w.get('form').trigger('submit')
    await settle()
    // the demo volume is locked: the host refuses, and nothing typed is shown back
    expect(sent.find((r) => r.path.includes('/passphrase'))?.body).toEqual({ old_passphrase: demoVaultPassphrase, new_passphrase: 'a-new-long-passphrase' })
    expect(w.html()).not.toContain('a-new-long-passphrase')
    expect((w.get('#pc-old').element as HTMLInputElement).value).toBe('')
  })
})
