import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import ImageCreateDialog from './ImageCreateDialog.vue'
import { Client, getClient, setClient, type RawRequest, type Transport } from '@jailops/shared/api/client'
import { POLL_MS } from '@jailops/shared/composables/ops'
import { session } from '@jailops/shared/composables/session'
import { demoTransport } from '@/demo/transport'
import { server } from '@/demo/data'

/** The demo server, recording every request it is sent. */
function recorded(): { sent: RawRequest[] } {
  const inner = demoTransport({ speed: 1000 })
  const sent: RawRequest[] = []
  const t: Transport = { request: (r) => { sent.push(r); return inner.request(r) }, stream: (p, h) => inner.stream(p, h) }
  setClient(new Client(t))
  return { sent }
}

async function settle(until?: () => boolean): Promise<void> {
  const deadline = Date.now() + 20000
  for (let i = 0; i < 20 || (until && !until() && Date.now() < deadline); i++) {
    await flushPromises()
    await new Promise((r) => setTimeout(r, 5))
  }
}

/** The changing requests, as METHOD path. */
const writes = (sent: RawRequest[]) => sent.filter((r) => r.method !== 'GET').map((r) => `${r.method} ${r.path}`)

describe('ImageCreateDialog', () => {
  const before = getClient()
  const poll = POLL_MS.value
  const info = session.info
  beforeEach(() => {
    POLL_MS.value = 1
    session.info = { ...server(), environment: { ...server().environment, kernel_version: '15.1-RELEASE-p2' } }
  })
  afterEach(() => {
    setClient(before)
    POLL_MS.value = poll
    session.info = info
  })

  // the dialog is teleported to the body, as in the browser (a stubbed Teleport would remount its fields)
  let mounted: VueWrapper | null = null
  afterEach(() => { mounted?.unmount(); mounted = null })
  async function open() {
    const v = mount(ImageCreateDialog, { props: { open: false }, attachTo: document.body })
    mounted = v
    await v.setProps({ open: true })
    await settle()
    const body = new DOMWrapper(document.body)
    return {
      get: (sel: string) => body.get(sel),
      find: (sel: string) => body.find(sel),
      text: () => body.get('[data-test="image-create"]').text() + ' ' + (body.find('.modal footer').exists() ? body.get('.modal footer').text() : ''),
      emitted: (e: string) => v.emitted(e),
    }
  }
  const phase = (w: Awaited<ReturnType<typeof open>>) => w.get('[data-test="image-create"]').attributes('data-phase')

  it('proposes the base image of this host and checks names and releases as the server does', async () => {
    recorded()
    const w = await open()
    expect((w.get('[data-test="image-name"]').element as HTMLInputElement).value).toBe('freebsd-15-1')
    expect(w.get('[data-test="image-release-choice"]').text()).toContain('15.1-RELEASE (this host)')
    expect(w.get('[data-test="image-arch"]').attributes('readonly')).toBeDefined()
    expect((w.get('[data-test="image-arch"]').element as HTMLInputElement).value).toBe('amd64')
    expect(w.find('[data-test="image-alias"]').exists()).toBe(false)
    expect((w.get('[data-test="image-build"]').element as HTMLInputElement).checked).toBe(true)
    // the nightly upgrade is the owner's choice: off until the box is ticked, then at 03:00, with the packages
    expect((w.get('[data-test="image-auto"]').element as HTMLInputElement).checked).toBe(false)
    await w.get('[data-test="image-auto"]').setValue(true)
    expect((w.get('[data-test="image-at"]').element as HTMLInputElement).value).toBe('03:00')
    expect((w.get('[data-test="image-packages"]').element as HTMLInputElement).checked).toBe(true)

    // a name that exists, a name against the rule, a release older than 15.1
    await w.get('[data-test="image-name"]').setValue('freebsd-15-1')
    await w.get('[data-test="image-name"]').trigger('blur')
    expect(w.text()).toContain('An image named freebsd-15-1 exists already.')
    await w.get('[data-test="image-name"]').setValue('Base')
    expect(w.text()).toContain('Lowercase letters, digits and hyphens')
    await w.get('[data-test="image-name"]').setValue('base')
    await w.get('[data-test="image-release-choice"]').setValue('other')
    await w.get('[data-test="image-release"]').setValue('14.3-RELEASE')
    await w.get('form').trigger('submit')
    await settle()
    expect(w.text()).toContain('JailOps supports FreeBSD 15.1 and later.')
    expect(w.get('[data-test="image-create-why"]').text()).toContain('Release: JailOps supports FreeBSD 15.1 and later.')
    expect(w.get('[data-test="image-create-go"]').attributes('aria-disabled')).toBe('true')
    expect(phase(w)).toBe('idle')
  })

  it('creates the definition, then builds it, and follows the build', async () => {
    const { sent } = recorded()
    const w = await open()
    await w.get('[data-test="image-name"]').setValue('base')
    await w.get('form').trigger('submit')
    await settle(() => phase(w) === 'done')
    expect(phase(w)).toBe('done')
    expect(writes(sent)).toEqual(['POST /images', 'POST /images/base/generations'])
    expect(sent.find((r) => r.method === 'POST' && r.path === '/images')?.body).toEqual({
      metadata: { name: 'base' }, spec: { os: 'freebsd', release: '15.1-RELEASE', arch: 'amd64', source: { type: 'pkgbase' } },
    })
    expect(w.get('[data-test="image-done"]').text()).toBe('The image base is ready.')
    expect(w.emitted('done')).toEqual([['base']])
  })

  it('keeps the definition when the build fails and builds it again on Try again', async () => {
    const { sent } = recorded()
    const w = await open()
    await w.get('[data-test="image-name"]').setValue('flaky-base')
    await w.get('form').trigger('submit')
    await settle(() => phase(w) === 'failed')
    expect(w.get('[data-test="image-failed"]').text()).toBe('The image flaky-base is defined, but its first generation was not built.')
    expect(w.get('[data-test="image-check"]').text()).toContain('pkg.freebsd.org')
    expect(w.text()).toContain('No address record')
    // the fields are kept as they were, read-only: the definition exists
    expect(w.get('[data-test="image-fields"]').attributes('disabled')).toBeDefined()
    expect(w.get('[data-test="image-retry"]').text()).toBe('Try again')
    await w.get('form').trigger('submit')
    await settle(() => phase(w) === 'done')
    expect(writes(sent)).toEqual(['POST /images', 'POST /images/flaky-base/generations', 'POST /images/flaky-base/generations'])
    expect(w.emitted('done')).toEqual([['flaky-base']])
  })

  it('creates the definition only when the build is left for later', async () => {
    const { sent } = recorded()
    const w = await open()
    await w.get('[data-test="image-name"]').setValue('later')
    await w.get('[data-test="image-build"]').setValue(false)
    expect(w.get('[data-test="image-create-go"]').text()).toBe('Create')
    await w.get('form').trigger('submit')
    await settle(() => phase(w) === 'done')
    expect(writes(sent)).toEqual(['POST /images'])
    expect(w.get('[data-test="image-done"]').text()).toContain('The image later is defined.')
  })

  it('offers the Linux images the API creates, with their own release rules', async () => {
    const { sent } = recorded()
    const w = await open()
    await w.get('[data-test="image-kind"]').setValue('alpine')
    expect((w.get('[data-test="image-name"]').element as HTMLInputElement).value).toBe('alpine-3-22')
    expect((w.get('[data-test="image-release"]').element as HTMLInputElement).value).toBe('3.22')
    expect((w.get('[data-test="image-auto"]').element as HTMLInputElement).checked).toBe(false)
    await w.get('[data-test="image-release"]').setValue('15.1-RELEASE')
    await w.get('[data-test="image-build"]').setValue(false)
    await w.get('form').trigger('submit')
    await settle()
    expect(w.text()).toContain('An Alpine release such as 3.22 or 3.22.1.')
    await w.get('[data-test="image-kind"]').setValue('debian')
    expect((w.get('[data-test="image-release"]').element as HTMLInputElement).value).toBe('trixie')
    expect(w.text()).toContain('The path of the keyring on the host')
    await w.get('[data-test="image-keys"]').setValue('/usr/local/share/keyrings/debian-archive-keyring.gpg')
    await w.get('form').trigger('submit')
    await settle(() => phase(w) === 'done')
    expect(sent.find((r) => r.method === 'POST' && r.path === '/images')?.body).toEqual({
      metadata: { name: 'debian-trixie' }, spec: { os: 'linux', release: 'trixie', arch: 'amd64', source: { type: 'debootstrap', keys: '/usr/local/share/keyrings/debian-archive-keyring.gpg' } },
    })
  })

  it('names the image after the release until the name is edited', async () => {
    recorded()
    const w = await open()
    const name = () => (w.get('[data-test="image-name"]').element as HTMLInputElement).value
    await w.get('[data-test="image-release-choice"]').setValue('other')
    await w.get('[data-test="image-release"]').setValue('15.2-RELEASE')
    expect(name()).toBe('freebsd-15-2')
    await w.get('[data-test="image-release"]').setValue('16.0-RELEASE')
    expect(name()).toBe('freebsd-16-0')
    await w.get('[data-test="image-name"]').setValue('mine')
    await w.get('[data-test="image-release"]').setValue('15.2-RELEASE')
    expect(name()).toBe('mine')
  })

  it('sends the nightly upgrade as chosen, and checks its time', async () => {
    const { sent } = recorded()
    const w = await open()
    await w.get('[data-test="image-name"]').setValue('nightly')
    await w.get('[data-test="image-auto"]').setValue(true)
    await w.get('[data-test="image-build"]').setValue(false)
    await w.get('[data-test="image-at"]').setValue('')
    await w.get('form').trigger('submit')
    await settle()
    expect(w.get('[data-test="image-create-why"]').text()).toContain('Time (host time): Required.')
    expect(phase(w)).toBe('idle')
    await w.get('[data-test="image-at"]').setValue('04:30')
    await w.get('[data-test="image-packages"]').setValue(false)
    await w.get('form').trigger('submit')
    await settle(() => phase(w) === 'done')
    expect((sent.find((r) => r.method === 'POST' && r.path === '/images')?.body as { spec: unknown }).spec).toMatchObject({ auto_upgrade: { enabled: true, at: '04:30', packages: false } })
  })

  it('leaves the nightly upgrade out when the box is cleared', async () => {
    const { sent } = recorded()
    const w = await open()
    await w.get('[data-test="image-name"]').setValue('manual')
    await w.get('[data-test="image-build"]').setValue(false)
    await w.get('[data-test="image-auto"]').setValue(false)
    expect(w.find('[data-test="image-at"]').exists()).toBe(false)
    await w.get('form').trigger('submit')
    await settle(() => phase(w) === 'done')
    expect((sent.find((r) => r.method === 'POST' && r.path === '/images')?.body as { spec: Record<string, unknown> }).spec.auto_upgrade).toBeUndefined()
  })
})
