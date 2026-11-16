import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { defineComponent, h } from 'vue'
import SetupView from './SetupView.vue'
import { Client, getClient, setClient, type RawRequest, type Transport } from '@jailops/shared/api/client'
import { POLL_MS } from '@jailops/shared/composables/ops'
import { session } from '@jailops/shared/composables/session'
import { demoTransport } from '@/demo/transport'
import { DEMO_SETUP_TOKEN } from '@/demo/setupToken'

// The wizard's base image step against the demo server of a host that was just installed (`?demo=setup`): the
// steps before it are skipped, as a person may.

async function settle(until?: () => boolean): Promise<void> {
  const deadline = Date.now() + 20000
  for (let i = 0; i < 20 || (until && !until() && Date.now() < deadline); i++) {
    await flushPromises()
    await new Promise((r) => setTimeout(r, 5))
  }
}
const writes = (sent: RawRequest[]) => sent.filter((r) => r.method !== 'GET').map((r) => `${r.method} ${r.path}`)

describe('the wizard: base image', () => {
  const before = getClient()
  const poll = POLL_MS.value
  let w: VueWrapper | null = null
  let sent: RawRequest[] = []
  beforeEach(() => {
    POLL_MS.value = 1
    localStorage.clear()
    sessionStorage.clear()
    history.replaceState({}, '', '/setup?demo=setup')
    Object.assign(session, { authed: false, info: null, role: '', global: false, user: '' })
    const inner = demoTransport({ speed: 1000, signedOut: true })
    sent = []
    const t: Transport = { request: (r) => { sent.push(r); return inner.request(r) }, stream: (p, hd) => inner.stream(p, hd) }
    setClient(new Client(t))
  })
  afterEach(() => {
    w?.unmount()
    w = null
    setClient(before)
    POLL_MS.value = poll
    history.replaceState({}, '', '/')
  })

  /** The wizard, walked to the base image step. */
  async function toImageStep() {
    const blank = defineComponent({ render: () => h('div') })
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/setup', component: SetupView }, { path: '/:any(.*)', component: blank }] })
    await router.push('/setup')
    w = mount(defineComponent({ render: () => h(SetupView) }), { global: { plugins: [router] }, attachTo: document.body })
    await settle()
    const step = () => w!.get('[data-test="setup-step"]').text()
    await w.get('[data-test="setup-token"]').setValue(DEMO_SETUP_TOKEN)
    await w.get('[data-test="setup-password"]').setValue('correct horse battery')
    await w.get('[data-test="setup-repeat"]').setValue('correct horse battery')
    await w.get('[data-test="setup-account"]').trigger('submit')
    await settle(() => step().includes('Host name'))
    for (const name of ['Host name', 'Certificate', 'Firewall', 'Storage and network']) {
      await settle(() => step().includes(name) && w!.find('[data-test="setup-skip"]').exists())
      await w.get('[data-test="setup-skip"]').trigger('click')
    }
    await settle(() => w!.find('[data-test="image-fields"]').exists())
    expect(step()).toBe('Step 6 of 7: Base image')
    sent.length = 0
    return { w: w!, step }
  }

  it('proposes the base image of this host and builds it: create, then build', async () => {
    const { w, step } = await toImageStep()
    expect((w.get('[data-test="image-name"]').element as HTMLInputElement).value).toBe('freebsd-15-1')
    expect(w.get('[data-test="image-release-choice"]').text()).toContain('15.1-RELEASE (this host)')
    expect(w.find('[data-test="image-alias"]').exists()).toBe(false)
    expect((w.get('[data-test="image-auto"]').element as HTMLInputElement).checked).toBe(false)
    await w.get('[data-test="image-auto"]').setValue(true)
    expect(w.text()).toContain('the image gets the patch updates of its release every night')
    expect(w.get('[data-test="setup-image-skip-note"]').text()).toContain('Images page')
    await w.get('[data-test="setup-image"]').trigger('submit')
    await settle(() => step().includes('Done'))
    expect(writes(sent)).toEqual(['POST /images', 'POST /images/freebsd-15-1/generations'])
    expect((sent.find((r) => r.method === 'POST' && r.path === '/images')?.body as { spec: unknown }).spec).toMatchObject({ auto_upgrade: { enabled: true, packages: true } })
    expect(w.get('[data-test="setup-done"]').text()).toContain('Image freebsd-15-1 (FreeBSD 15.1-RELEASE), first generation built, upgraded every night at 03:00')
    expect(w.get('[data-test="setup-apps"]').text()).toBe('Install your first app')
    expect(w.find('[data-test="setup-image-link"]').exists()).toBe(false)
  })

  it('checks the fields before anything is sent', async () => {
    const { w } = await toImageStep()
    await w.get('[data-test="image-name"]').setValue('Base')
    await w.get('[data-test="image-release-choice"]').setValue('other')
    await w.get('[data-test="image-release"]').setValue('15.0-RELEASE')
    await w.get('[data-test="setup-image"]').trigger('submit')
    await settle()
    expect(writes(sent)).toEqual([])
    expect(w.text()).toContain('JailOps supports FreeBSD 15.1 and later.')
    expect(w.get('[data-test="setup-image-make"]').attributes('aria-disabled')).toBe('true')
  })

  it('shows a failed build in the step and builds again on Try again', async () => {
    const { w, step } = await toImageStep()
    await w.get('[data-test="image-name"]').setValue('flaky')
    await w.get('[data-test="setup-image"]').trigger('submit')
    await settle(() => w.find('[data-test="setup-image-failed"]').exists())
    expect(w.get('[data-test="setup-image"]').attributes('data-phase')).toBe('failed')
    expect(w.get('[data-test="setup-image-failed"]').text()).toBe('The image flaky is defined, but its first generation was not built.')
    expect(w.text()).toContain('pkg.freebsd.org')
    expect(w.get('[data-test="image-fields"]').attributes('disabled')).toBeDefined()
    expect(step()).toContain('Base image')
    expect(w.get('[data-test="setup-image-retry"]').text()).toBe('Try again')
    await w.get('[data-test="setup-image"]').trigger('submit')
    await settle(() => step().includes('Done'))
    expect(writes(sent)).toEqual(['POST /images', 'POST /images/flaky/generations', 'POST /images/flaky/generations'])
    expect(w.find('[data-test="setup-apps"]').exists()).toBe(true)
  })

  it('can be skipped: the Done step then leads to the base image', async () => {
    const { w, step } = await toImageStep()
    await w.get('[data-test="setup-skip"]').trigger('click')
    await settle(() => step().includes('Done') && w.find('[data-test="setup-done-no-image"]').exists())
    expect(writes(sent)).toEqual([])
    expect(w.get('[data-test="setup-done-no-image"]').text()).toContain('create the base image')
    expect(w.get('[data-test="setup-image-link"]').attributes('href')).toBe('/images?create=1')
    expect(w.find('[data-test="setup-apps"]').exists()).toBe(false)
  })
})
