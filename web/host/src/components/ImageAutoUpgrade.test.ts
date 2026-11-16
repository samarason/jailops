import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import ImageAutoUpgrade from './ImageAutoUpgrade.vue'
import NewReleaseNotice from './NewReleaseNotice.vue'
import { Client, getClient, setClient, type RawRequest, type Transport } from '@jailops/shared/api/client'
import { POLL_MS } from '@jailops/shared/composables/ops'
import { session } from '@jailops/shared/composables/session'
import { demoTransport } from '@/demo/transport'
import { autoUpgradeRuns, images, server } from '@/demo/data'
import type { Image } from '@jailops/shared/api/types'

function recorded(): RawRequest[] {
  const inner = demoTransport({ speed: 1000 })
  const sent: RawRequest[] = []
  const t: Transport = { request: (r) => { sent.push(r); return inner.request(r) }, stream: (p, h) => inner.stream(p, h) }
  setClient(new Client(t))
  return sent
}
async function settle(): Promise<void> {
  for (let i = 0; i < 20; i++) {
    await flushPromises()
    await new Promise((r) => setTimeout(r, 2))
  }
}
const freebsd = (): Image => images().find((i) => i.metadata.name === 'freebsd-15-1')!
const checked = (w: ReturnType<typeof mount>, t: string) => (w.get(`[data-test="${t}"]`).element as HTMLInputElement).checked

describe('the nightly upgrade of an image', () => {
  const before = getClient()
  const poll = POLL_MS.value
  beforeEach(() => { POLL_MS.value = 1 })
  afterEach(() => { setClient(before); POLL_MS.value = poll })

  it('shows the state, the next run and the recent runs', () => {
    const w = mount(ImageAutoUpgrade, { props: { image: freebsd(), editable: true } })
    expect(checked(w, 'auto-upgrade-on')).toBe(true)
    expect((w.get('[data-test="auto-upgrade-at"]').element as HTMLInputElement).value).toBe('03:00')
    expect(checked(w, 'auto-upgrade-packages')).toBe(true)
    expect(w.get('[data-test="auto-upgrade-summary"]').text()).toBe('Every night at 03:00 (host time), with the packages inside the jails.')
    expect(w.get('[data-test="auto-upgrade-next"]').text()).toMatch(/^Next run: \d{4}-\d{2}-\d{2}/)
    const rows = w.findAll('[data-test="auto-upgrade-runs"] tbody tr')
    expect(rows.map((r) => r.attributes('data-result'))).toEqual(['unchanged', 'unchanged', 'ok'])
    expect(rows[0].text()).toContain('Nothing new')
    expect(rows[2].text()).toContain('freebsd-15-1#g4')
    expect(rows[2].text()).toContain('5 moved, 5 with packages upgraded')
    // nothing changed: no Save, no failure notice
    expect(w.find('[data-test="auto-upgrade-save"]').exists()).toBe(false)
    expect(w.find('[data-test="auto-upgrade-failed"]').exists()).toBe(false)
  })

  it('shows a failed last run plainly', () => {
    const img = freebsd()
    img.status.auto_upgrade!.recent = autoUpgradeRuns(true)
    const w = mount(ImageAutoUpgrade, { props: { image: img, editable: true } })
    const n = w.get('[data-test="auto-upgrade-failed"]')
    expect(n.classes()).toContain('danger')
    expect(n.attributes('role')).toBe('alert')
    expect(n.text()).toContain('The last nightly upgrade failed')
    expect(n.text()).toContain('jail db: health check /usr/local/bin/check exited 1')
    expect(w.findAll('[data-test="auto-upgrade-runs"] tbody tr')[0].text()).toContain('2 moved, 1 failed')
  })

  it('saves a change with a merge patch of spec.auto_upgrade, and checks the time first', async () => {
    const sent = recorded()
    const w = mount(ImageAutoUpgrade, { props: { image: freebsd(), editable: true }, attachTo: document.body })
    await w.get('[data-test="auto-upgrade-at"]').setValue('')
    await w.get('form').trigger('submit')
    await settle()
    expect(w.text()).toContain('Required.')
    expect(sent.filter((r) => r.method === 'PATCH')).toEqual([])
    await w.get('[data-test="auto-upgrade-at"]').setValue('04:15')
    await w.get('[data-test="auto-upgrade-packages"]').setValue(false)
    await w.get('form').trigger('submit')
    await settle()
    const patch = sent.find((r) => r.method === 'PATCH')
    expect(patch?.path).toBe('/images/freebsd-15-1')
    expect(patch?.body).toEqual({ spec: { auto_upgrade: { enabled: true, at: '04:15', packages: false } } })
    expect(w.emitted('saved')).toHaveLength(1)
    w.unmount()
  })

  it('turns it on with the packages proposed, and off', async () => {
    const off = freebsd()
    off.spec.auto_upgrade = undefined
    off.status.auto_upgrade = undefined
    const sent = recorded()
    const w = mount(ImageAutoUpgrade, { props: { image: off, editable: true } })
    expect(checked(w, 'auto-upgrade-on')).toBe(false)
    expect(w.find('[data-test="auto-upgrade-at"]').exists()).toBe(false)
    await w.get('[data-test="auto-upgrade-on"]').setValue(true)
    expect(checked(w, 'auto-upgrade-packages')).toBe(true)
    await w.get('form').trigger('submit')
    await settle()
    expect(sent.find((r) => r.method === 'PATCH')?.body).toEqual({ spec: { auto_upgrade: { enabled: true, packages: true } } })

    const on = mount(ImageAutoUpgrade, { props: { image: freebsd(), editable: true } })
    await on.get('[data-test="auto-upgrade-on"]').setValue(false)
    await on.get('form').trigger('submit')
    await settle()
    expect(sent.filter((r) => r.method === 'PATCH').at(-1)?.body).toEqual({ spec: { auto_upgrade: { enabled: false, packages: true } } })
  })

  it('is read-only for everyone but a global admin', () => {
    const w = mount(ImageAutoUpgrade, { props: { image: freebsd(), editable: false } })
    expect(w.find('input').exists()).toBe(false)
    expect(w.get('[data-test="auto-upgrade-state"]').text()).toContain('Every night at 03:00 (host time)')
    expect(w.get('[data-test="auto-upgrade-state"]').text()).toContain('A global administrator changes this.')
    expect(w.find('[data-test="auto-upgrade-runs"]').exists()).toBe(true)
  })
})

describe('the new release notice', () => {
  const info = session.info
  afterEach(() => { session.info = info })
  const withKernel = (k: string) => { session.info = { ...server(), environment: { ...server().environment, kernel_version: k } } }

  it('offers the image of a newer host release, quietly', async () => {
    withKernel('15.2-RELEASE-p1')
    const w = mount(NewReleaseNotice, { props: { images: images(), mayCreate: true } })
    const n = w.get('[data-test="new-release"]')
    expect(n.classes()).toContain('info')
    expect(n.text()).toContain('This host runs FreeBSD 15.2-RELEASE')
    expect(n.text()).toContain('the jails that exist stay on the release of their image')
    await w.get('[data-test="new-release-go"]').trigger('click')
    expect(w.emitted('create')).toHaveLength(1)
    const ro = mount(NewReleaseNotice, { props: { images: images(), mayCreate: false } })
    expect(ro.find('[data-test="new-release-go"]').exists()).toBe(false)
    expect(ro.text()).toContain('An administrator creates it on the Images page.')
  })

  it('says nothing while the host runs the release of an image, or before the images are known', () => {
    withKernel('15.1-RELEASE-p4')
    expect(mount(NewReleaseNotice, { props: { images: images(), mayCreate: true } }).find('[data-test="new-release"]').exists()).toBe(false)
    withKernel('15.2-RELEASE')
    expect(mount(NewReleaseNotice, { props: { images: undefined, mayCreate: true } }).find('[data-test="new-release"]').exists()).toBe(false)
  })
})
