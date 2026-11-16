import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { defineComponent, h } from 'vue'
import JailLabels from './JailLabels.vue'
import JailFilter from './JailFilter.vue'
import JailCreateForm from './JailCreateForm.vue'
import { Client, getClient, setClient, type RawRequest, type Transport } from '@jailops/shared/api/client'
import { session } from '@jailops/shared/composables/session'
import { POLL_MS } from '@jailops/shared/composables/ops'
import { demoTransport } from '@/demo/transport'
import { server } from '@/demo/data'
import { projectState } from '@/composables/project'
import { knownLabels } from '@/lib/labels'
import { withProject } from '@/lib/projectScope'
import { api } from '@/api/endpoints'
import type { Jail } from '@jailops/shared/api/types'

async function until(ok: () => boolean): Promise<void> {
  const deadline = Date.now() + 20000
  while (!ok() && Date.now() < deadline) {
    await flushPromises()
    await new Promise((r) => setTimeout(r, 5))
  }
  expect(ok()).toBe(true)
}

describe('labels in the console', () => {
  const before = getClient()
  const poll = POLL_MS.value
  let sent: RawRequest[] = []
  let router: Router
  let w: VueWrapper | null = null
  const patches = () => sent.filter((r) => r.method === 'PATCH').map((r) => [r.path, JSON.stringify(r.body)])

  beforeEach(async () => {
    POLL_MS.value = 1
    localStorage.clear()
    const inner = demoTransport({ speed: 1000 })
    sent = []
    setClient(new Client({ request: (r) => { sent.push(r); return inner.request(r) }, stream: (p, hd) => inner.stream(p, hd) } as Transport))
    Object.assign(session, { authed: true, info: server(), role: 'admin', global: true, user: 'alice', projects: [] })
    projectState.current = 'web'
    api.setProjectFilter((p) => withProject(p, 'web'))
    router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)*', component: defineComponent({ render: () => h('div') }) }] })
    await router.push('/jails/api')
  })
  afterEach(() => {
    w?.unmount()
    w = null
    api.setProjectFilter(null)
    setClient(before)
    POLL_MS.value = poll
  })

  async function mountJail(name: string): Promise<VueWrapper> {
    const jail = await api.jails.get(name)
    const m = mount(JailLabels, { props: { jail }, global: { plugins: [router] }, attachTo: document.body })
    return m
  }

  it('adds and removes one label with a merge patch, and refuses what the server refuses', async () => {
    w = await mountJail('build')
    expect(w.findAll('[data-label]').map((c) => c.attributes('data-label'))).toEqual(['env=dev', 'team=platform', 'role=ci'])
    await w.get('[data-test="labels-edit"]').trigger('click')
    await w.get('[data-test="label-key"]').setValue('bad key')
    await w.get('form').trigger('submit')
    await flushPromises()
    expect(w.text()).toContain("Letters, digits, '-', '_' and '.'")
    expect(document.activeElement?.id).toBe('lbl-key')
    await w.get('[data-test="label-key"]').setValue('jailops.app')
    await w.get('form').trigger('submit')
    await flushPromises()
    expect(w.text()).toContain('set by JailOps')
    await w.get('[data-test="label-key"]').setValue('tier')
    await w.get('[data-test="label-value"]').setValue('esc\u001b[31m')
    await w.get('form').trigger('submit')
    await flushPromises()
    expect(w.text()).toContain('Printable text only')
    expect(patches()).toEqual([])
    await w.get('[data-test="label-value"]').setValue('edge')
    await w.get('form').trigger('submit')
    await until(() => patches().length === 1)
    expect(patches()[0]).toEqual(['/jails/build?project=web', JSON.stringify({ metadata: { labels: { tier: 'edge' } } })])
    await until(() => w!.find('[data-label="tier=edge"]').exists())
    expect((await api.jails.get('build')).metadata.labels).toMatchObject({ env: 'dev', role: 'ci', team: 'platform', tier: 'edge' })
    await w.get('[data-remove="env"]').trigger('click')
    await until(() => patches().length === 2)
    expect(patches()[1][1]).toBe(JSON.stringify({ metadata: { labels: { env: null } } }))
    await until(() => !w!.find('[data-label="env=dev"]').exists())
    expect((await api.jails.get('build')).metadata.labels).toEqual({ role: 'ci', team: 'platform', tier: 'edge' })
  })

  it('a chip filters the jail list; an app jail shows its system labels read-only', async () => {
    w = await mountJail('web')
    expect(w.find('.lsys').text()).toContain('jailops.app')
    expect(w.text()).not.toContain('jailops.app.hash')
    await w.get('[data-label="env=prod"]').trigger('click')
    await until(() => router.currentRoute.value.path === '/jails')
    expect(router.currentRoute.value.query.q).toBe('env=prod')
  })

  it('offers no editor to an operator', async () => {
    session.role = 'operator'
    w = await mountJail('web')
    expect(w.find('[data-test="labels-edit"]').exists()).toBe(false)
  })

  it('the filter box suggests keys, then values, and commits a finished term', async () => {
    const jails = await api.jails.list()
    const f = mount(JailFilter, { props: { modelValue: '', known: knownLabels(jails), 'onUpdate:modelValue': (v: string) => f.setProps({ modelValue: v }) }, attachTo: document.body })
    const el = f.get<HTMLInputElement>('[data-test="jails-filter"]')
    await el.trigger('focus')
    el.element.value = 't'
    el.element.setSelectionRange(1, 1)
    await el.trigger('input')
    await flushPromises()
    expect(f.findAll('[role="option"]').map((o) => o.attributes('data-sugg'))).toEqual(['team=', 'tier='])
    expect(el.attributes('aria-expanded')).toBe('true')
    await el.trigger('keydown', { key: 'ArrowDown' })
    expect(el.attributes('aria-activedescendant')).toBe('jf-s-0')
    await el.trigger('keydown', { key: 'Enter' })
    await flushPromises()
    expect(f.props('modelValue')).toBe('team=')
    // the values of team, the most used first
    const values = f.findAll('[role="option"]').map((o) => o.attributes('data-sugg'))
    expect(values[0]).toBe('team=web')
    expect(values).toContain('team=data')
    await f.get('[data-sugg="team=data"]').trigger('mousedown')
    await flushPromises()
    expect(f.props('modelValue')).toBe('team=data ')
    expect(f.emitted('commit')?.at(-1)).toEqual(['team=data '])
    // an active term has its own remove button
    await f.setProps({ modelValue: 'env=prod -team=web db' })
    expect(f.findAll('[data-term]').map((t) => t.attributes('data-term'))).toEqual(['env=prod', '-team=web'])
    await f.get('[aria-label="Remove the filter -team=web"]').trigger('click')
    expect(f.emitted('commit')?.at(-1)).toEqual(['env=prod db'])
    f.unmount()
  })

  it('the create form sends the labels typed as key=value', async () => {
    const images = await api.images.list()
    const storage = await api.storage.list()
    const f = mount(JailCreateForm, { props: { open: false, project: undefined, images, storage, networks: [] }, global: { stubs: { Teleport: true } }, attachTo: document.body })
    await f.setProps({ open: true })
    await f.get('#jc-name').setValue('labelled')
    await f.get('[data-test="jc-labels"]').setValue('env=prod nope')
    await f.get('form').trigger('submit')
    await flushPromises()
    expect(document.activeElement?.id).toBe('jc-labels')
    expect(f.text()).toContain('key=value')
    await f.get('[data-test="jc-labels"]').setValue('env=prod owner="Web Ops"')
    await f.get('form').trigger('submit')
    await until(() => sent.some((r) => r.method === 'POST' && r.path.startsWith('/jails')))
    const body = sent.find((r) => r.method === 'POST' && r.path.startsWith('/jails'))!.body as Jail
    expect(body.metadata).toEqual({ name: 'labelled', labels: { env: 'prod', owner: 'Web Ops' } })
    await until(() => !!f.emitted('done'))
    expect((await api.jails.get('labelled')).metadata.labels).toEqual({ env: 'prod', owner: 'Web Ops' })
    f.unmount()
  })
})
