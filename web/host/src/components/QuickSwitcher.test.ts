import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { defineComponent, h } from 'vue'
import QuickSwitcher from './QuickSwitcher.vue'
import { Client, getClient, setClient, type RawRequest, type Transport } from '@jailops/shared/api/client'
import { POLL_MS } from '@jailops/shared/composables/ops'
import { session } from '@jailops/shared/composables/session'
import { confirmState } from '@jailops/shared/composables/confirm'
import { demoTransport } from '@/demo/transport'
import { server } from '@/demo/data'
import { projectState } from '@/composables/project'
import { closeSwitcher, indexState, switcherState } from '@/composables/search'
import { loadRecent } from '@/lib/search'
import { api } from '@/api/endpoints'
import { withProject } from '@/lib/projectScope'

// The quick switcher against the demo server: the keys that open it, the ranking it shows, the keyboard, the quick
// actions of a jail and where the focus goes.

async function until(ok: () => boolean): Promise<void> {
  const deadline = Date.now() + 20000
  while (!ok() && Date.now() < deadline) {
    await flushPromises()
    await new Promise((r) => setTimeout(r, 5))
  }
  expect(ok()).toBe(true)
}
const key = (k: string, o: KeyboardEventInit = {}) => window.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, ...o }))
const input = () => document.querySelector<HTMLInputElement>('[data-test="qs-input"]')
const rows = () => [...document.querySelectorAll<HTMLElement>('[role="option"]')]
const selected = () => document.querySelector<HTMLElement>('[role="option"][aria-selected="true"]')
async function type(text: string): Promise<void> {
  const el = input()!
  el.value = text
  el.dispatchEvent(new Event('input'))
  // the ranking follows the typing after a short pause: wait until it ranked this text
  await until(() => document.querySelector<HTMLElement>('[data-test="quick-switcher"]')?.dataset.query === text)
}
async function press(k: string, o: KeyboardEventInit = {}): Promise<void> {
  input()!.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, ...o }))
  await flushPromises()
}

describe('QuickSwitcher', () => {
  const before = getClient()
  const poll = POLL_MS.value
  let w: VueWrapper | null = null
  let router: Router
  let sent: RawRequest[] = []
  let opener: HTMLButtonElement

  beforeEach(async () => {
    POLL_MS.value = 1
    localStorage.clear()
    const inner = demoTransport({ speed: 1000 })
    sent = []
    setClient(new Client({ request: (r) => { sent.push(r); return inner.request(r) }, stream: (p, hd) => inner.stream(p, hd) } as Transport))
    Object.assign(session, { authed: true, info: server(), role: 'admin', global: true, user: 'alice', projects: [] })
    projectState.current = 'web'
    api.setProjectFilter((p) => withProject(p, projectState.current))
    projectState.projects = await api.projects.list()
    indexState.loaded = false
    router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)*', component: defineComponent({ render: () => h('div') }) }] })
    await router.push('/jails')
    opener = document.createElement('button')
    document.body.appendChild(opener)
    opener.focus()
    w = mount(QuickSwitcher, { props: { pages: [{ to: '/jails', label: 'Jails', icon: 'box' }, { to: '/networks', label: 'Networks', icon: 'network' }] }, global: { plugins: [router] }, attachTo: document.body })
  })
  afterEach(() => {
    closeSwitcher()
    w?.unmount()
    opener.remove()
    api.setProjectFilter(null)
    setClient(before)
    POLL_MS.value = poll
    confirmState.req = null
  })

  it('opens with Ctrl+K and with / outside a text field, never from inside one', async () => {
    key('k', { ctrlKey: true })
    await until(() => !!input())
    expect(document.activeElement).toBe(input())
    expect(document.querySelector('[role="dialog"]')?.getAttribute('aria-modal')).toBe('true')
    await press('Escape')
    await until(() => !input())
    expect(document.activeElement).toBe(opener)
    key('/')
    await until(() => !!input())
    await press('Escape')
    await until(() => !input())
    const field = document.createElement('input')
    document.body.appendChild(field)
    field.focus()
    key('/')
    await flushPromises()
    expect(switcherState.open).toBe(false)
    field.remove()
  })

  it('ranks jails by name, label and address; arrows move; Enter opens and remembers', async () => {
    switcherState.open = true
    await until(() => indexState.loaded)
    await type('web')
    expect(selected()?.dataset.qs).toBe('jail:web:web')
    expect(input()!.getAttribute('aria-activedescendant')).toBe(selected()!.id)
    expect(document.querySelector('[data-test="qs-status"]')!.textContent).toMatch(/\d+ results/)
    await type('env=prod team=data')
    expect(rows().filter((r) => r.dataset.kind === 'jail').map((r) => r.dataset.qs)).toEqual(['jail:web:db', 'jail:web:worker'])
    await type('10.20.0.24')
    expect(selected()?.dataset.qs).toBe('jail:web:git')
    await type('netw')
    expect(selected()?.dataset.kind).toBe('page')
    await press('ArrowUp')
    expect(selected()).toBe(rows()[rows().length - 1])
    await press('ArrowDown')
    expect(selected()).toBe(rows()[0])
    await type('worker')
    await press('Enter')
    await until(() => router.currentRoute.value.path === '/jails/worker')
    expect(switcherState.open).toBe(false)
    expect(loadRecent()[0]).toMatchObject({ id: 'jail:web:worker', title: 'worker' })
    // the box opens on the recent items
    switcherState.open = true
    await until(() => !!input())
    expect(rows()[0].dataset.qs).toBe('jail:web:worker')
  })

  it('says when nothing matches', async () => {
    switcherState.open = true
    await until(() => indexState.loaded)
    await type('zzzqqq')
    expect(document.querySelector('[data-test="qs-empty"]')!.textContent).toContain('Nothing matches "zzzqqq"')
    expect(input()!.getAttribute('aria-expanded')).toBe('false')
  })

  it('opens the shell with Shift+Enter, the logs with Alt+L; stopping asks first', async () => {
    switcherState.open = true
    await until(() => indexState.loaded)
    await type('api')
    await press('Enter', { shiftKey: true })
    await until(() => router.currentRoute.value.path === '/jails/api/shell')
    switcherState.open = true
    await until(() => indexState.loaded && !!input())
    await type('api')
    await press('l', { altKey: true, code: 'KeyL' })
    await until(() => router.currentRoute.value.fullPath === '/jails/api?tab=logs')
    switcherState.open = true
    await until(() => !!input())
    await type('api')
    await press('s', { altKey: true, code: 'KeyS' })
    // stop is tier 2: the confirmation names the jail and nothing is sent yet
    await until(() => !!confirmState.req)
    expect(confirmState.req!.title).toContain('api')
    expect(sent.some((r) => r.method === 'PUT' && r.path.includes('/state'))).toBe(false)
  })

  it('starts a stopped jail before its shell', async () => {
    switcherState.open = true
    await until(() => indexState.loaded)
    await type('build')
    expect(selected()?.dataset.qs).toBe('jail:web:build')
    await press('Enter', { shiftKey: true })
    await until(() => router.currentRoute.value.path === '/jails/build/shell')
    await until(() => sent.some((r) => r.method === 'PUT' && r.path.startsWith('/jails/build/state')))
  })

  it('searches every project when asked, and leaves out what the identity may not reach', async () => {
    switcherState.open = true
    await until(() => indexState.loaded)
    await type('stg')
    expect(rows().some((r) => r.dataset.qs === 'jail:staging:stg-web')).toBe(false)
    const all = document.querySelector<HTMLInputElement>('[data-test="qs-all"]')!
    all.checked = true
    all.dispatchEvent(new Event('change'))
    await until(() => indexState.entries.some((e) => e.id === 'jail:staging:stg-web'))
    await type('stg-web')
    expect(selected()?.dataset.qs).toBe('jail:staging:stg-web')
    await press('Enter')
    await until(() => router.currentRoute.value.path === '/jails/stg-web')
    expect(projectState.current).toBe('staging')
  })

  it('offers no shell to a read-only identity', async () => {
    session.role = 'readonly'
    switcherState.open = true
    await until(() => indexState.loaded)
    await type('api')
    expect(selected()!.querySelector('[data-act="shell"]')).toBeNull()
    await press('Enter', { shiftKey: true })
    await flushPromises()
    expect(router.currentRoute.value.path).toBe('/jails')
  })
})
