import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import RenameDialog from './RenameDialog.vue'
import { Client, getClient, setClient, type RawRequest, type Transport } from '@jailops/shared/api/client'
import { POLL_MS } from '@jailops/shared/composables/ops'
import { session } from '@jailops/shared/composables/session'
import { demoTransport } from '@/demo/transport'
import { server } from '@/demo/data'
import { withProject } from '@/lib/projectScope'
import type { RenameKind } from '@/lib/rename'

/** The demo server in the project web, recording every request it is sent. */
function recorded(): { sent: RawRequest[] } {
  const inner = demoTransport({ speed: 1000 })
  const sent: RawRequest[] = []
  const t: Transport = { request: (r) => { sent.push(r); return inner.request(r) }, stream: (p, h) => inner.stream(p, h) }
  const c = new Client(t)
  c.setRequestFilter((p) => withProject(p, 'web'))
  setClient(c)
  return { sent }
}

async function settle(until?: () => boolean): Promise<void> {
  const deadline = Date.now() + 5000
  for (let i = 0; i < 10 || (until && !until() && Date.now() < deadline); i++) {
    await flushPromises()
    await new Promise((r) => setTimeout(r, 10))
  }
}

describe('RenameDialog', () => {
  const before = getClient()
  const poll = POLL_MS.value
  const info = session.info
  beforeEach(() => {
    POLL_MS.value = 1
    session.info = server()
  })
  afterEach(() => {
    setClient(before)
    POLL_MS.value = poll
    session.info = info
  })

  // teleported to the body, as in the browser
  let mounted: VueWrapper | null = null
  afterEach(() => { mounted?.unmount(); mounted = null })
  async function open(kind: RenameKind, name: string, etag?: string) {
    const v = mount(RenameDialog, { props: { open: false, kind, name, etag }, attachTo: document.body })
    mounted = v
    await v.setProps({ open: true })
    await settle()
    const body = new DOMWrapper(document.body)
    const type = async (x: string) => { await body.get('#rn-name').setValue(x); await settle(() => !body.find('[data-test="rename-planning"]').exists()) }
    return { v, body, type, text: (sel: string) => (body.find(sel).exists() ? body.get(sel).text() : '') }
  }

  it('is a modal titled with the kind and the name, focuses the field and asks for a name first', async () => {
    recorded()
    const w = await open('network', 'lan')
    const dlg = w.body.get('[role="dialog"]')
    expect(dlg.attributes('aria-modal')).toBe('true')
    expect(document.getElementById(dlg.attributes('aria-labelledby')!)?.textContent).toBe('Rename network lan')
    expect(document.activeElement?.id).toBe('rn-name')
    expect(w.body.get('[data-test="rename-plan"]').attributes('aria-live')).toBe('polite')
    expect(w.text('[data-test="rename-why"]')).toBe('Enter a new name to see what changes.')
    expect(w.body.get('[data-test="rename-go"]').attributes('aria-disabled')).toBe('true')
    expect(w.text('#rn-name-h')).toContain('Lowercase letters, digits and hyphens')
  })

  it('checks the name with the rule of the kind before it asks the server', async () => {
    const { sent } = recorded()
    const w = await open('network', 'lan')
    await w.type('Lan')
    expect(w.text('#rn-name-e')).toBe('This name does not follow the rule above.')
    await w.type('lan')
    expect(w.text('#rn-name-e')).toBe('This is the name it has now.')
    expect(sent.filter((r) => r.path.includes('/rename'))).toEqual([])
    // an address set follows the same rule: hyphens, no underscores
    mounted?.unmount()
    const s = await open('addressSet', 'admins')
    await s.type('ops_team')
    expect(s.text('#rn-name-e')).toBe('This name does not follow the rule above.')
    await s.type('ops-team')
    expect(s.text('#rn-name-e')).toBe('')
  })

  it('lists what the dry run changes, grouped, with the counts in words', async () => {
    const { sent } = recorded()
    const w = await open('network', 'lan', '"3"')
    await w.type('lan2')
    const dry = sent.filter((r) => r.path.includes('/rename'))
    expect(dry.length).toBe(1)
    expect(dry[0].path).toBe('/networks/lan/rename')
    expect(dry[0].body).toEqual({ new_name: 'lan2', dry_run: true })
    expect(dry[0].headers?.['If-Match']).toBe('"3"')
    expect(w.text('[data-test="rename-summary"]')).toMatch(/^The rename changes 1 object, \d+ references and 1 firewall anchor\.$/)
    expect(w.text('[data-group="reference"]')).toContain('project web')
    expect(w.text('[data-group="reference"]')).toContain('spec.networks: lan -> lan2')
    expect(w.text('[data-group="reference"]')).toContain('jail web (project web)')
    expect(w.body.find('[data-test="rename-why"]').exists()).toBe(false)
    expect(w.body.get('[data-test="rename-go"]').attributes('aria-disabled')).toBe('false')
  })

  it('shows the refusal of the server in words in place of the plan', async () => {
    recorded()
    const w = await open('network', 'lan')
    await w.type('edge')
    expect(w.text('[data-test="rename-plan"] [data-test="error-panel"]')).toContain('network "edge" already exists')
    expect(w.text('[data-test="rename-why"]')).toBe('The server refuses this name; the reason is above.')
    mounted?.unmount()
    const j = await open('jail', 'web')
    await j.type('www')
    expect(j.text('[data-test="error-panel"]')).toContain('jail "web" is running')
    expect(j.text('[data-test="error-hint"]')).toContain('stop it first')
    expect(j.text('[data-test="rename-plan"]')).not.toContain('/api/v1')
  })

  it('renames with If-Match, follows the operation and says done', async () => {
    const { sent } = recorded()
    const w = await open('jail', 'build', '"3"')
    await w.type('ci')
    expect(w.text('[data-test="rename-warnings"]')).toBe('')
    expect(w.text('[data-group="dataset"]')).toContain('tank/jailops/web/build')
    await w.body.get('form#rn').trigger('submit')
    await settle(() => !!w.v.emitted('done'))
    const real = sent.filter((r) => r.path.includes('/rename') && !(r.body as { dry_run?: boolean }).dry_run)
    expect(real.map((r) => [r.path, r.headers?.['If-Match']])).toEqual([['/jails/build/rename?project=web', '"3"']])
    expect(w.v.emitted('done')).toEqual([['ci']])
    expect(w.v.emitted('close')).toBeTruthy()
  })

  it('shows a failed rename in the dialog and a stale If-Match as the server words it', async () => {
    recorded()
    const w = await open('policy', 'mail-edge', '"3"')
    await w.type('failing')
    await w.body.get('form#rn').trigger('submit')
    await settle(() => w.body.find('form#rn > [data-test="error-panel"]').exists() || w.body.findAll('[data-test="error-panel"]').length > 0)
    expect(w.text('[data-test="error-panel"]')).toContain('failed at step')
    expect(w.v.emitted('done')).toBeFalsy()
    mounted?.unmount()
    const st = await open('policy', 'mail-edge', '"1"')
    await st.type('mail-out')
    expect(st.text('[data-test="error-panel"]')).toContain('changed: current generation is 3')
  })

  it('closes on Escape', async () => {
    recorded()
    const w = await open('profile', 'web-limits')
    await w.body.get('[role="dialog"]').trigger('keydown', { key: 'Escape' })
    expect(w.v.emitted('close')).toBeTruthy()
  })
})
