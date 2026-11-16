import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { defineComponent, h } from 'vue'
import FirewallView from './FirewallView.vue'
import AddressSetCreateDialog from '@/components/AddressSetCreateDialog.vue'
import ConfirmHost from '@jailops/shared/components/ConfirmHost.vue'
import { Client, getClient, setClient, type RawRequest, type Transport } from '@jailops/shared/api/client'
import { session } from '@jailops/shared/composables/session'
import { POLL_MS } from '@jailops/shared/composables/ops'
import { closeConfirm } from '@jailops/shared/composables/confirm'
import { demoTransport } from '@/demo/transport'
import { server } from '@/demo/data'
import { projectState } from '@/composables/project'
import { withProject } from '@/lib/projectScope'
import { api } from '@/api/endpoints'
import type { AddressSet } from '@jailops/shared/api/types'

async function until(ok: () => boolean): Promise<void> {
  const deadline = Date.now() + 20000
  while (!ok() && Date.now() < deadline) {
    await flushPromises()
    await new Promise((r) => setTimeout(r, 5))
  }
  expect(ok()).toBe(true)
}

const body = () => new DOMWrapper(document.body)
const writes = (sent: RawRequest[]) => sent.filter((r) => r.method !== 'GET').map((r) => `${r.method} ${r.path.split('?')[0]}`)

describe('address sets in the firewall page', () => {
  const before = getClient()
  const poll = POLL_MS.value
  let sent: RawRequest[] = []
  let router: Router
  let w: VueWrapper | null = null

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
    await router.push('/firewall?tab=sets')
  })
  afterEach(() => {
    w?.unmount()
    w = null
    closeConfirm()
    api.setProjectFilter(null)
    setClient(before)
    POLL_MS.value = poll
  })

  const sets = async (): Promise<AddressSet[]> => api.firewall.addressSets()

  describe('the create dialog', () => {
    async function open(list: AddressSet[]) {
      const v = mount(AddressSetCreateDialog, { props: { open: false, sets: list }, attachTo: document.body })
      w = v
      await v.setProps({ open: true })
      await flushPromises()
      return v
    }

    it('checks the name and the members as the server does, and focuses the first problem', async () => {
      const v = await open(await sets())
      expect(document.activeElement?.id).toBe('fws-name')
      await body().get('#fws-name').setValue('admins')
      await body().get('#fws-members').setValue('192.0.2.1\nnot-an-address')
      await body().get('[data-test="set-create-go"]').trigger('click')
      await body().get('#fws').trigger('submit')
      await flushPromises()
      expect(body().get('#fws-name-e').text()).toBe('An address set of this name exists.')
      expect(body().get('#fws-members-e').text()).toBe('"not-an-address" is not an address, a CIDR, jail:NAME or set:NAME.')
      expect(body().get('[data-test="set-create-why"]').text()).toContain('Name: An address set of this name exists.')
      expect(document.activeElement?.id).toBe('fws-name')
      // a set that has itself as a member
      await body().get('#fws-name').setValue('loop')
      await body().get('#fws-members').setValue('set:loop')
      await flushPromises()
      expect(body().get('#fws-members-e').text()).toBe('Address set cycle: loop -> loop.')
      expect(writes(sent)).toEqual([])
      expect(v.emitted('created')).toBeUndefined()
    })

    it('creates an empty set and a set with members', async () => {
      const v = await open(await sets())
      await body().get('#fws-name').setValue('empty')
      await body().get('#fws').trigger('submit')
      await until(() => !!v.emitted('created'))
      expect(v.emitted('created')![0]).toEqual(['empty'])
      await v.setProps({ open: false })
      await v.setProps({ open: true, sets: await sets() })
      await flushPromises()
      expect((body().get('#fws-name').element as HTMLInputElement).value).toBe('')
      await body().get('#fws-name').setValue('ops')
      await body().get('#fws-members').setValue('192.0.2.10\n2001:db8::/64')
      await body().get('#fws').trigger('submit')
      await until(() => v.emitted('created')?.length === 2)
      const ops = (await api.firewall.addressSet('ops')).data
      expect(ops.spec).toEqual({ addresses: [{ address: '192.0.2.10' }, { address: '2001:db8::/64' }] })
      expect(ops.metadata.project).toBe('web')
    })

    it('shows a refusal of the server on its field', async () => {
      // the list the dialog knows is stale: the server still refuses the name
      const v = await open([])
      await body().get('#fws-name').setValue('office')
      await body().get('#fws').trigger('submit')
      await until(() => body().find('[data-test="error-panel"]').exists())
      expect(body().get('#fws-name-e').text()).toBe('')
      expect(body().get('[data-test="error-panel"]').text()).toContain('already exists')
      // a member set:NAME the dialog believes in but the server does not know: its message lands under the field
      await v.setProps({ sets: [{ metadata: { name: 'phantom' }, spec: { addresses: [] } } as AddressSet] })
      await body().get('#fws-name').setValue('fresh')
      await body().get('#fws-members').setValue('set:phantom')
      await body().get('#fws').trigger('submit')
      await until(() => body().get('#fws-members-e').text() !== '')
      expect(body().get('#fws-members-e').text()).toBe('address set "phantom" does not exist (a rule or a set names set:phantom)')
      expect(document.activeElement?.id).toBe('fws-members')
      // typing clears it; without the member the set is created
      await body().get('#fws-members').setValue('')
      await body().get('#fws-members').trigger('input')
      expect(body().get('#fws-members-e').text()).toBe('')
      await body().get('#fws').trigger('submit')
      await until(() => !!v.emitted('created'))
    })
  })

  describe('the tab', () => {
    async function page(): Promise<VueWrapper> {
      const v = mount(defineComponent({ render: () => h('div', [h(FirewallView), h(ConfirmHost)]) }), { global: { plugins: [router] }, attachTo: document.body })
      w = v
      await until(() => body().find('[data-test="set-editor"]').exists())
      return v
    }

    it('creates a set, selects it, edits it and deletes it; the list follows and nothing dangles', async () => {
      await page()
      expect(body().get('[data-test="set-editor"] h2').text()).toBe('set:admins')
      expect(body().get('[data-test="save-set"]').text()).toBe('Save set')
      expect(body().get('[data-test="set-save-why"]').text()).toContain('Nothing to save')
      await body().get('[data-test="new-set"]').trigger('click')
      await until(() => body().find('#fws-name').exists())
      await body().get('#fws-name').setValue('lab')
      await body().get('#fws').trigger('submit')
      await until(() => body().get('[data-test="set-editor"] h2').text() === 'set:lab')
      expect(body().get('[data-test="set-list"]').text()).toContain('set:lab')
      expect(body().find('#fws-name').exists()).toBe(false)
      // an empty set edits like any other
      expect((body().get('#sa').element as HTMLTextAreaElement).value).toBe('')
      await body().get('#sa').setValue('198.51.100.1\nbad')
      await body().get('[data-test="save-set"]').trigger('click')
      await flushPromises()
      expect(body().get('#sa-e').text()).toBe('"bad" is not an address, a CIDR, jail:NAME or set:NAME.')
      expect(document.activeElement?.id).toBe('sa')
      await body().get('#sa').setValue('198.51.100.1')
      await body().get('[data-test="save-set"]').trigger('click')
      await until(() => writes(sent).includes('PUT /firewall/address-sets/lab'))
      // saved and loaded again: nothing left to save
      await until(() => body().find('[data-test="set-save-why"]').exists() && body().get('[data-test="set-save-why"]').text().includes('Nothing to save'))
      expect((await api.firewall.addressSet('lab')).data.spec.addresses).toEqual([{ address: '198.51.100.1' }])
      // nothing uses lab: a plain confirmation, then the first set is shown
      await body().get('[data-test="delete-set"]').trigger('click')
      await until(() => body().find('[data-test="confirm-dialog"]').exists())
      expect(body().get('[data-test="confirm-dialog"]').attributes('data-tier')).toBe('2')
      await body().get('[data-test="confirm-dialog"]').trigger('submit')
      await until(() => !body().get('[data-test="set-list"]').text().includes('set:lab'))
      await until(() => body().find('[data-test="set-editor"] h2').exists() && body().get('[data-test="set-editor"] h2').text() === 'set:admins')
      expect(writes(sent)).toEqual(['POST /firewall/address-sets', 'PUT /firewall/address-sets/lab', 'DELETE /firewall/address-sets/lab'])
    })

    it('lists what uses a set and shows the refusal of the server', async () => {
      await page()
      // admins is used by the web-default policy
      expect(body().get('[data-test="set-users"]').text()).toContain('web-default')
      await body().get('[data-test="delete-set"]').trigger('click')
      await until(() => body().find('[data-test="confirm-items"]').exists())
      expect(body().get('[data-test="confirm-items"]').text()).toContain('web-default')
      await body().get('[data-test="confirm-dialog"]').trigger('submit')
      await until(() => body().find('[data-test="confirm-dialog"] [data-test="error-panel"]').exists())
      const panel = body().get('[data-test="confirm-dialog"] [data-test="error-panel"]').text()
      expect(panel).toContain('address set "admins" is used by firewall policy "web-default"')
      expect(panel).toContain('remove set:admins from the rules of web-default first')
      expect((await sets()).map((x) => x.metadata.name)).toContain('admins')
      // office is a member of admins
      closeConfirm()
      await flushPromises()
      const office = body().findAll('[data-test="set-list"] button').find((b) => b.text() === 'set:office')!
      await office.trigger('click')
      await until(() => body().get('[data-test="set-editor"] h2').text() === 'set:office')
      await body().get('[data-test="delete-set"]').trigger('click')
      await until(() => body().find('[data-test="confirm-dialog"]').exists())
      await body().get('[data-test="confirm-dialog"]').trigger('submit')
      await until(() => body().find('[data-test="confirm-dialog"] [data-test="error-panel"]').exists())
      expect(body().get('[data-test="confirm-dialog"] [data-test="error-panel"]').text()).toContain('is a member of "admins"')
    })

    it('shows the empty state with the add button in a project without sets', async () => {
      projectState.current = 'staging'
      api.setProjectFilter((p) => withProject(p, 'staging'))
      const v = mount(defineComponent({ render: () => h('div', [h(FirewallView), h(ConfirmHost)]) }), { global: { plugins: [router] }, attachTo: document.body })
      w = v
      await until(() => body().find('[data-test="sets-empty"]').exists())
      expect(body().find('[data-test="new-set"]').exists()).toBe(false)
      expect(body().get('[data-test="sets-empty"]').text()).toContain('No address sets yet.')
      await body().get('[data-test="new-set-empty"]').trigger('click')
      await until(() => body().find('#fws-name').exists())
      await body().get('#fws-name').setValue('stage-ops')
      await body().get('#fws').trigger('submit')
      await until(() => body().find('[data-test="set-editor"]').exists())
      expect(body().get('[data-test="set-editor"] h2').text()).toBe('set:stage-ops')
      expect((await sets()).map((x) => x.metadata.name)).toEqual(['stage-ops'])
    })
  })
})
