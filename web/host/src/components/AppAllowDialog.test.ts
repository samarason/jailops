import { describe, expect, it, vi, beforeEach } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const allow = vi.fn()
vi.mock('@/api/endpoints', () => ({
  api: {
    jails: { list: () => Promise.resolve([{ metadata: { name: 'db' } }, { metadata: { name: 'web' } }, { metadata: { name: 'web-api' } }]) },
    firewall: { addressSets: () => Promise.resolve([{ metadata: { name: 'office' } }]) },
    appAccess: { allow: (...a: unknown[]) => allow(...a) },
  },
}))

import AppAllowDialog from './AppAllowDialog.vue'

const access = { jail: 'db', project: 'web', app: 'postgresql', type: 'postgresql', policy: 'app-db', closed: true, ports: ['5432/tcp'], grants: [] }
const grant = { source: 'jail:web', source_kind: 'jail', ports: ['5432/tcp'], rules: ['allow in tcp from 10.20.0.11 to port 5432'], hba: ['host web web 10.20.0.11/32 scram-sha-256'], database: 'web', role: 'web', created_at: '' }

describe('AppAllowDialog', () => {
  beforeEach(() => allow.mockReset())
  it('lists the other jails, sends the source, shows the connection string once and forgets it on close', async () => {
    allow.mockResolvedValue({ kind: 'sync', data: { jail: 'db', grant, changed: true, connection_string: 'postgres://web:SECRET@10.20.0.12:5432/web?sslmode=disable', notes: ['shown once'] } })
    const w = mount(AppAllowDialog, { props: { open: true, access: access as never }, global: { stubs: { Teleport: true } } })
    await flushPromises()
    const names = w.findAll('[data-test="allow-jails"] .mono').map((x) => x.text())
    expect(names).toEqual(['jail:web', 'jail:web-api'])
    await w.get('#acc-filter').setValue('api')
    expect(w.findAll('[data-test="allow-jails"] .mono').map((x) => x.text())).toEqual(['jail:web-api'])
    await w.get('#acc-filter').setValue('')
    await w.findAll('[data-test="allow-jails"] input')[0].setValue(true)
    expect(w.get('#acc-db').attributes('placeholder')).toBe('web')
    await w.get('form').trigger('submit')
    await flushPromises()
    expect(allow).toHaveBeenCalledWith('db', { source: 'jail:web' })
    expect((w.get('[data-test="allow-secret"] input').element as HTMLInputElement).value).toContain('SECRET')
    expect(w.emitted('done')).toBeTruthy()
    await w.setProps({ open: false })
    await w.setProps({ open: true })
    await flushPromises()
    expect(w.find('[data-test="allow-secret"]').exists()).toBe(false)
    expect(w.html()).not.toContain('SECRET')
  })
  it('refuses a bad address or database name before asking the server', async () => {
    const w = mount(AppAllowDialog, { props: { open: true, access: access as never }, global: { stubs: { Teleport: true } } })
    await flushPromises()
    await w.get('[data-test="kind-cidr"]').setValue(true)
    await w.get('#acc-cidr').setValue('192.0.2.300')
    await w.get('#acc-db').setValue('Bad-Name')
    await w.get('form').trigger('submit')
    await flushPromises()
    expect(allow).not.toHaveBeenCalled()
    expect(w.text()).toContain('Not an IPv4 or IPv6 address or prefix.')
    expect(w.text()).toContain('A lower-case letter')
  })
  it('previews with a dry run and shows the rule, the pg_hba line and the SQL', async () => {
    allow.mockResolvedValue({ kind: 'sync', data: { jail: 'db', grant, changed: true, dry_run: true, sql: [`CREATE ROLE "web" LOGIN PASSWORD '<generated, shown once>';`], steps: ['firewall policy app-db: allow'] } })
    const w = mount(AppAllowDialog, { props: { open: true, access: access as never }, global: { stubs: { Teleport: true } } })
    await flushPromises()
    await w.findAll('[data-test="allow-jails"] input')[0].setValue(true)
    await w.get('[data-test="allow-preview-btn"]').trigger('click')
    await flushPromises()
    expect(allow).toHaveBeenCalledWith('db', { source: 'jail:web', dry_run: true })
    const p = w.get('[data-test="allow-preview"]').text()
    expect(p).toContain('host web web 10.20.0.11/32 scram-sha-256')
    expect(p).toContain('CREATE ROLE')
    expect(w.find('[data-test="allow-secret"]').exists()).toBe(false)
  })
  it('has no database field for an app without an access block', async () => {
    const w = mount(AppAllowDialog, { props: { open: true, access: { ...access, type: undefined, app: 'nginx', ports: ['80/tcp'] } as never }, global: { stubs: { Teleport: true } } })
    await flushPromises()
    expect(w.find('#acc-db').exists()).toBe(false)
  })
})
