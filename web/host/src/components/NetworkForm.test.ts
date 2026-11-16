import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const create = vi.fn()
vi.mock('@/api/endpoints', () => ({ api: { networks: { create: (...a: unknown[]) => create(...a) } } }))

import NetworkForm from './NetworkForm.vue'

async function fill() {
  const w = mount(NetworkForm, { props: { open: false }, global: { stubs: { Teleport: true } } })
  await w.setProps({ open: true })
  await w.get('#nf-name').setValue('lan')
  await w.get('#nf-v4s').setValue('10.20.0.0/24')
  return w
}

describe('NetworkForm', () => {
  it('a new name has at most 13 characters', async () => {
    const w = await fill()
    await w.get('#nf-name').setValue('a-long-network')
    expect(w.get('#nf-name-e').text()).toBe('At most 13 characters.')
    expect(w.get('#nf-name-h').text()).toContain('at most 13 characters')
  })
  it('stays open on the warnings the server returns, and closes without them', async () => {
    create.mockResolvedValueOnce({ kind: 'sync', data: { metadata: { name: 'lan' }, spec: {}, status: { warnings: ['net.inet.ip.forwarding is 0: run sysctl net.inet.ip.forwarding=1'] } } })
    let w = await fill()
    await w.get('form').trigger('submit')
    await flushPromises()
    expect(w.emitted('done')).toHaveLength(1)
    expect(w.emitted('close')).toBeUndefined()
    expect(w.get('[data-test="nf-warnings"]').text()).toContain('net.inet.ip.forwarding is 0')
    await w.get('[data-test="nf-warn-close"]').trigger('click')
    expect(w.emitted('close')).toHaveLength(1)

    create.mockResolvedValueOnce({ kind: 'sync', data: { metadata: { name: 'lan' }, spec: {}, status: {} } })
    w = await fill()
    await w.get('form').trigger('submit')
    await flushPromises()
    expect(w.emitted('close')).toHaveLength(1)
  })
})
