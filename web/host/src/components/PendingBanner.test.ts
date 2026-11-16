import { afterEach, describe, expect, it } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import PendingBanner from './PendingBanner.vue'
import { Client, getClient, setClient } from '@jailops/shared/api/client'
import { demoTransport } from '@/demo/transport'
import { api } from '@/api/endpoints'
import { pendingState } from '@/composables/pending'

describe('PendingBanner', () => {
  const before = getClient()
  afterEach(() => setClient(before))
  it('reads the pending change from the server, counts down and confirms it', async () => {
    setClient(new Client(demoTransport({ speed: 1000 })))
    localStorage.clear()
    pendingState.data = null
    const fw = await api.host.firewall()
    const r = await api.host.applyFirewall({ spec: { ...fw.spec, icmp: !fw.spec.icmp }, confirm_within: 90 })
    expect(r.kind === 'sync' && r.data?.pending?.confirm_within).toBe(90)
    const w = mount(PendingBanner)
    await flushPromises()
    expect(w.get('[data-test="pending-banner"]').text()).toContain('firewall change reverts in 1:30')
    // the countdown is in the sentence once, not repeated after it
    expect(w.get('[data-test="pending-countdown"]').text().match(/1:30/g)).toHaveLength(1)
    expect(w.get('[data-test="pending-banner"]').text().match(/\d+:\d\d/g)).toHaveLength(1)
    expect(w.get('[role="status"]').attributes('aria-live')).toBe('polite')
    // a second change waits for the first
    await expect(api.host.applyFirewall({ spec: fw.spec })).rejects.toMatchObject({ code: 'busy' })
    await w.get('[data-test="pending-confirm"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="pending-banner"]').exists()).toBe(false)
    expect(w.get('[data-test="pending-said"]').text()).toContain('confirmed')
    expect((await api.host.pending()).last?.outcome).toBe('confirmed')
    w.unmount()
  })
})
