import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import RollbackDialog from './RollbackDialog.vue'
import { session } from '@jailops/shared/composables/session'

const snap = { metadata: { name: 's1', created_at: '2026-01-01T00:00:00Z' }, spec: { jail: 'web' }, status: { written: 3 * 1024 ** 2 } }

describe('RollbackDialog', () => {
  it('requires the jail name for data scope and shows bytes', async () => {
    session.info = { api_extensions: ['jail_rollback_scopes'] } as never
    const w = mount(RollbackDialog, { props: { open: true, jail: 'web', snapshots: [snap as never] }, global: { stubs: { Teleport: true } } })
    await w.vm.$nextTick()
    const go = () => w.get('[data-test="rollback-go"]')
    expect(go().attributes('aria-disabled')).toBe('false')
    await w.findAll('input[type="radio"]')[1].setValue(true)
    expect(go().attributes('aria-disabled')).toBe('true')
    expect(w.get('[data-test="rollback-why"]').text()).toContain('Type web')
    expect(w.get('[data-test="stake"]').text()).toBe('3 MiB')
    await w.get('form').trigger('submit')
    expect(w.emitted('done')).toBeFalsy()
    expect(w.get('#rb-confirm-err').text()).toContain('does not match')
    await w.get('#rb-confirm').setValue('web')
    expect(go().attributes('aria-disabled')).toBe('false')
    expect(w.find('[data-test="rollback-why"]').exists()).toBe(false)
  })
})
