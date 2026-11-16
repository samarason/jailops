import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { session } from '@jailops/shared/composables/session'
import type { ServerInfo } from '@jailops/shared/api/types'
import { canFirewallTest, hasFirewallTest } from './fwtest'

// Who is offered the firewall test: operator or admin of the project, when the server has the extension.
describe('the firewall test is offered', () => {
  const before = { info: session.info, role: session.role, global: session.global, projects: session.projects }
  beforeEach(() => {
    session.info = { api_extensions: ['firewall_test'] } as unknown as ServerInfo
    session.role = 'operator'
    session.global = false
    session.projects = ['web']
  })
  afterEach(() => Object.assign(session, before))

  it('to an operator and an admin of the project', () => {
    expect(canFirewallTest('web')).toBe(true)
    session.role = 'admin'
    expect(canFirewallTest('web')).toBe(true)
  })
  it('not to a read-only identity, and not outside its projects', () => {
    session.role = 'readonly'
    expect(canFirewallTest('web')).toBe(false)
    session.role = 'operator'
    expect(canFirewallTest('shop')).toBe(false)
    session.global = true
    expect(canFirewallTest('shop')).toBe(true)
  })
  it('only when the server has the extension, and an unknown role may try', () => {
    session.info = { api_extensions: [] } as unknown as ServerInfo
    expect(hasFirewallTest()).toBe(false)
    expect(canFirewallTest('web')).toBe(false)
    session.info = { api_extensions: ['firewall_test'] } as unknown as ServerInfo
    session.role = ''
    expect(canFirewallTest('web')).toBe(true)
  })
})
