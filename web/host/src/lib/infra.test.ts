import { describe, expect, it } from 'vitest'
import { actionText, objectOf } from '@jailops/shared/lib/describe'
import { hostKinds, resourcePaths } from './objects'
import { portIn, wgCover, withWgAllow } from './wgfw'
import { blankNet, checkNet, formOf, netBody } from './netform'
import { blankServer, checkServer } from './wireguard'
import { nameError, BAD_NAME } from './nameField'
import type { HostFirewall, Network } from '@jailops/shared/api/types'

describe('host objects by name', () => {
  it('links the API paths of operations and audit entries to console pages', () => {
    expect(objectOf('/api/v1/jails/cache', hostKinds)).toEqual({ kind: 'jail', name: 'cache', to: '/jails/cache' })
    expect(objectOf('/api/v1/firewall/policies/web-default', hostKinds)).toEqual({ kind: 'firewall policy', name: 'web-default', to: '/firewall?policy=web-default' })
    expect(objectOf('/api/v1/images/freebsd-15', hostKinds)?.to).toBe('/images')
    expect(objectOf('/api/v1/tokens/ci', hostKinds)?.to).toBe('/access?tab=tokens')
    expect(actionText('POST /api/v1/jails/{name}/upgrade', hostKinds)).toBe('Upgrade jail')
    expect(actionText('DELETE /api/v1/firewall/policies/{name}', hostKinds)).toBe('Delete firewall policy')
    expect(resourcePaths({ jails: ['/api/v1/jails/a'], images: ['/api/v1/images/b'] })).toEqual(['/api/v1/jails/a', '/api/v1/images/b'])
  })
})

describe('the host firewall and a WireGuard listen port', () => {
  const fw = (template: string, allow: HostFirewall['spec']['allow'] = [], managed = true): HostFirewall => ({
    kind: 'HostFirewall' as never, spec: { template, icmp: true, allow }, status: { managed, config_enabled: managed, helper_enabled: managed, file_exists: true, file_managed: managed, console_port: 39110, rules: [] },
  })
  it('reads port lists and ranges', () => {
    expect(portIn('51820', 51820)).toBe(true)
    expect(portIn('51000-52000', 51820)).toBe(true)
    expect(portIn('51821', 51820)).toBe(false)
  })
  it('says whether the port passes', () => {
    expect(wgCover(undefined, 51820).state).toBe('unmanaged')
    expect(wgCover(fw('default', [], false), 51820).state).toBe('unmanaged')
    expect(wgCover(fw('open'), 51820).state).toBe('open')
    expect(wgCover(fw('default'), 51820).state).toBe('missing')
    // the allow list counts only with the custom-rules template, and only for udp
    expect(wgCover(fw('default', [{ proto: 'udp', ports: ['51820'] }]), 51820).state).toBe('missing')
    expect(wgCover(fw('custom-rules', [{ proto: 'tcp', ports: ['51820'] }]), 51820).state).toBe('missing')
    expect(wgCover(fw('custom-rules', [{ proto: 'udp', ports: ['51820'], from: ['198.51.100.0/24'] }]), 51820)).toEqual({ state: 'allowed', from: ['198.51.100.0/24'] })
  })
  it('adds one udp row and keeps everything else', () => {
    const sp = withWgAllow(fw('default', [], true), 51821, 'WireGuard lab')
    expect(sp.template).toBe('custom-rules')
    expect(sp.allow).toEqual([{ proto: 'udp', ports: ['51821'], comment: 'WireGuard lab' }])
    expect(wgCover({ ...fw('custom-rules'), spec: sp }, 51821).state).toBe('allowed')
  })
})

describe('name fields follow the server rule', () => {
  it('network names', () => {
    expect(checkNet({ ...blankNet(), name: 'lan.1', v4subnet: '10.0.0.0/24', v4gateway: '10.0.0.1', v4range: '10.0.0.2-10.0.0.9' }).name).toBe(BAD_NAME)
    expect(checkNet({ ...blankNet(), name: '1lan', v4subnet: '10.0.0.0/24', v4gateway: '10.0.0.1', v4range: '10.0.0.2-10.0.0.9' }).name).toBe(BAD_NAME)
    expect(checkNet({ ...blankNet(), name: 'lan-1', v4subnet: '10.0.0.0/24', v4gateway: '10.0.0.1', v4range: '10.0.0.2-10.0.0.9' }).name).toBeUndefined()
    // a new network has at most 13 characters; an existing one keeps its longer name
    const long = { ...blankNet(), name: 'a-long-network', v4subnet: '10.0.0.0/24', v4gateway: '10.0.0.1', v4range: '10.0.0.2-10.0.0.9' }
    expect(checkNet(long).name).toBe('At most 13 characters.')
    expect(checkNet(long, true).name).toBeUndefined()
  })
  it('a tunnel name has at most 12 characters', () => {
    expect(checkServer({ ...blankServer(), name: 'office', address: '10.99.0.1/24' }).name).toBeUndefined()
    expect(checkServer({ ...blankServer(), name: 'a-very-long-tunnel', address: '10.99.0.1/24' }).name).toBe('At most 12 characters.')
  })
  it('projects refuse the reserved names', () => {
    expect(nameError('host', 'project')).toBe('"host" is reserved.')
    expect(nameError('Shop', 'project')).toBe(BAD_NAME)
    expect(nameError('')).toBe('Required.')
  })
})

describe('editing a network keeps what the form does not show', () => {
  it('round-trips the spec', () => {
    const n: Network = {
      metadata: { name: 'lan', generation: 3 },
      spec: { uplink: 'em0', ipv4: { subnet: '10.20.0.0/24', gateway: '10.20.0.1', range: '10.20.0.10-10.20.0.60', exclude: ['10.20.0.40-10.20.0.44'], nat: true }, dns: ['10.20.0.1'], mtu: 1500 },
      status: {},
    }
    const f = formOf(n)
    expect(f).toMatchObject({ name: 'lan', uplink: 'em0', v4: true, nat: true, mode: 'none' })
    f.v4range = '10.20.0.10-10.20.0.90'
    const b = netBody(f, n)
    expect(b.metadata).toEqual(n.metadata)
    expect(b.spec).toEqual({ ...n.spec, ipv4: { ...n.spec.ipv4!, range: '10.20.0.10-10.20.0.90' } })
  })
})
