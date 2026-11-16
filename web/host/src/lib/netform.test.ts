import { describe, expect, it } from 'vitest'
import { blankNet, checkNet, netBody, suggestV4 } from './netform'

describe('network form helpers', () => {
  it('suggests gateway and range from a subnet', () => {
    expect(suggestV4('10.20.0.0/24')).toEqual({ gateway: '10.20.0.1', range: '10.20.0.2-10.20.0.254' })
    expect(suggestV4('10.20.0.5/28')).toEqual({ gateway: '10.20.0.1', range: '10.20.0.2-10.20.0.14' })
    expect(suggestV4('nonsense')).toBeNull()
  })
  it('flags plain typing mistakes and leaves limits to the server', () => {
    const f = { ...blankNet(), name: 'lan', v4subnet: '10.20.0.0/24', v4gateway: '10.30.0.1', v4range: '10.20.0.10-10.20.0.300' }
    expect(Object.keys(checkNet(f)).sort()).toEqual(['v4gateway', 'v4range'])
    expect(checkNet({ ...blankNet(), name: 'lan', v4subnet: '10.20.0.0/7', v4gateway: '10.20.0.1', v4range: '10.20.0.2-10.20.0.9' })).toEqual({})
  })
  it('proxy needs an uplink', () => {
    const f = { ...blankNet(), name: 'edge', v4: false, mode: 'proxy' as const, v6subnet: '2001:db8:99::/64', v6range: '2001:db8:99::100-2001:db8:99::1ff' }
    expect(checkNet(f)).toMatchObject({ uplink: expect.any(String) })
    expect(checkNet({ ...f, uplink: 'em1' })).toEqual({})
  })
  it('needs one address family and builds the API body', () => {
    expect(checkNet({ ...blankNet(), name: 'x', v4: false }).family).toBeTruthy()
    const b = netBody({ ...blankNet(), name: 'lan', uplink: 'em0', v4subnet: '10.0.0.0/24', v4gateway: '10.0.0.1', v4range: '10.0.0.2-10.0.0.9', nat: true })
    expect(b.spec).toEqual({ uplink: 'em0', ipv4: { subnet: '10.0.0.0/24', gateway: '10.0.0.1', range: '10.0.0.2-10.0.0.9', nat: true } })
  })
})
