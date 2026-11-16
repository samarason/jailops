import { describe, expect, it } from 'vitest'
import { v4Plan, setupNetwork, retargetRemoteAdd } from './setup'

describe('setup: the network step takes every prefix the server takes', () => {
  it('accepts /8 to /30 without host bits, gateway first, the rest for jails', () => {
    expect(v4Plan('10.77.0.0/16')).toEqual({ gateway: '10.77.0.1', range: '10.77.0.2-10.77.255.254' })
    expect(v4Plan('10.77.0.0/24')).toEqual({ gateway: '10.77.0.1', range: '10.77.0.2-10.77.0.254' })
    expect(v4Plan('192.0.2.8/30')).toEqual({ gateway: '192.0.2.9', range: '192.0.2.10-192.0.2.10' })
    expect(v4Plan('10.0.0.0/8')?.gateway).toBe('10.0.0.1')
    for (const bad of ['10.77.0.1/24', '10.77.0.0/31', '10.0.0.0/7', '10.77.0.0', 'x/24']) expect(v4Plan(bad)).toBeNull()
    expect(setupNetwork('10.77.0.0/20', 'em0')?.ipv4).toEqual({ subnet: '10.77.0.0/20', gateway: '10.77.0.1', range: '10.77.0.2-10.77.15.254', nat: true })
  })
})

describe('setup: the renamed host', () => {
  it('rewrites the client command the daemon built with its old name', () => {
    const cmd = 'jailops remote add bsd01 https://bsd01.example.net:39110 --fingerprint ab --token-file -'
    expect(retargetRemoteAdd(cmd, 'bsd01.example.net', 'jails1.example.com')).toBe('jailops remote add jails1 https://jails1.example.com:39110 --fingerprint ab --token-file -')
    expect(retargetRemoteAdd(cmd, 'bsd01.example.net', 'bsd01.example.net')).toBe(cmd)
    // a command for another name (an ACME domain) is not touched
    expect(retargetRemoteAdd('jailops remote add web https://web.example.com:39110 --token-file -', 'bsd01.example.net', 'x.example.com')).toBe('jailops remote add web https://web.example.com:39110 --token-file -')
  })
})
