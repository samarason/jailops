import { describe, expect, it } from 'vitest'
import { bytes, percent, ago, rangeSize, parseSize } from './format'
import { has } from './features'

describe('format', () => {
  it('formats bytes', () => {
    expect(bytes(0)).toBe('0 B')
    expect(bytes(1536)).toBe('1.5 KiB')
    expect(bytes(5 * 1024 ** 3)).toBe('5 GiB')
    expect(bytes(96 * 1024 ** 2)).toBe('96 MiB')
    expect(bytes(undefined)).toBe('-')
  })
  it('clamps percent', () => {
    expect(percent(5, 0)).toBe(0)
    expect(percent(150, 100)).toBe(100)
  })
  it('ago', () => {
    const now = Date.parse('2026-01-01T00:10:00Z')
    expect(ago('2026-01-01T00:07:00Z', now)).toBe('3m ago')
    expect(ago('0001-01-01T00:00:00Z', now)).toBe('-')
  })
  it('range size and sizes', () => {
    expect(rangeSize('10.0.0.10-10.0.0.60')).toBe(51)
    expect(rangeSize('junk')).toBe(0)
    expect(parseSize('2G')).toBe(2 * 1024 ** 3)
    expect(parseSize('x')).toBeNull()
  })
})

describe('features', () => {
  it('hides what the server lacks', () => {
    expect(has(['jails'], 'jails')).toBe(true)
    expect(has(['jails'], 'backups')).toBe(false)
    expect(has(undefined, 'jails')).toBe(false)
  })
})

import { compressIPv6, shortAddr } from './format'
describe('compressIPv6', () => {
  it('compresses per RFC 5952', () => {
    expect(compressIPv6('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe('2001:db8::1')
    expect(compressIPv6('2001:DB8:0:0:1:0:0:1')).toBe('2001:db8::1:0:0:1')
    expect(compressIPv6('2001:db8:0:1:1:1:1:1')).toBe('2001:db8:0:1:1:1:1:1')
    expect(compressIPv6('2001:db8:0:0:0:0:0:0/64')).toBe('2001:db8::/64')
    expect(compressIPv6('0:0:0:0:0:0:0:1')).toBe('::1')
    expect(compressIPv6('2001:db8::1')).toBe('2001:db8::1')
  })
  it('leaves everything else alone', () => {
    for (const x of ['10.0.0.1', 'auto', 'none', 'fe80::zz', '1:2:3:4:5:6:7:8:9', '10.0.0.0/24']) expect(compressIPv6(x)).toBe(x)
  })
  it('shortens ranges', () => {
    expect(shortAddr('2001:db8:20:1:0:0:0:100-2001:db8:20:1:0:0:0:1ff')).toBe('2001:db8:20:1::100-2001:db8:20:1::1ff')
    expect(shortAddr('10.0.0.2-10.0.0.9')).toBe('10.0.0.2-10.0.0.9')
  })
})
