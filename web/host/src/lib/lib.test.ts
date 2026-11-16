import { describe, expect, it } from 'vitest'
import { canSubmit, bytesAtStake, request, needsConfirm } from './rollback'
import { buildRequest, requestKey } from './restore'
import { validPort, validateRules, detailToRuleErrors, splitList } from './firewall'




describe('rollback', () => {
  it('data and all need the typed name', () => {
    expect(canSubmit('root', '', 'web', undefined)).toBe(true)
    expect(canSubmit('data', '', 'web', 's')).toBe(false)
    expect(canSubmit('all', 'wev', 'web', 's')).toBe(false)
    expect(canSubmit('all', 'web', 'web', 's')).toBe(true)
    expect(canSubmit('data', 'web', 'web', undefined)).toBe(false)
  })
  it('reports bytes only for destructive scopes and sets confirm_data_loss', () => {
    const snap = { status: { written: 99 } } as never
    expect(bytesAtStake('root', snap)).toBe(0)
    expect(bytesAtStake('data', snap)).toBe(99)
    expect(request('root', 's').confirm_data_loss).toBe(false)
    expect(request('data', 's')).toEqual({ scope: 'data', snapshot: 's', confirm_data_loss: true })
    expect(needsConfirm('all')).toBe(true)
  })
})

describe('restore', () => {
  const f = { backup: 'b', as: '', host: '', replace: false, keepIp: false, noVolumes: false, passphrase: '', networkMap: { a: 'a', b: 'x' } }
  it('omits empties and identity mappings', () => {
    expect(buildRequest(f, true)).toEqual({ backup: 'b', network_map: { b: 'x' }, dry_run: true })
  })
  it('key ignores dry_run but not choices', () => {
    expect(requestKey(f)).toBe(requestKey({ ...f }))
    expect(requestKey(f)).not.toBe(requestKey({ ...f, as: 'n' }))
  })
  it('sends no_volumes and the passphrase only when set, and the key ignores what the passphrase says', () => {
    expect(buildRequest({ ...f, noVolumes: true }, false)).toMatchObject({ no_volumes: true })
    expect(buildRequest(f, false)).not.toHaveProperty('no_volumes')
    expect(buildRequest({ ...f, passphrase: 'correct horse battery' }, false)).toMatchObject({ passphrase: 'correct horse battery' })
    expect(buildRequest(f, false)).not.toHaveProperty('passphrase')
    expect(requestKey({ ...f, passphrase: 'one' })).toBe(requestKey({ ...f, passphrase: 'two' }))
    expect(requestKey({ ...f, passphrase: 'one' })).not.toBe(requestKey(f))
    expect(requestKey({ ...f, noVolumes: true })).not.toBe(requestKey(f))
  })
})

describe('firewall', () => {
  const msg = { portRange: 'range', portNeedsProto: 'proto', redirectInOnly: 'in only', hostPortRange: 'hp' }
  it('validates ports', () => {
    expect(validPort('80')).toBe(true)
    expect(validPort('8000-8100')).toBe(true)
    expect(validPort('9000-8000')).toBe(false)
    expect(validPort('70000')).toBe(false)
  })
  it('flags rules', () => {
    const e = validateRules([{ action: 'allow', direction: 'out', proto: 'icmp', ports: ['80'], redirect: { host_port: 1, jail_port: 2 } }], msg)
    expect(e['0.ports']).toBe('proto')
    expect(e['0.redirect']).toBe('in only')
  })
  it('maps api detail keys', () => {
    expect(detailToRuleErrors({ 'rules[2].ports': 'bad', 'rules.1.from': 'x', other: 'y' })).toEqual({ '2.ports': 'bad', '1.from': 'x' })
    expect(splitList('a, b  c')).toEqual(['a', 'b', 'c'])
  })
})
