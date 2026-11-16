import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { nameProblem, validName, nameHint, validSize, DATASET_MAX } from './names'
import { stamp, snapshotLabel, sentence, plural, bytes, day } from './format'
import { actionText, objectOf, codeText, type KindMap } from './describe'
import { nextTab } from '../composables/tabs'
import { tierOf, confirmAction, confirmState, closeConfirm } from '../composables/confirm'
import { toasts, runOp, holdToast, releaseToast, TOAST_MS, POLL_MS } from '../composables/ops'
import { ApiError } from '../api/client'

describe('name rules follow the server', () => {
  it('object names: lower case, digits, hyphens, a letter first, at most 63', () => {
    for (const ok of ['web', 'a', 'web-1', 'a'.repeat(63)]) expect(validName(ok)).toBe(true)
    for (const bad of ['', 'Web', '1web', 'web.1', 'web_1', '-web', 'a'.repeat(64)]) expect(validName(bad)).toBe(false)
    expect(nameProblem('a'.repeat(64))).toBe('At most 63 characters.')
    expect(nameProblem('')).toBe('Required.')
    expect(nameHint()).toContain('at most 63 characters')
  })
  it('variants: reserved project names, the tunnel limit, identities', () => {
    expect(nameProblem('host', 'project')).toBe('"host" is reserved.')
    expect(validName('shop', 'project')).toBe(true)
    expect(validName('a'.repeat(12), 'tunnel')).toBe(true)
    expect(validName('a'.repeat(13), 'tunnel')).toBe(false)
    expect(validName('alice-b2', 'identity')).toBe(true)
    for (const bad of ['alice.b', 'alice_b', '.alice', 'Alice', '2alice']) expect(validName(bad, 'identity')).toBe(false)
  })
  it('the lengths of new objects: project and network 13, jail, volume and image 32, snapshot 64', () => {
    for (const [rule, max] of [['project', 13], ['network', 13], ['jail', 32], ['volume', 32], ['image', 32], ['snapshot', 64]] as const) {
      expect(validName('a'.repeat(max), rule)).toBe(true)
      expect(nameProblem('a'.repeat(max + 1), rule)).toBe(`At most ${max} characters.`)
      expect(nameHint(rule)).toContain(`at most ${max} characters`)
    }
    expect(validName('freebsd-15-1', 'image')).toBe(true)
    expect(validName('freebsd-15.1_x', 'image')).toBe(false)
    expect(validName('daily-2026-11-04', 'snapshot')).toBe(true)
    expect(validName('daily.2026-11-04', 'snapshot')).toBe(false)
    expect(validName('-x', 'snapshot')).toBe(false)
    expect(validName('web.1', 'jail')).toBe(false)
    expect(DATASET_MAX).toBe(88)
  })
  it('sizes: what the server parses, not zero, no fractions', () => {
    for (const ok of ['100', '512M', '512m', '4GiB', '1k', '7B', '2TB', ' 2G ']) expect(validSize(ok)).toBe(true)
    for (const bad of ['', '0', '0G', '1.5G', '4iB', 'G', '-1', '10Q', '4 G', '1'.repeat(19)]) expect(validSize(bad)).toBe(false)
  })
})

describe('format', () => {
  it('one time format: ISO in UTC', () => {
    expect(stamp('2026-11-01T13:16:12.345Z')).toBe('2026-11-01 13:16 UTC')
    expect(stamp('2026-11-01T13:16:12Z', true)).toBe('2026-11-01 13:16:12 UTC')
    expect(stamp('0001-01-01T00:00:00Z')).toBe('-')
    expect(day('2026-11-01T13:16:12Z')).toBe('2026-11-01')
  })
  it('snapshot names that are times read as dates', () => {
    expect(snapshotLabel('20261101T131612Z')).toBe('2026-11-01 13:16 UTC')
    expect(snapshotLabel('daily-20261101T131612Z')).toBe('daily 2026-11-01 13:16 UTC')
    expect(snapshotLabel('pre-upgrade-g4')).toBe('pre-upgrade-g4')
  })
  it('units keep a decimal only when it is not zero', () => {
    expect(bytes(2.5 * 1024 ** 3)).toBe('2.5 GiB')
    expect(bytes(62 * 1024 ** 3)).toBe('62 GiB')
  })
  it('sentence case and plurals', () => {
    expect(sentence('ONLINE')).toBe('Online')
    expect(sentence('success')).toBe('Success')
    expect(sentence('ok')).toBe('OK')
    expect(sentence('rolled_back')).toBe('Rolled back')
    expect(plural(1, 'warning')).toBe('1 warning')
    expect(plural(2, 'jail')).toBe('2 jails')
  })
})

describe('describe', () => {
  const kinds: KindMap = { jails: { kind: 'jail', to: (n) => `/jails/${n}` }, 'firewall/policies': { kind: 'firewall policy', to: () => '/firewall' } }
  it('links API paths by name', () => {
    expect(objectOf('/api/v1/jails/cache', kinds)).toEqual({ kind: 'jail', name: 'cache', to: '/jails/cache' })
    expect(objectOf('/api/v1/firewall/policies/web-default', kinds)).toEqual({ kind: 'firewall policy', name: 'web-default', to: '/firewall' })
    expect(objectOf('session', kinds)).toBeUndefined()
  })
  it('turns actions into words', () => {
    expect(actionText('POST /api/v1/jails/{name}/upgrade', kinds)).toBe('Upgrade jail')
    expect(actionText('POST /api/v1/jails', kinds)).toBe('Create jail')
    expect(actionText('DELETE /api/v1/jails/{name}', kinds)).toBe('Delete jail')
    expect(actionText('PUT /api/v1/firewall/policies/{name}', kinds)).toBe('Change firewall policy')
    expect(actionText('jail.start', kinds)).toBe('Start jail')
    expect(actionText('firewall.update', kinds)).toBe('Change firewall')
  })
  it('codes become sentences', () => {
    expect(codeText('busy')).toMatch(/Another operation/)
    expect(codeText('ApplyFailed')).toBe('Apply failed')
    expect(codeText('something_new')).toBe('something_new')
  })
})

describe('tabs', () => {
  it('arrow keys wrap, Home and End jump', () => {
    const t = ['a', 'b', 'c'] as const
    expect(nextTab(t, 'a', 'ArrowRight')).toBe('b')
    expect(nextTab(t, 'a', 'ArrowLeft')).toBe('c')
    expect(nextTab(t, 'b', 'End')).toBe('c')
    expect(nextTab(t, 'c', 'Home')).toBe('a')
    expect(nextTab(t, 'a', 'Enter')).toBeUndefined()
  })
})

describe('confirmation tiers', () => {
  afterEach(() => closeConfirm())
  it('typed name is tier 3, a plain ask tier 2, tier 1 runs at once', async () => {
    expect(tierOf({ typeName: 'web' })).toBe(3)
    expect(tierOf({})).toBe(2)
    const run = vi.fn(() => Promise.resolve())
    confirmAction({ title: 't', confirmLabel: 'Start', run, tier: 1 })
    expect(run).toHaveBeenCalledOnce()
    expect(confirmState.req).toBeNull()
    confirmAction({ title: 'Stop web', confirmLabel: 'Stop', run })
    expect(confirmState.req?.title).toBe('Stop web')
    expect(run).toHaveBeenCalledOnce()
  })
})

describe('toasts dismiss themselves', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    toasts.splice(0)
    POLL_MS.value = 1
  })
  afterEach(() => vi.useRealTimers())
  it('success after 5 s, failure after 15 s, held while pointed at', async () => {
    await runOp('ok', async () => ({ kind: 'sync' as const, data: null }))
    await runOp('bad', async () => { throw new ApiError({ code: 'busy', message: 'no' }) }).catch(() => undefined)
    expect(toasts.map((t) => t.status)).toEqual(['success', 'failure'])
    vi.advanceTimersByTime(TOAST_MS.success + 10)
    expect(toasts.map((t) => t.title)).toEqual(['bad'])
    holdToast(toasts[0].id)
    vi.advanceTimersByTime(TOAST_MS.failure * 2)
    expect(toasts).toHaveLength(1)
    releaseToast(toasts[0].id)
    vi.advanceTimersByTime(TOAST_MS.failure)
    expect(toasts).toHaveLength(0)
  })
})
