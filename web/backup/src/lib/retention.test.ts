import { describe, expect, it } from 'vitest'
import { freeScopes, policyProblems } from './retention'
import type { Group, RetentionPolicyRow } from '@/types'

const row = (scope: string): RetentionPolicyRow => ({ scope, policy: { daily: 7 }, timezone: 'UTC', updated_at: '', updated_by: 'alice' })
const grp = (id: string, host = 'h'): Group => ({ group_id: id, host_name: host, created_at: '', snapshots: 1, failed: 0, protected: 0, pending_deletion: 0 })
const msg = { scope: 'scope', taken: (s: string) => `taken ${s}`, count: 'count', none: 'none' }

describe('retention policy scopes', () => {
  it('offers default and the groups that have no policy yet', () => {
    expect(freeScopes([row('default'), row('g1')], [grp('g1'), grp('g2', 'bsd02')])).toEqual([{ scope: 'g2', host: 'bsd02' }])
    expect(freeScopes([], [grp('g1')]).map((x) => x.scope)).toEqual(['default', 'g1'])
  })
  it('adding needs a free scope; editing keeps its scope', () => {
    expect(policyProblems({ scope: '', values: { daily: 7 } }, [], true, msg)).toEqual({ 'pe-scope': 'scope' })
    expect(policyProblems({ scope: 'default', values: { daily: 7 } }, ['default'], true, msg)).toEqual({ 'pe-scope': 'taken default' })
    expect(policyProblems({ scope: 'default', values: { daily: 7 } }, [], false, msg)).toEqual({})
  })
  it('follows the server: counts 0 to 100000 and at least one above 0', () => {
    expect(policyProblems({ scope: 'g', values: {} }, [], true, msg)).toEqual({ 'pe-last': 'none' })
    expect(policyProblems({ scope: 'g', values: { daily: -1, weekly: 2 } }, [], true, msg)).toEqual({ 'pe-daily': 'count' })
    expect(policyProblems({ scope: 'g', values: { yearly: 100001 } }, [], true, msg)['pe-yearly']).toBe('count')
  })
})
