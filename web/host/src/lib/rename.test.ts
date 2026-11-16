import { describe, expect, it } from 'vitest'
import { capFirst, countsText, groupChanges, ifMatch, renamedAddress, renameProblem } from './rename'
import { demoRename, renameKindOf, type RenameDb } from '@/demo/rename'
import * as d from '@/demo/data'
import * as d2 from '@/demo/data2'
import { s } from '@/i18n'

describe('rename helpers', () => {
  it('checks the new name with the rule of the kind', () => {
    expect(renameProblem('network', 'lan', '', 'same')).toBe('Required.')
    expect(renameProblem('network', 'lan', 'lan', 'same')).toBe('same')
    expect(renameProblem('network', 'lan', 'lan_2', 'same')).toBe('This name does not follow the rule above.')
    expect(renameProblem('addressSet', 'admins', 'ops-team', 'same')).toBe('')
    expect(renameProblem('addressSet', 'admins', 'a'.repeat(30), 'same')).toBe('At most 29 characters.')
    expect(renameProblem('project', 'web', 'host', 'same')).toBe('"host" is reserved.')
  })
  it('makes If-Match of a generation', () => {
    expect(ifMatch(3)).toBe('"3"')
    expect(ifMatch(0)).toBe('"0"')
    expect(ifMatch(undefined)).toBeUndefined()
  })
  it('groups the changes in plan order and counts them in words', () => {
    const g = groupChanges([{ kind: 'dataset', object: 'a' }, { kind: 'reference', object: 'b' }, { kind: 'weird', object: 'c' }, { kind: 'object', object: 'd' }, { kind: 'reference', object: 'e' }])
    expect(g.map((x) => [x.kind, x.items.length])).toEqual([['object', 1], ['reference', 2], ['dataset', 1], ['weird', 1]])
    expect(countsText({ reference: 2, object: 1, dataset: 1 }, s.rename.count, 'and')).toBe('1 object, 2 references and 1 dataset')
    expect(countsText({ object: 1 }, s.rename.count, 'and')).toBe('1 object')
    expect(countsText({}, s.rename.count, 'and')).toBe('')
    expect(capFirst('backups name "x"')).toBe('Backups name "x"')
  })
  it('moves the object page to the new name, and only the object page', () => {
    expect(renamedAddress('jail', 'web', 'www', '/jails/web')).toBe('/jails/www')
    expect(renamedAddress('jail', 'web', 'www', '/jails/web?tab=config')).toBe('/jails/www?tab=config')
    expect(renamedAddress('jail', 'web', 'www', '/jails/webby')).toBeNull()
    expect(renamedAddress('project', 'web', 'shop2', '/projects/web')).toBe('/projects/shop2')
    expect(renamedAddress('network', 'lan', 'x', '/networks')).toBeNull()
  })
})

function db(): RenameDb {
  const sp = d2.profiles()
  return {
    jails: [...d.jails(), ...d2.stagingJails()], networks: d.networks(), images: d.images(), projects: d2.projects({}), policies: d.policies(), sets: d.addressSets(),
    profiles: sp, leases: d.leases(), snaps: d.snapshots(), history: {}, updates: [], bpol: d.backupPolicies(), backups: d.backups(),
  }
}

describe('demo rename', () => {
  it('knows the routes', () => {
    expect(renameKindOf(['networks', 'lan', 'rename'])).toEqual({ kind: 'network', name: 'lan' })
    expect(renameKindOf(['firewall', 'address-sets', 'admins', 'rename'])).toEqual({ kind: 'addressSet', name: 'admins' })
    expect(renameKindOf(['firewall', 'policies', 'x', 'rename'])).toEqual({ kind: 'policy', name: 'x' })
    expect(renameKindOf(['storage', 'x', 'rename'])).toBeUndefined()
    expect(renameKindOf(['networks', 'lan'])).toBeUndefined()
  })
  it('renames an address set and the rules and sets that name it follow', () => {
    const x = db()
    const a = demoRename(x, 'addressSet', 'office', 'office-eu', 'web', '"3"')
    if ('error' in a) throw new Error(a.error.message)
    expect(a.result.changes.map((c) => c.object)).toEqual(['address set office', 'address set admins'])
    expect(a.result.counts).toEqual({ object: 1, reference: 1 })
    a.apply()
    expect(x.sets.map((y) => y.metadata.name)).toEqual(['admins', 'office-eu'])
    expect(x.sets[0].spec.addresses.map((a) => a.address)).toContain('set:office-eu')
    const b = demoRename(x, 'addressSet', 'admins', 'ops', 'web', undefined)
    if ('error' in b) throw new Error(b.error.message)
    b.apply()
    expect(x.policies[0].spec.rules?.[1].from).toEqual(['set:ops'])
  })
  it('refuses what the server refuses', () => {
    const x = db()
    const code = (r: ReturnType<typeof demoRename>) => ('error' in r ? `${r.status} ${r.error.code}` : 'ok')
    expect(code(demoRename(x, 'network', 'lan', 'Lan', '', undefined))).toBe('400 invalid')
    expect(code(demoRename(x, 'network', 'lan', 'lan', '', undefined))).toBe('400 invalid')
    expect(code(demoRename(x, 'network', 'lan', 'edge', '', undefined))).toBe('409 already_exists')
    expect(code(demoRename(x, 'network', 'nope', 'x', '', undefined))).toBe('404 not_found')
    expect(code(demoRename(x, 'network', 'lan', 'lan2', '', '"1"'))).toBe('409 conflict')
    expect(code(demoRename(x, 'jail', 'web', 'www', 'web', undefined))).toBe('409 busy')
    expect(code(demoRename(x, 'jail', 'vault', 'safe', 'web', undefined))).toBe('409 locked')
    expect(code(demoRename(x, 'project', 'shop', 'store', '', undefined))).toBe('403 forbidden')
    expect(code(demoRename(x, 'jail', 'build', 'ci', 'web', undefined))).toBe('ok')
    const f = demoRename(x, 'jail', 'build', 'failing', 'web', undefined)
    expect('fails' in f && f.fails?.code).toBe('internal')
  })
  it('renames a project with what belongs to it, and leaves the old name free', () => {
    const x = db()
    const a = demoRename(x, 'project', 'web', 'www', '', undefined)
    if ('error' in a) throw new Error(a.error.message)
    expect(a.result.warnings?.[0]).toContain('keep the old project name')
    a.apply()
    expect(x.projects.map((p) => p.metadata.name)).toEqual(['www', 'shop', 'staging'])
    expect(x.jails.filter((j) => j.metadata.project === 'web')).toEqual([])
    expect(x.policies.every((p) => p.metadata.project === 'www')).toBe(true)
  })
})
