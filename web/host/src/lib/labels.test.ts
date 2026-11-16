import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  chipOrder, knownLabels, labelKeyProblem, labelPatch, labelsProblem, labelValueProblem, matchTerms, parseLabelField, parseQuery, queryText,
  suggest, tokens, validLabelKey, withLabel, withoutTerm,
} from './labels'

const jail = (name: string, labels: Record<string, string> = {}, addresses: string[] = [], image = 'freebsd-15-1') => ({ metadata: { name, labels }, spec: { image }, status: { addresses } })

// The cases the server's own test checks (sdk/api/text_test.go): the console refuses exactly what the server refuses.
type Part = string | [string, number]
const fixture = JSON.parse(readFileSync(join(import.meta.dirname, '../../../../sdk/api/testdata/labels.json'), 'utf8')) as Record<'keys' | 'values', Record<'valid' | 'invalid', Part[][]>>
const build = (parts: Part[]) => parts.map((p) => (typeof p === 'string' ? p : p[0].repeat(p[1]))).join('')

describe('label rules, as sdk/api/text.go', () => {
  it('agrees with the server on the shared cases', () => {
    for (const k of fixture.keys.valid.map(build)) expect(labelKeyProblem(k), JSON.stringify(k)).toBe('')
    for (const k of fixture.keys.invalid.map(build)) expect(labelKeyProblem(k), JSON.stringify(k)).not.toBe('')
    for (const v of fixture.values.valid.map(build)) expect(labelValueProblem(v), JSON.stringify(v)).toBe('')
    for (const v of fixture.values.invalid.map(build)) expect(labelValueProblem(v), JSON.stringify(v)).not.toBe('')
    expect(fixture.keys.valid.length + fixture.values.invalid.length).toBeGreaterThan(10)
  })
  it('accepts the keys ValidLabelKey accepts', () => {
    for (const k of ['env', 'a', 'jailops.app', 'jailops.app.version', 'example.org/tier', 'Team_1', 'a-b.c_d', 'x'.repeat(63), 'p'.repeat(253) + '/n']) expect(validLabelKey(k), k).toBe(true)
  })
  it('refuses the keys ValidLabelKey refuses', () => {
    for (const k of ['', '-env', 'env-', '.env', 'env.', 'e nv', 'env=x', 'a/b/c', '/name', 'prefix/', 'pre_fix/name', 'x'.repeat(64), 'p'.repeat(254) + '/n', 'ümlaut', 'a:b']) expect(validLabelKey(k), k).toBe(false)
  })
  it('names the problem of a key and a value', () => {
    expect(labelKeyProblem('')).toBe('keyNeeded')
    expect(labelKeyProblem('bad key')).toBe('key')
    expect(labelKeyProblem('env')).toBe('')
    expect(labelValueProblem('')).toBe('')
    expect(labelValueProblem('web ops, 2026')).toBe('')
    expect(labelValueProblem('x'.repeat(253))).toBe('')
    expect(labelValueProblem('x'.repeat(254))).toBe('valueLong')
    // the limit is in bytes: 127 two-byte letters are 254 bytes
    expect(labelValueProblem('ä'.repeat(126))).toBe('')
    expect(labelValueProblem('ä'.repeat(127))).toBe('valueLong')
    for (const bad of ['a\nb', 'tab\there', 'esc\x1b[31m', 'del\x7f', 'c1\x85', 'rtl‮', 'zw​', 'bom﻿', 'iso⁦', 'lone\ud800']) expect(labelValueProblem(bad), JSON.stringify(bad)).toBe('valueUnsafe')
  })
  it('checks a whole set: at most 64', () => {
    const many = Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`k${i}`, 'v']))
    expect(labelsProblem(many)).toBe('tooMany')
    delete many.k64
    expect(labelsProblem(many)).toBe('')
    expect(labelsProblem({ ok: 'v', 'b d': 'v' })).toBe('key')
  })
  it('reads the create field like --label', () => {
    expect(parseLabelField('env=prod  team=web')).toEqual({ labels: { env: 'prod', team: 'web' }, problem: '' })
    expect(parseLabelField('owner="Web Ops"')).toEqual({ labels: { owner: 'Web Ops' }, problem: '' })
    expect(parseLabelField('flag=')).toEqual({ labels: { flag: '' }, problem: '' })
    expect(parseLabelField('env').problem).toBe('format')
    expect(parseLabelField('=x').problem).toBe('format')
    expect(parseLabelField('jailops.app=nginx').problem).toBe('system')
    expect(parseLabelField('bad_/k=v').problem).toBe('key')
  })
})

describe('merge patch of labels', () => {
  it('sends changed and new keys, null for removed ones, nothing for the rest', () => {
    expect(labelPatch({ env: 'prod', team: 'web', old: 'x' }, { env: 'dev', team: 'web', tier: 'edge' })).toEqual({ env: 'dev', tier: 'edge', old: null })
    expect(labelPatch(undefined, { a: '1' })).toEqual({ a: '1' })
    expect(labelPatch({ a: '1' }, { a: '1' })).toEqual({})
  })
})

describe('filter language', () => {
  it('splits on blanks and keeps quoted values together', () => {
    expect(tokens(' env=prod  team="web ops" x ')).toEqual(['env=prod', 'team=web ops', 'x'])
    expect(tokens('a=""')).toEqual(['a='])
  })
  it('parses label terms, presence, negation and words', () => {
    expect(parseQuery('env=prod team: -tier=edge -backup: Web 10.20.0.11')).toEqual([
      { kind: 'label', key: 'env', value: 'prod', not: false },
      { kind: 'has', key: 'team', not: false },
      { kind: 'label', key: 'tier', value: 'edge', not: true },
      { kind: 'has', key: 'backup', not: true },
      { kind: 'word', text: 'web', not: false },
      { kind: 'word', text: '10.20.0.11', not: false },
    ])
    // key= while the value is still being typed means "has the key"
    expect(parseQuery('env=')).toEqual([{ kind: 'has', key: 'env', not: false }])
    // an address or a path is a word, not a label
    expect(parseQuery('2001:db8::1 /var/db a=b=c')).toEqual([
      { kind: 'word', text: '2001:db8::1', not: false }, { kind: 'word', text: '/var/db', not: false }, { kind: 'label', key: 'a', value: 'b=c', not: false },
    ])
    expect(parseQuery('-')).toEqual([{ kind: 'word', text: '-', not: false }])
  })
  it('matches every term, labels exactly and words anywhere', () => {
    const list = [
      jail('web', { env: 'prod', team: 'web', app: 'nginx' }, ['10.20.0.11/24']),
      jail('db', { env: 'prod', team: 'data' }, ['10.20.0.12/24']),
      jail('build', { env: 'dev' }),
      jail('bare'),
    ]
    const names = (q: string) => list.filter((j) => matchTerms(j, parseQuery(q))).map((j) => j.metadata.name)
    expect(names('')).toEqual(['web', 'db', 'build', 'bare'])
    expect(names('env=prod')).toEqual(['web', 'db'])
    expect(names('env=Prod')).toEqual([])
    expect(names('env=prod -team=web')).toEqual(['db'])
    expect(names('team:')).toEqual(['web', 'db'])
    expect(names('-team:')).toEqual(['build', 'bare'])
    expect(names('-env=prod')).toEqual(['build', 'bare'])
    expect(names('10.20.0.1')).toEqual(['web', 'db'])
    expect(names('NGINX')).toEqual(['web'])
    expect(names('freebsd b')).toEqual(['web', 'db', 'build', 'bare'])
    expect(names('-web')).toEqual(['db', 'build', 'bare'])
  })
  it('adds a chip to the filter, replacing the same key, and removes a term', () => {
    expect(withLabel('', 'env', 'prod')).toBe('env=prod')
    expect(withLabel('web env=dev', 'env', 'prod')).toBe('web env=prod')
    expect(withLabel('env=prod', 'env', 'prod')).toBe('env=prod')
    expect(withLabel('team:', 'team', 'web')).toBe('team=web')
    expect(withLabel('x', 'owner', 'Web Ops')).toBe('x owner="Web Ops"')
    expect(withoutTerm('env=prod -team=web db', 1)).toBe('env=prod db')
    expect(queryText(parseQuery('a=1  b:  -c=2 w'))).toBe('a=1 b: -c=2 w')
  })
  it('suggests keys while a key is typed and values after key=', () => {
    const known = knownLabels([jail('a', { env: 'prod', team: 'web', 'jailops.app': 'nginx' }), jail('b', { env: 'prod', tier: 'edge' }), jail('c', { env: 'dev' })])
    expect(suggest('t', 1, known).map((x) => x.text)).toEqual(['team=', 'tier='])
    expect(suggest('', 0, known)).toEqual([])
    const k = suggest('db te', 5, known)[0]
    expect(k).toMatchObject({ text: 'team=', value: 'db team=', caret: 8, count: 1 })
    const v = suggest('env=', 4, known)
    expect(v.map((x) => [x.text, x.count])).toEqual([['env=prod', 2], ['env=dev', 1]])
    expect(v[0]).toMatchObject({ value: 'env=prod ', caret: 9 })
    expect(suggest('env=p web', 5, known)[0]).toMatchObject({ value: 'env=prod web', caret: 8 })
    expect(suggest('-env=d', 6, known)[0]).toMatchObject({ value: '-env=dev ' })
    // system labels come after the others
    expect(suggest('j', 1, known).map((x) => x.text)).toEqual(['jailops.app='])
    expect(suggest('unknown=', 8, known)).toEqual([])
  })
  it('orders chips with the keys people look for first and leaves out system labels', () => {
    expect(chipOrder({ zeta: '1', role: 'web', env: 'prod', 'jailops.app': 'nginx', app: 'nginx', alpha: '2' }).map(([k]) => k)).toEqual(['env', 'app', 'role', 'alpha', 'zeta'])
  })
})
