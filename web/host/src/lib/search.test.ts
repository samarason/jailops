import { beforeEach, describe, expect, it } from 'vitest'
import { entry, loadRecent, pushRecent, rank, RECENT_MAX, scoreText, typingTarget, type Entry } from './search'

const jail = (name: string, labels: Record<string, string> = {}, extra: string[] = []) => entry({ kind: 'jail', id: `jail:web:${name}`, title: name, to: `/jails/${name}`, icon: 'box', labels, state: 'running', extra })
const page = (title: string, to: string) => entry({ kind: 'page', id: `page:${to}`, title, to, icon: 'box' })

describe('scoreText', () => {
  it('ranks exact over prefix over part over anywhere over fuzzy', () => {
    const exact = scoreText('web', 'web')
    const prefix = scoreText('web', 'webmail')
    const part = scoreText('web', 'stg-web')
    const inside = scoreText('web', 'cobweb')
    const fuzzy = scoreText('wb', 'web')
    expect(exact).toBeGreaterThan(prefix)
    expect(prefix).toBeGreaterThan(part)
    expect(part).toBeGreaterThan(inside)
    expect(inside).toBeGreaterThan(fuzzy)
    expect(fuzzy).toBeGreaterThan(0)
  })
  it('prefers the shorter text and the tighter fuzzy match', () => {
    expect(scoreText('db', 'db1')).toBeGreaterThan(scoreText('db', 'db-replica'))
    expect(scoreText('prx', 'proxy')).toBeGreaterThan(scoreText('prx', 'some-long-prefix-pr-proxy'))
  })
  it('does not match letters out of order, or one letter anywhere', () => {
    expect(scoreText('bw', 'web')).toBe(-1)
    expect(scoreText('z', 'web')).toBe(-1)
    expect(scoreText('e', 'web')).toBeGreaterThan(0) // inside a word, not fuzzy
  })
})

describe('rank', () => {
  const index: Entry[] = [
    jail('web', { env: 'prod', team: 'web' }, ['10.20.0.11']),
    jail('api', { env: 'prod', team: 'web', app: 'nginx' }),
    jail('db', { env: 'prod', team: 'data' }, ['10.20.0.12']),
    jail('webmail', { env: 'dev' }),
    entry({ kind: 'app', id: 'app:nginx', title: 'nginx', sub: 'Web server', to: '/apps/nginx', icon: 'store', extra: ['web server'] }),
    entry({ kind: 'project', id: 'project:web', title: 'web', to: '/projects/web', icon: 'users' }),
    page('Networks', '/networks'),
    page('Firewall', '/firewall'),
  ]
  it('groups by kind and puts the best group first', () => {
    const r = rank(index, 'web')
    expect(r.groups[0].kind).toBe('jail')
    expect(r.groups[0].items.map((e) => e.title)).toEqual(['web', 'webmail', 'api'])
    expect(r.groups.map((g) => g.kind)).toContain('project')
    expect(r.total).toBe(r.groups.reduce((n, g) => n + g.items.length + g.more, 0))
  })
  it('filters by label terms and ranks the words among what is left', () => {
    expect(rank(index, 'env=prod').groups.flatMap((g) => g.items.map((e) => e.title))).toEqual(['api', 'db', 'web'])
    expect(rank(index, 'env=prod -team=web').groups.flatMap((g) => g.items.map((e) => e.title))).toEqual(['db'])
    expect(rank(index, 'team: db').groups.flatMap((g) => g.items.map((e) => e.title))).toEqual(['db'])
    // fuzzy letters do not wander across labels: d...b is in "env=prod team=web" but means nothing there
    expect(rank(index, 'db').groups[0].items.map((e) => e.title)).toEqual(['db'])
    // a page has no labels: a label term leaves it out
    expect(rank(index, 'env=prod net').total).toBe(0)
  })
  it('finds a jail by address, label text and app', () => {
    expect(rank(index, '10.20.0.12').groups[0].items[0].title).toBe('db')
    expect(rank(index, 'nginx').groups.map((g) => g.items[0].title)).toEqual(['nginx', 'api'])
    expect(rank(index, 'fire').groups[0].items[0].title).toBe('Firewall')
  })
  it('gives nothing for an empty query and caps each group with a count of the rest', () => {
    expect(rank(index, '  ').groups).toEqual([])
    const many = Array.from({ length: 5000 }, (_, i) => jail(`node-${i}`, { env: i % 2 ? 'prod' : 'dev' }))
    const t0 = performance.now()
    const r = rank(many, 'node env=prod')
    expect(performance.now() - t0).toBeLessThan(500)
    expect(r.groups[0].items).toHaveLength(8)
    expect(r.groups[0].more).toBe(2500 - 8)
    expect(r.total).toBe(2500)
  })
})

describe('recent items', () => {
  beforeEach(() => localStorage.clear())
  it('keeps the newest first, once each, at most RECENT_MAX, per console', () => {
    for (let i = 0; i < RECENT_MAX + 3; i++) pushRecent({ id: `jail:web:j${i}`, kind: 'jail', title: `j${i}`, to: `/jails/j${i}` }, 'a')
    pushRecent({ id: 'jail:web:j5', kind: 'jail', title: 'j5', to: '/jails/j5' }, 'a')
    const l = loadRecent('a')
    expect(l).toHaveLength(RECENT_MAX)
    expect(l[0].id).toBe('jail:web:j5')
    expect(l.filter((x) => x.id === 'jail:web:j5')).toHaveLength(1)
    expect(loadRecent('b')).toEqual([])
  })
  it('survives broken or blocked storage', () => {
    localStorage.setItem('jailops.recent', '{not json')
    expect(loadRecent('a')).toEqual([])
    localStorage.setItem('jailops.recent', JSON.stringify({ a: [{ nope: 1 }, { id: 'x', to: '/x', kind: 'page', title: 'X' }] }))
    expect(loadRecent('a').map((r) => r.id)).toEqual(['x'])
  })
})

describe('typingTarget', () => {
  it('knows where `/` is typed text', () => {
    const mk = (html: string) => {
      document.body.innerHTML = html
      return document.body.firstElementChild
    }
    expect(typingTarget(mk('<input type="text">'))).toBe(true)
    expect(typingTarget(mk('<input type="search">'))).toBe(true)
    expect(typingTarget(mk('<input type="checkbox">'))).toBe(false)
    expect(typingTarget(mk('<textarea></textarea>'))).toBe(true)
    expect(typingTarget(mk('<div class="term" tabindex="0" role="textbox"></div>'))).toBe(true)
    expect(typingTarget(mk('<button>x</button>'))).toBe(false)
    expect(typingTarget(document.body)).toBe(false)
    expect(typingTarget(null)).toBe(false)
  })
})
