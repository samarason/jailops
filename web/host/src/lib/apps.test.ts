import { describe, expect, it } from 'vitest'
import {
  categoryCounts, searchApps, monogram, validateInstall, initialForm, installBody, grants, parseStep, stepsDone, stepState,
  volumeName, installedJails, openLinks, webPorts, installBlock,
} from './apps'
import type { AppSummary, Jail, Project } from '@jailops/shared/api/types'

const app = (name: string, category: AppSummary['category'], extra: Partial<AppSummary> = {}): AppSummary => ({ name, title: name[0].toUpperCase() + name.slice(1), summary: `${name} summary`, category, valid: true, source: 'catalog', ...extra })
const list = [app('nginx', 'web', { summary: 'Web server and reverse proxy' }), app('postgresql', 'database'), app('valkey', 'database', { summary: 'key-value store' }), app('wiki', 'tools', { valid: false, error: 'bad' })]

describe('catalog search and categories', () => {
  it('searches name, title and summary, case-insensitively, invalid ones last', () => {
    expect(searchApps(list, '').map((a) => a.name)).toEqual(['nginx', 'postgresql', 'valkey', 'wiki'])
    expect(searchApps(list, 'PROXY').map((a) => a.name)).toEqual(['nginx'])
    expect(searchApps(list, 'Postgres').map((a) => a.name)).toEqual(['postgresql'])
    expect(searchApps(list, '', 'database').map((a) => a.name)).toEqual(['postgresql', 'valkey'])
    expect(searchApps(list, 'key', 'web')).toEqual([])
  })
  it('counts categories of what matches, in catalog order, without empty ones', () => {
    expect(categoryCounts(list, '')).toEqual([{ category: 'database', count: 2 }, { category: 'web', count: 1 }, { category: 'tools', count: 1 }])
    expect(categoryCounts(list, 'store')).toEqual([{ category: 'database', count: 1 }])
  })
  it('makes a stable monogram', () => {
    expect(monogram('postgresql', 'PostgreSQL').text).toBe('PO')
    expect(monogram('team-wiki', 'Team wiki').text).toBe('TW')
    expect(monogram('nginx').hue).toBe(monogram('nginx').hue)
    expect(monogram('nginx').hue).toBeLessThan(360)
  })
})

describe('install form', () => {
  const ctx = { networks: ['lan', 'edge'], storage: ['default'], taken: ['web'] }
  const hints = { memory: '256M', disk: '2G', cpu: '1' }
  it('prefills the app name, the only grant and the hints', () => {
    expect(initialForm('nginx', hints, ['lan', 'edge'], ['default'])).toEqual({ jail: 'nginx', image: '', network: '', storage: 'default', memory: '256M', disk: '2G', cpu: '1' })
    expect(initialForm('nginx', undefined, ['lan'], []).network).toBe('lan')
  })
  it('validates like the server: names, grants, sizes and cpu', () => {
    const ok = { jail: 'nginx', image: '', network: 'lan', storage: 'default', memory: '256M', disk: '2G', cpu: '1' }
    expect(validateInstall(ok, ctx)).toEqual({})
    expect(validateInstall({ ...ok, jail: 'Nginx' }, ctx).jail).toBe('nameInvalid')
    expect(validateInstall({ ...ok, jail: '1web' }, ctx).jail).toBe('nameInvalid')
    expect(validateInstall({ ...ok, jail: 'web.1' }, ctx).jail).toBe('nameInvalid')
    expect(validateInstall({ ...ok, jail: 'a'.repeat(33) }, ctx).jail).toBe('nameInvalid')
    expect(validateInstall({ ...ok, jail: 'a'.repeat(32) }, ctx).jail).toBeUndefined()
    expect(validateInstall({ ...ok, memory: '4GiB', disk: '512m' }, ctx)).toEqual({})
    expect(validateInstall({ ...ok, memory: '1.5G' }, ctx).memory).toBe('sizeInvalid')
    expect(validateInstall({ ...ok, jail: 'web' }, ctx).jail).toBe('nameTaken')
    expect(validateInstall({ ...ok, network: '' }, ctx).network).toBe('needNetwork')
    expect(validateInstall({ ...ok, storage: 'fast' }, ctx).storage).toBe('needStorage')
    expect(validateInstall({ ...ok, memory: 'lots', disk: '10Q', cpu: '0' }, ctx)).toEqual({ memory: 'sizeInvalid', disk: 'sizeInvalid', cpu: 'cpuInvalid' })
    // without known grants the server picks the defaults
    expect(validateInstall({ ...ok, network: '', storage: '' }, { networks: [], storage: [], taken: [] })).toEqual({})
  })
  it('sends limits only when they differ from the hints', () => {
    const f = { jail: 'nginx', image: '', network: 'lan', storage: 'default', memory: '256M', disk: '2G', cpu: '1' }
    expect(installBody(f, hints)).toEqual({ jail: 'nginx', network: 'lan', storage: 'default' })
    expect(installBody({ ...f, image: 'freebsd-15-2' }, hints)).toEqual({ jail: 'nginx', image: 'freebsd-15-2', network: 'lan', storage: 'default' })
    expect(installBody({ ...f, memory: '1G', cpu: '2' }, hints, true)).toEqual({ jail: 'nginx', network: 'lan', storage: 'default', limits: { memory: '1G', disk: '2G', cpu: 2 }, dry_run: true })
  })
  it('reads the grants of a project; "*" is every storage', () => {
    const p = { spec: { networks: [{ network: 'lan' }], storage: [{ storage: '*' }] } } as Project
    expect(grants(p, ['default', 'fast'])).toEqual({ networks: ['lan'], storage: ['default', 'fast'] })
    expect(grants(undefined, ['x'])).toEqual({ networks: [], storage: [] })
  })
  it('says why the caller cannot install', () => {
    const base = { ext: true, needProject: true, project: 'web', role: 'operator', global: false, scopes: ['web'], known: true, networks: ['lan'], storage: ['default'] }
    expect(installBlock(base)).toBe('')
    expect(installBlock({ ...base, role: 'admin', global: true, scopes: [] })).toBe('')
    expect(installBlock({ ...base, role: '' })).toBe('') // unknown identity: the server decides
    expect(installBlock({ ...base, ext: false })).toBe('noExtension')
    expect(installBlock({ ...base, project: '' })).toBe('noProject')
    expect(installBlock({ ...base, role: 'readonly' })).toBe('role')
    expect(installBlock({ ...base, scopes: ['shop'] })).toBe('scope')
    expect(installBlock({ ...base, networks: [] })).toBe('noNetwork')
    expect(installBlock({ ...base, storage: [] })).toBe('noStorage')
    expect(installBlock({ ...base, known: false, networks: [], storage: [] })).toBe('')
  })
})

describe('install steps', () => {
  const steps = ['01 create-jail: create thin jail nginx', '02 start-jail: start nginx', '03 install-packages-ports: pkg -r /r install -y nginx', '04 health-check: GET /', '05 snapshot: snapshot every dataset']
  const parsed = steps.map(parseStep)
  it('parses the server form', () => {
    expect(parsed[2]).toEqual({ n: 3, name: 'install-packages-ports', text: 'pkg -r /r install -y nginx' })
    expect(parseStep('free text')).toEqual({ n: 0, name: '', text: 'free text' })
  })
  it('recovers the finished steps from the progress the server reports', () => {
    for (const total of [5, 11, 12, 13, 40, 99]) {
      for (let k = 0; k < total; k++) {
        const progress = Math.min(99, Math.floor(((k) * 100) / total))
        expect(stepsDone(progress, total), `k=${k} of ${total}`).toBe(k)
      }
      expect(stepsDone(99, total)).toBe(total)
    }
    expect(stepsDone(undefined, 5)).toBe(0)
    expect(stepsDone(40, 5, true)).toBe(5)
  })
  it('gives each step its state, the failed one by name', () => {
    expect(parsed.map((_, i) => stepState(i, parsed, 2, 'running'))).toEqual(['done', 'done', 'running', 'pending', 'pending'])
    expect(parsed.map((_, i) => stepState(i, parsed, 2, 'success'))).toEqual(['done', 'done', 'done', 'done', 'done'])
    expect(parsed.map((_, i) => stepState(i, parsed, 2, 'failure', 'health-check'))).toEqual(['done', 'done', 'done', 'failed', 'pending'])
    expect(parsed.map((_, i) => stepState(i, parsed, 1, 'failure'))).toEqual(['done', 'failed', 'pending', 'pending', 'pending'])
  })
  it('names the volume of a path after the path (the jail name comes before it)', () => {
    expect(volumeName('/var/db/postgres')).toBe('var-db-postgres')
  })
})

describe('installed apps', () => {
  const jail = (name: string, labels: Record<string, string> | undefined, power: Jail['status']['power'] = 'running', addresses = ['10.20.0.40/24']): Jail => ({ metadata: { name, labels }, spec: { image: 'x' }, status: { power, addresses } })
  const jails = [jail('web', { 'jailops.app': 'nginx' }), jail('db', { role: 'db' }), jail('a-forge', { 'jailops.app': 'forgejo' }), jail('plain', undefined), jail('www2', { 'jailops.app': 'nginx' }, 'stopped', [])]
  it('keeps the jails with the jailops.app label, optionally of one app', () => {
    expect(installedJails(jails).map((j) => j.metadata.name)).toEqual(['a-forge', 'web', 'www2'])
    expect(installedJails(jails, 'nginx').map((j) => j.metadata.name)).toEqual(['web', 'www2'])
    expect(installedJails(jails, 'none')).toEqual([])
  })
  it('links only exposed http and https tcp ports of a running jail, on its first address', () => {
    const ports = [
      { name: 'http', port: 80, proto: 'tcp', expose: true }, { name: 'https', port: 443, proto: 'tcp', expose: true },
      { name: 'http', port: 3000, proto: 'udp', expose: true }, { name: 'metrics', port: 9100, proto: 'tcp', expose: true }, { name: 'http', port: 8080, proto: 'tcp', expose: false },
    ]
    expect(webPorts(ports).map((p) => p.port)).toEqual([80, 443, 8080])
    expect(openLinks(jails[0], ports).map((l) => l.url)).toEqual(['http://10.20.0.40/', 'https://10.20.0.40/'])
    expect(openLinks(jail('v6', {}, 'running', ['2001:db8::5/64']), [{ name: 'http', port: 3000, proto: 'tcp', expose: true }]).map((l) => l.url)).toEqual(['http://[2001:db8::5]:3000/'])
    expect(openLinks(jails[4], ports)).toEqual([])
  })
})

describe('demo catalog sources', () => {
  it('lists every entry with its source and one local definition, read from apps.local_dir', async () => {
    const demo = await import('@/demo/apps')
    const list = demo.catalog()
    expect(list.every((a) => a.source === 'catalog' || a.source === 'local')).toBe(true)
    expect(list.filter((a) => a.source === 'local').map((a) => a.name)).toEqual(['memcached'])
    const d = demo.detail('memcached')
    expect(d && d !== 'invalid' && d.source).toBe('local')
    expect(d && d !== 'invalid' && d.file).toBe('/usr/local/etc/jailops/apps/memcached.yaml')
    const n = demo.detail('nginx')
    expect(n && n !== 'invalid' && n.source).toBe('catalog')
  })
})
