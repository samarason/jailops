import { describe, expect, it } from 'vitest'
import { noteBlocks, validateInstall } from './apps'
import { helpText, ALL_KEYS } from './configKeys'
import { deleteItems } from '@/composables/jailActions'

describe('notes of a definition', () => {
  it('keeps commands apart from the prose', () => {
    const b = noteBlocks("Connect with: jailops exec NAME -- psql\nThe jail is closed.\n\nIn the zone:\nblock:\n  notify: 192.0.2.1 NOKEY\n  provide-xfr: 192.0.2.1 NOKEY\n1. Run 'service nsd restart' now.\n2. service isms start\nThe web interface is on port 8080.")
    expect(b[0]).toEqual({ kind: 'p', parts: [{ code: false, text: 'Connect with: ' }, { code: true, text: 'jailops exec NAME -- psql' }, { code: false, text: ' ' }, { code: false, text: 'The jail is closed.' }] })
    expect(b[2]).toEqual({ kind: 'pre', text: 'notify: 192.0.2.1 NOKEY\nprovide-xfr: 192.0.2.1 NOKEY' })
    expect(b[3]).toEqual({ kind: 'p', parts: [{ code: false, text: '1. Run ' }, { code: true, text: 'service nsd restart' }, { code: false, text: ' now.' }] })
    expect(b[4]).toEqual({ kind: 'p', parts: [{ code: false, text: '2. ' }, { code: true, text: 'service isms start' }] })
    expect(b[5]).toEqual({ kind: 'p', parts: [{ code: false, text: 'The web interface is on port 8080.' }] })
  })
  it('marks jailops commands inside a sentence', () => {
    const [p] = noteBlocks('Allow it on the Access tab (jailops app allow) first.')
    expect(p).toEqual({ kind: 'p', parts: [{ code: false, text: 'Allow it on the Access tab (' }, { code: true, text: 'jailops app allow' }, { code: false, text: ') first.' }] })
  })
})

describe('install form', () => {
  it('uses the server name rule', () => {
    const ok = { jail: 'web-2', image: '', network: 'lan', storage: 'default', memory: '', disk: '', cpu: '' }
    const ctx = { networks: ['lan'], storage: ['default'], taken: [] }
    expect(validateInstall(ok, ctx)).toEqual({})
    expect(validateInstall({ ...ok, jail: 'web_2' }, ctx).jail).toBe('nameInvalid')
  })
})

describe('config key help', () => {
  it('reads the registry as written: it carries no developer markers', () => {
    expect(helpText(' Rate limit in.  Not enforced yet. ')).toBe('Rate limit in. Not enforced yet.')
    expect(helpText(undefined)).toBe('')
    for (const k of ALL_KEYS) expect(k.description ?? '').not.toMatch(/UNVERIFIED|^Not yet:/)
  })
})

describe('deleting a jail', () => {
  it('lists the root and the snapshots; the volumes it attaches stay', () => {
    const j = { metadata: { name: 'db' }, spec: { image: 'x', volumes: [{ volume: 'pgdata', mount: '/var/db/postgres' }] }, status: { power: 'running' } }
    const items = deleteItems(j as never, [{ status: { written: 1024 } }, { status: { written: 1024 } }] as never)
    expect(items).toEqual(['the root file system of db', '2 snapshots of the jail'])
  })
})
