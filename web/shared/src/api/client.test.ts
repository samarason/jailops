import { describe, expect, it } from 'vitest'
import { Client, ApiError, type Transport, type RawRequest, type RawResponse } from './client'

function fake(handler: (r: RawRequest) => RawResponse): { t: Transport; calls: RawRequest[] } {
  const calls: RawRequest[] = []
  return { calls, t: { request: async (r) => (calls.push(r), handler(r)), stream: () => ({ close() {} }) } }
}
const sync = (metadata: unknown, etag?: string): RawResponse => ({ status: 200, etag, envelope: { type: 'sync', metadata } })

describe('Client', () => {
  it('unwraps sync metadata and normalises null lists', async () => {
    const { t } = fake(() => sync(null))
    expect(await new Client(t).list('/jails')).toEqual([])
  })
  it('throws ApiError with code, hint and notifies on 401', async () => {
    const { t } = fake(() => ({ status: 401, envelope: { type: 'error', error: { code: 'unauthorized', message: 'no', hint: 'sign in' } } }))
    const c = new Client(t)
    let hit = 0
    c.onUnauthorized(() => hit++)
    const e = (await c.get('/x').catch((x: unknown) => x)) as ApiError
    expect(e).toBeInstanceOf(ApiError)
    expect(e.code).toBe('unauthorized')
    expect(e.hint).toBe('sign in')
    expect(hit).toBe(1)
  })
  it('returns the operation of an async reply and sends If-Match', async () => {
    const { t, calls } = fake(() => ({ status: 202, envelope: { type: 'async', operation: '/api/v1/operations/o1', metadata: { id: 'o1', status: 'running' } } }))
    const r = await new Client(t).mutate('PUT', '/firewall/policies/p', {}, { etag: '"3"' })
    expect(r.kind === 'async' && r.op.id).toBe('o1')
    expect(calls[0].headers?.['If-Match']).toBe('"3"')
  })
  it('exposes the ETag', async () => {
    const { t } = fake(() => sync({ a: 1 }, '"7"'))
    expect((await new Client(t).getWithEtag('/x')).etag).toBe('"7"')
  })
})

import { handleFrame, codeFromStatus, storeCsrf, HttpTransport } from './client'
import type { ApiEvent } from './types'
import { vi } from 'vitest'

describe('SSE and protocol helpers', () => {
  it('parses frames: data, id, retry, comments', () => {
    const got: ApiEvent[] = []
    let retry = 0
    const h = { onEvent: (e: ApiEvent) => got.push(e), onRetry: (n: number) => (retry = n) }
    handleFrame(': keep-alive', h)
    handleFrame('id: 4\nretry: 3000\nevent: lifecycle\ndata: {"type":"lifecycle","timestamp":"t","metadata":{}}', h)
    expect(got).toHaveLength(1)
    expect(retry).toBe(3000)
  })
  it('maps non-JSON statuses as the protocol says', () => {
    expect([400, 401, 403, 404, 405, 409, 412, 429, 502, 418, 500].map(codeFromStatus)).toEqual(['invalid', 'unauthorized', 'forbidden', 'not_found', 'unsupported', 'already_exists', 'conflict', 'busy', 'busy', 'invalid', 'internal'])
  })
  it('sends the CSRF token from the login reply on state-changing requests only', async () => {
    storeCsrf('tok-1')
    const seen: Record<string, string>[] = []
    vi.stubGlobal('fetch', async (_u: string, init: RequestInit) => {
      seen.push(init.headers as Record<string, string>)
      return new Response(JSON.stringify({ type: 'sync', metadata: null }), { status: 200 })
    })
    const t = new HttpTransport()
    await t.request({ method: 'GET', path: '/x' })
    await t.request({ method: 'POST', path: '/x', body: {} })
    vi.unstubAllGlobals()
    storeCsrf('')
    expect(seen[0]['X-CSRF-Token']).toBeUndefined()
    expect(seen[1]['X-CSRF-Token']).toBe('tok-1')
  })
})

import { storeToken, storedToken } from './client'
import { boot, session, demoBuild } from '../composables/session'

describe('credentials in the browser', () => {
  it('forgets an API token the server answers 401 to', async () => {
    storeToken('jot_revoked')
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({ type: 'error', error: { code: 'unauthorized', message: 'no' } }), { status: 401 }))
    await new HttpTransport().request({ method: 'GET', path: '/jails' })
    expect(storedToken()).toBe('')
    vi.unstubAllGlobals()
  })
  it('a console without the demo ignores ?demo', async () => {
    expect(demoBuild).toBe(false)
    history.replaceState(null, '', '/?demo')
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({ type: 'sync', metadata: { api_version: '1.0', api_extensions: [], role: 'host', auth: 'untrusted' } }), { status: 200 }))
    await boot({ role: 'host' })
    expect(session.demo).toBe(false)
    expect(session.demoAvailable).toBe(false)
    expect(sessionStorage.getItem('jailops.demo')).toBeNull()
    vi.unstubAllGlobals()
    history.replaceState(null, '', '/')
  })
})

describe('streams', () => {
  it('a stream path goes through the request filter, the project included', () => {
    const paths: string[] = []
    const c = new Client({ request: async () => sync(null), stream: (p) => (paths.push(p), { close() {} }) })
    c.setRequestFilter((p) => p + '?project=web')
    c.stream('/jails/a/console/x/output', { onEvent() {} })
    expect(paths).toEqual(['/jails/a/console/x/output?project=web'])
  })
})
