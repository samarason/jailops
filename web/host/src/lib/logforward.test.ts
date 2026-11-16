import { describe, expect, it } from 'vitest'
import { blankSink, checkSink, failingLong, formOf, parseLabels, plaintextRemote, schemeOf, sinkBody, splitList, withSink } from './logforward'
import type { LogSink } from '@jailops/shared/api/types'

const form = (o: Partial<ReturnType<typeof blankSink>>) => ({ ...blankSink(), ...o })

describe('sink form', () => {
  it('accepts a plain tls syslog sink and builds it with only what was set', () => {
    const f = form({ name: 'central', to: 'tls://logs.example.com:6514', facility: 'local3' })
    expect(checkSink(f, [])).toEqual({})
    expect(sinkBody(f)).toEqual({ name: 'central', type: 'syslog', to: 'tls://logs.example.com:6514', facility: 'local3', sources: {} })
  })

  it('checks the destination against the type', () => {
    expect(checkSink(form({ to: 'https://x.example.com' }), []).to).toBe('syslogScheme')
    expect(checkSink(form({ type: 'webhook', to: 'http://x.example.com' }), []).to).toBe('https')
    expect(checkSink(form({ to: 'logs.example.com:514' }), []).to).toBe('url')
    expect(checkSink(form({ to: 'udp://user@logs.example.com' }), []).to).toBe('url')
    expect(checkSink(form({ to: 'tcp://logs.example.com:99999' }), []).to).toBe('port')
    expect(checkSink(form({ to: 'tcp://logs.example.com:514/x' }), []).to).toBe('path')
    expect(checkSink(form({ to: 'udp://[2001:db8::5]:514' }), [])).toEqual({})
    expect(checkSink(form({ type: 'webhook', to: 'https://hooks.example.com/a?b=c' }), [])).toEqual({})
  })

  it('checks names, files, paths, queue and labels', () => {
    expect(checkSink(form({ name: 'Bad Name' }), []).name).toBe('name')
    expect(checkSink(form({ name: 'central' }), ['central']).name).toBe('taken')
    expect(checkSink(form({ caFile: 'relative.pem', to: 'tls://a.example.com' }), []).caFile).toBe('path')
    expect(checkSink(form({ caFile: '/etc/ca.pem', to: 'udp://a.example.com' }), []).caFile).toBe('caOnlyTLS')
    expect(checkSink(form({ type: 'webhook', tokenFile: '/etc/../x' }), []).tokenFile).toBe('path')
    expect(checkSink(form({ queue: '10' }), []).queue).toBe('queue')
    expect(checkSink(form({ queue: '5000' }), []).queue).toBeUndefined()
    expect(checkSink(form({ jails: 'web, Db' }), []).jails).toBe('names')
    expect(checkSink(form({ labels: 'role=web, oops' }), []).labels).toBe('labels')
    expect(checkSink(form({ files: 'messages.0' }), []).files).toBe('files')
    expect(checkSink(form({ files: 'a/b/c' }), []).files).toBe('files')
    expect(checkSink(form({ files: 'nginx/access.log auth.log' }), []).files).toBeUndefined()
    expect(checkSink(form({ jailLogs: false, audit: false }), []).audit).toBe('nothing')
  })

  it('round-trips a sink through the form, leaving out what does not apply', () => {
    const k: LogSink = { name: 'alerts', type: 'webhook', to: 'https://hooks.example.com/l', token_file: '/usr/local/etc/jailops/sinks/hook.token', queue: 2000,
      sources: { projects: ['web'], labels: { role: 'web' }, exclude_jails: ['build'], exclude_labels: { tier: 'test' }, files: ['messages', 'auth.log'], no_app_logs: true, audit: true } }
    expect(sinkBody(formOf(k))).toEqual(k)
    const syslog = sinkBody(form({ name: 'a', to: 'udp://192.0.2.5', tokenFile: '/x', caFile: '/y', facility: 'local0', jailLogs: false, audit: true }))
    expect(syslog).toEqual({ name: 'a', type: 'syslog', to: 'udp://192.0.2.5', sources: { no_jails: true, audit: true } })
  })

  it('splits lists and labels', () => {
    expect(splitList(' a, b  c,,')).toEqual(['a', 'b', 'c'])
    expect(parseLabels('role=web, tier = front')).toEqual({ labels: { role: 'web', tier: 'front' } })
    expect(parseLabels('=x').bad).toBe('=x')
    expect(schemeOf('tls://h:1')).toBe('tls')
    expect(schemeOf('nope')).toBe('')
  })

  it('warns about plain transport to a remote address only', () => {
    expect(plaintextRemote('syslog', 'udp://192.0.2.5:514')).toBe(true)
    expect(plaintextRemote('syslog', 'tcp://logs.example.com')).toBe(true)
    expect(plaintextRemote('syslog', 'tcp://127.0.0.1:5140')).toBe(false)
    expect(plaintextRemote('syslog', 'udp://[::1]:514')).toBe(false)
    expect(plaintextRemote('syslog', 'tls://logs.example.com')).toBe(false)
    expect(plaintextRemote('webhook', 'https://h.example.com')).toBe(false)
  })

  it('adds, replaces in place and removes sinks', () => {
    const a: LogSink = { name: 'a', type: 'syslog', to: 'tls://a.example.com' }
    const b: LogSink = { name: 'b', type: 'syslog', to: 'tls://b.example.com' }
    expect(withSink([a], b).map((k) => k.name)).toEqual(['a', 'b'])
    expect(withSink([a, b], { ...a, name: 'c' }, 'a').map((k) => k.name)).toEqual(['c', 'b'])
    expect(withSink([a, b], null, 'a').map((k) => k.name)).toEqual(['b'])
  })

  it('says when a sink has failed for more than five minutes', () => {
    const now = Date.parse('2026-03-01T09:00:00Z')
    expect(failingLong(undefined, now)).toBe(false)
    expect(failingLong({ name: 'a', type: 'syslog', to: '', sources: 0, sent: 0, queued: 0, dropped: 0, failing_since: '2026-03-01T08:57:00Z' }, now)).toBe(false)
    expect(failingLong({ name: 'a', type: 'syslog', to: '', sources: 0, sent: 0, queued: 0, dropped: 0, failing_since: '2026-03-01T08:50:00Z' }, now)).toBe(true)
  })
})
