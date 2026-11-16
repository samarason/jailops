// Turn what the API records (routes, object paths, error codes) into words and links, so no API path is shown to a
// user. The words for codes are in i18n/common.ts (codes); an app passes the kinds it links to.
import { common as s } from '../i18n/common'

export interface ObjectRef {
  /** "jail", "firewall policy" */
  kind: string
  name: string
  /** console route of the object, when the app has a page for it */
  to?: string
}

/** Kind words and console routes of the first path segment under /api/v1 ("jails" -> jail, /jails/NAME). */
export type KindMap = Record<string, { kind: string; to?: (name: string) => string }>

// the prefix of every recorded path; matched as text, never requested from here
const PREFIX = '/api/v1'

function trimApi(p: string): string[] {
  return p.replace(/^\/?api\/v1\/?/, '').replace(/\?.*$/, '').split('/').filter(Boolean)
}

/** "/api/v1/jails/cache" -> jail cache, linked to /jails/cache. Not an API path: undefined. */
export function objectOf(path: string | undefined, kinds: KindMap): ObjectRef | undefined {
  if (!path || !path.includes(PREFIX)) return undefined
  const seg = trimApi(path).map(decodeURIComponent)
  if (!seg.length) return undefined
  // "firewall/policies/x" names its kind with two segments
  const two = seg.length >= 3 ? kinds[`${seg[0]}/${seg[1]}`] : undefined
  const k = two ?? kinds[seg[0]]
  const name = two ? seg[2] : seg[1]
  if (!k || !name) return { kind: seg[0], name: seg.slice(1).join('/') }
  return { kind: k.kind, name, to: k.to?.(name) }
}

/** An audit action: "POST /api/v1/jails/{name}/upgrade" -> "Upgrade jail"; "jail.start" -> "Start jail". */
export function actionText(action: string, kinds: KindMap): string {
  const m = /^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)$/.exec(action.trim())
  if (m) {
    const seg = trimApi(m[2])
    const twoKey = seg.length >= 2 && !seg[1].startsWith('{') ? `${seg[0]}/${seg[1]}` : ''
    const k = kinds[twoKey] ?? kinds[seg[0]]
    const kind = k?.kind ?? (seg[0] ?? '').replace(/-/g, ' ').replace(/s$/, '')
    const rest = seg.slice(twoKey && kinds[twoKey] ? 2 : 1).filter((x) => !x.startsWith('{'))
    const sub = rest.length ? rest[rest.length - 1].replace(/-/g, ' ') : ''
    if (sub) return cap(m[1] === 'DELETE' ? `delete ${kind} ${sub}` : m[1] === 'GET' ? `read ${kind} ${sub}` : `${sub} ${kind}`)
    const verb = m[1] === 'POST' && seg.length > 1 && seg[1].startsWith('{') ? 'Change' : s.verbs[m[1]] ?? m[1]
    return `${verb} ${kind}`
  }
  const d = /^([a-z-]+)\.([a-z.-]+)$/.exec(action)
  if (d) return cap(`${d[2].replace(/[.-]/g, ' ')} ${d[1]}`).replace(/^Update /, 'Change ')
  return cap(action)
}

/** An error code or condition reason in words; unknown codes come back as they are. */
export function codeText(code: string | undefined): string {
  if (!code) return ''
  return s.codes[code] ?? code
}

function cap(x: string): string {
  return x.charAt(0).toUpperCase() + x.slice(1)
}
