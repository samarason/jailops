// Labels on jails: the server's rules (sdk/api/text.go), the filter language of the jails list and the quick switcher,
// and the merge patch that changes them. The server decides; these checks only say early what it would refuse.

export const MAX_LABELS = 64
export const MAX_LABEL_NAME = 63
export const MAX_LABEL_PREFIX = 253
export const MAX_LABEL_VALUE = 253

export type Labels = Record<string, string>

const alnum = (c: string) => /[a-zA-Z0-9]/.test(c)

function nameOK(s: string, max: number, extra: string): boolean {
  if (!s || s.length > max || !alnum(s[0]) || !alnum(s[s.length - 1])) return false
  for (const c of s) if (!alnum(c) && !extra.includes(c)) return false
  return true
}

/** The key rule of ValidLabelKey: a name (letters, digits, '-', '_', '.') with an optional prefix and '/'. */
export function validLabelKey(k: string): boolean {
  const i = k.indexOf('/')
  if (i < 0) return nameOK(k, MAX_LABEL_NAME, '-_.')
  return nameOK(k.slice(i + 1), MAX_LABEL_NAME, '-_.') && nameOK(k.slice(0, i), MAX_LABEL_PREFIX, '-.')
}

/** A character that changes how text is shown instead of being shown (UnsafeRune): controls, bidi and zero width. */
export function unsafeChar(cp: number): boolean {
  return cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || cp === 0x200e || cp === 0x200f || (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2066 && cp <= 0x2069) || (cp >= 0x200b && cp <= 0x200d) || cp === 0x2060 || cp === 0xfeff
}

const utf8Length = (s: string) => new TextEncoder().encode(s).length

export type LabelProblem = '' | 'keyNeeded' | 'key' | 'valueLong' | 'valueUnsafe' | 'tooMany'

/** Why the server would refuse this key, '' when it accepts it. */
export function labelKeyProblem(k: string): LabelProblem {
  if (!k) return 'keyNeeded'
  return validLabelKey(k) ? '' : 'key'
}

/** Why the server would refuse this value: longer than 253 bytes, or not printable text. */
export function labelValueProblem(v: string): LabelProblem {
  if (utf8Length(v) > MAX_LABEL_VALUE) return 'valueLong'
  // a lone surrogate is not valid UTF-8 on the wire
  if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(v)) return 'valueUnsafe'
  for (const ch of v) if (unsafeChar(ch.codePointAt(0) ?? 0)) return 'valueUnsafe'
  return ''
}

/** The first problem of a whole label set, as ValidLabels checks it. */
export function labelsProblem(l: Labels): LabelProblem {
  if (Object.keys(l).length > MAX_LABELS) return 'tooMany'
  for (const [k, v] of Object.entries(l)) {
    const p = labelKeyProblem(k) || labelValueProblem(v)
    if (p) return p
  }
  return ''
}

/** Labels JailOps sets itself (jailops.app and its version and hash): shown, but not offered for editing. */
export function isSystemLabel(k: string): boolean {
  return k.startsWith('jailops.')
}

/** The labels a person set, sorted by key. */
export function userLabels(l: Labels | undefined): Array<[string, string]> {
  return Object.entries(l ?? {}).filter(([k]) => !isSystemLabel(k)).sort(([a], [b]) => a.localeCompare(b))
}

export const labelText = (k: string, v: string) => `${k}=${v}`

/** The keys people look for first come first in a short row of chips; the rest by name. */
const FIRST = ['env', 'app', 'team', 'tier', 'role']
export function chipOrder(l: Labels | undefined): Array<[string, string]> {
  const rank = (k: string) => (FIRST.includes(k) ? FIRST.indexOf(k) : FIRST.length)
  return userLabels(l).sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b))
}

/**
 * The merge patch that turns `from` into `to`: a changed or new key carries its value, a removed one null (a null in a
 * merge patch deletes the key, service.MergePatch). Unchanged keys are left out so a concurrent edit of another key
 * survives.
 */
export function labelPatch(from: Labels | undefined, to: Labels): Record<string, string | null> {
  const out: Record<string, string | null> = {}
  const old = from ?? {}
  for (const [k, v] of Object.entries(to)) if (old[k] !== v) out[k] = v
  for (const k of Object.keys(old)) if (!(k in to)) out[k] = null
  return out
}

// ---- the filter language: env=prod team: -tier=edge web ----

export type Term =
  | { kind: 'label'; key: string; value: string; not: boolean }
  | { kind: 'has'; key: string; not: boolean }
  | { kind: 'word'; text: string; not: boolean }

/** Split on blanks; double quotes keep a value with blanks together (team="web ops"). */
export function tokens(q: string): string[] {
  const out: string[] = []
  let cur = ''
  let quoted = false
  let any = false
  for (const ch of q) {
    if (ch === '"') {
      quoted = !quoted
      any = true
    } else if (!quoted && /\s/.test(ch)) {
      if (any) out.push(cur)
      cur = ''
      any = false
    } else {
      cur += ch
      any = true
    }
  }
  if (any) out.push(cur)
  return out
}

/**
 * Parse a filter: `key=value` (the label has this value), `key:` or `key=` (the jail has the label), a leading `-`
 * turns a term around, anything else is a word matched against the name, image, addresses and labels. Every term must
 * hold. A key that breaks the label rules is a word, so an IPv6 address or a path still searches as text.
 */
export function parseQuery(q: string): Term[] {
  const out: Term[] = []
  for (let t of tokens(q)) {
    let not = false
    if (t.length > 1 && t.startsWith('-')) {
      not = true
      t = t.slice(1)
    }
    const eq = t.indexOf('=')
    if (eq > 0 && validLabelKey(t.slice(0, eq))) {
      const key = t.slice(0, eq)
      const value = t.slice(eq + 1)
      out.push(value ? { kind: 'label', key, value, not } : { kind: 'has', key, not })
      continue
    }
    if (t.endsWith(':') && validLabelKey(t.slice(0, -1))) {
      out.push({ kind: 'has', key: t.slice(0, -1), not })
      continue
    }
    if (t) out.push({ kind: 'word', text: t.toLowerCase(), not })
  }
  return out
}

const quote = (v: string) => (/[\s"]/.test(v) || v === '' ? `"${v.replace(/"/g, '')}"` : v)

export function termText(t: Term): string {
  const neg = t.not ? '-' : ''
  if (t.kind === 'label') return `${neg}${t.key}=${quote(t.value)}`
  if (t.kind === 'has') return `${neg}${t.key}:`
  return neg + quote(t.text)
}

export const queryText = (terms: Term[]) => terms.map(termText).join(' ')

/**
 * Add a label term to a filter (a click on a chip). The same key with another value is replaced, since a jail has one
 * value per key and both could never hold; the same term twice is kept once.
 */
export function withLabel(q: string, key: string, value: string, not = false): string {
  const terms = parseQuery(q).filter((t) => !((t.kind === 'label' || t.kind === 'has') && t.key === key && t.not === not))
  terms.push({ kind: 'label', key, value, not })
  return queryText(terms)
}

/** The filter without one term (the x of an active filter chip). */
export function withoutTerm(q: string, i: number): string {
  return queryText(parseQuery(q).filter((_, j) => j !== i))
}

export interface Searchable {
  metadata: { name: string; labels?: Labels }
  spec: { image?: string }
  status: { addresses?: string[] }
}

/** The text a word is looked for in: name, image, addresses and key=value of every label. */
export function haystack(j: Searchable): string[] {
  return [j.metadata.name, j.spec.image ?? '', ...(j.status.addresses ?? []), ...Object.entries(j.metadata.labels ?? {}).map(([k, v]) => labelText(k, v))].map((h) => h.toLowerCase())
}

export function termHolds(t: Term, labels: Labels, hay: string[]): boolean {
  let hit: boolean
  if (t.kind === 'label') hit = labels[t.key] === t.value
  else if (t.kind === 'has') hit = t.key in labels
  else hit = hay.some((h) => h.includes(t.text))
  return t.not ? !hit : hit
}

/** Whether a jail passes every term of a parsed filter. */
export function matchTerms(j: Searchable, terms: Term[]): boolean {
  if (!terms.length) return true
  const labels = j.metadata.labels ?? {}
  const hay = haystack(j)
  return terms.every((t) => termHolds(t, labels, hay))
}

/** Every key with its values and how many jails carry each, for the suggestions. */
export function knownLabels(list: Array<{ metadata: { labels?: Labels } }>): Map<string, Map<string, number>> {
  const m = new Map<string, Map<string, number>>()
  for (const j of list) {
    for (const [k, v] of Object.entries(j.metadata.labels ?? {})) {
      const vals = m.get(k) ?? new Map<string, number>()
      vals.set(v, (vals.get(v) ?? 0) + 1)
      m.set(k, vals)
    }
  }
  return m
}

export interface Suggestion {
  /** What the list shows. */
  text: string
  /** The whole filter after the suggestion is taken. */
  value: string
  /** The caret position after it. */
  caret: number
  count: number
}

/**
 * Suggestions for the word under the caret: label keys while a key is typed (taken as `key=`), and the values of the
 * key once `key=` is typed. System labels come last; at most `max`.
 */
export function suggest(q: string, caret: number, known: Map<string, Map<string, number>>, max = 8): Suggestion[] {
  let start = caret
  while (start > 0 && !/\s/.test(q[start - 1])) start--
  let end = caret
  while (end < q.length && !/\s/.test(q[end])) end++
  let word = q.slice(start, caret)
  let neg = ''
  if (word.startsWith('-')) {
    neg = '-'
    word = word.slice(1)
  }
  const put = (text: string, finished: boolean) => {
    const before = q.slice(0, start) + neg + text
    const after = q.slice(end)
    const sep = finished ? (after.startsWith(' ') ? '' : ' ') : ''
    return { value: before + sep + after, caret: before.length + sep.length }
  }
  const sys = (k: string) => (isSystemLabel(k) ? 1 : 0)
  const eq = word.indexOf('=')
  if (eq > 0) {
    const key = word.slice(0, eq)
    const part = word.slice(eq + 1).replace(/^"/, '').toLowerCase()
    const vals = known.get(key)
    if (!vals) return []
    return [...vals.entries()]
      .filter(([v]) => v.toLowerCase().startsWith(part) && v !== word.slice(eq + 1))
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, max)
      .map(([v, count]) => ({ text: labelText(key, v), count, ...put(`${key}=${quote(v)}`, true) }))
  }
  if (!word) return []
  const w = word.replace(/:$/, '').toLowerCase()
  return [...known.entries()]
    .filter(([k]) => k.toLowerCase().startsWith(w) && k !== word)
    .sort((a, b) => sys(a[0]) - sys(b[0]) || a[0].localeCompare(b[0]))
    .slice(0, max)
    .map(([k, vals]) => ({ text: `${k}=`, count: [...vals.values()].reduce((x, y) => x + y, 0), ...put(`${k}=`, false) }))
}

/**
 * The labels typed into one field (`env=prod team=web`, as `--label` takes them): the labels, or the first problem.
 * Every item is key=value; a key of JailOps itself is refused, as it is set by an installation.
 */
export function parseLabelField(text: string): { labels: Labels; problem: LabelProblem | 'format' | 'system' } {
  const labels: Labels = {}
  for (const t of tokens(text)) {
    const eq = t.indexOf('=')
    if (eq <= 0) return { labels, problem: 'format' }
    const k = t.slice(0, eq)
    const v = t.slice(eq + 1)
    const p = isSystemLabel(k) ? 'system' : labelKeyProblem(k) || labelValueProblem(v)
    if (p) return { labels, problem: p }
    labels[k] = v
  }
  return { labels, problem: Object.keys(labels).length > MAX_LABELS ? 'tooMany' : '' }
}
