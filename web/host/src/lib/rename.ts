// Rename (extension rename): the name rule of each kind, the If-Match of the generation a page read, and the plan of a
// dry run in words (the changes grouped by what they touch, the counts as a sentence). The server is the judge.
import type { RenameChange } from '@jailops/shared/api/types'
import type { NameRule } from '@jailops/shared/lib/names'
import { nameError } from './nameField'

export type RenameKind = 'network' | 'image' | 'project' | 'jail' | 'policy' | 'addressSet' | 'profile'

/** The name rule of each kind: the one its create follows (shared/lib/names.ts). */
export const renameRule: Record<RenameKind, NameRule> = {
  network: 'object', image: 'object', project: 'project', jail: 'object', policy: 'object', addressSet: 'addressSet', profile: 'object',
}

/** The message under the New name field, or '' when the server would take it. */
export function renameProblem(kind: RenameKind, from: string, to: string, same: string): string {
  return nameError(to, renameRule[kind]) || (to === from ? same : '')
}

/** If-Match for the generation of the object as the page read it; nothing when the page has none. */
export function ifMatch(generation: number | undefined): string | undefined {
  return generation === undefined || generation === null ? undefined : `"${generation}"`
}

/** The kinds of change in the order the plan lists them: the object, what refers to it, then the host's side. */
export const CHANGE_ORDER = ['object', 'reference', 'dataset', 'anchor', 'interface', 'file', 'state']

export interface ChangeGroup {
  kind: string
  items: RenameChange[]
}

/** The changes grouped by kind, in CHANGE_ORDER; a kind the console does not know comes last, as it is. */
export function groupChanges(changes: RenameChange[] | null | undefined): ChangeGroup[] {
  const by = new Map<string, RenameChange[]>()
  for (const c of changes ?? []) {
    const list = by.get(c.kind) ?? []
    list.push(c)
    by.set(c.kind, list)
  }
  const rank = (k: string) => (CHANGE_ORDER.includes(k) ? CHANGE_ORDER.indexOf(k) : CHANGE_ORDER.length)
  return [...by.entries()].sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b)).map(([kind, items]) => ({ kind, items }))
}

/** "1 object, 3 references and 2 datasets": the counts in words, in the order of the groups. `word` names a kind. */
export function countsText(counts: Record<string, number> | null | undefined, word: (kind: string, n: number) => string, and: string): string {
  const parts = groupChanges(Object.entries(counts ?? {}).filter(([, n]) => n > 0).map(([kind]) => ({ kind, object: '' })))
    .map((g) => word(g.kind, counts![g.kind]))
  if (parts.length < 2) return parts.join('')
  return `${parts.slice(0, -1).join(', ')} ${and} ${parts[parts.length - 1]}`
}

/** The page of the object under its new name, when the page shown is the object's own page; else null. */
export function renamedAddress(kind: RenameKind, from: string, to: string, current: string): string | null {
  const base = kind === 'jail' ? '/jails/' : kind === 'project' ? '/projects/' : ''
  if (!base) return null
  const own = base + encodeURIComponent(from)
  if (current !== own && !current.startsWith(own + '/') && !current.startsWith(own + '?')) return null
  return base + encodeURIComponent(to) + current.slice(own.length)
}

/** A sentence of the server with its first letter capitalised; names and paths in it stay as they are. */
export function capFirst(x: string): string {
  return x.charAt(0).toUpperCase() + x.slice(1)
}
