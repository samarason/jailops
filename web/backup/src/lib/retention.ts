import type { Group, RetentionPolicyRow } from '@/types'

export const keepFields = ['last', 'hourly', 'daily', 'weekly', 'monthly', 'yearly'] as const
export type KeepField = (typeof keepFields)[number]

/** The scopes a new policy may get: "default" and every group, less those that have a policy already. The server
 *  stores a policy per scope and replaces it on a second save, so a taken scope is edited, never added again. */
export function freeScopes(rows: RetentionPolicyRow[], groups: Group[]): Array<{ scope: string; host?: string }> {
  const taken = new Set(rows.map((r) => r.scope))
  return [{ scope: 'default' }, ...groups.map((g) => ({ scope: g.group_id, host: g.host_name }))].filter((x) => !taken.has(x.scope))
}

/** What keeps a policy from being saved, field by field (server rule: counts 0 to 100000, at least one above 0). */
export function policyProblems(f: { scope: string; values: Partial<Record<KeepField, number | string | undefined>> }, taken: string[], adding: boolean, msg: { scope: string; taken: (s: string) => string; count: string; none: string }): Record<string, string> {
  const out: Record<string, string> = {}
  if (adding) {
    if (!f.scope) out['pe-scope'] = msg.scope
    else if (taken.includes(f.scope)) out['pe-scope'] = msg.taken(f.scope)
  }
  let sum = 0
  for (const k of keepFields) {
    const raw = f.values[k]
    if (raw === undefined || raw === '') continue
    const n = Number(raw)
    if (!Number.isInteger(n) || n < 0 || n > 100000) out['pe-' + k] = msg.count
    else sum += n
  }
  if (!sum && !out['pe-last']) out['pe-last'] = msg.none
  return out
}
