import type { Router } from 'vue-router'
import { hasExt, session } from '@jailops/shared/composables/session'
import { projectState } from '@/composables/project'
import { lifecycle } from '@/composables/jailActions'

// Who is offered the shell and the label editor. The server decides in the end (a console session needs operator in
// the jail's project, exactly as `jailops exec`; a PATCH of the labels needs admin); the console only avoids offering
// what it would refuse. An identity whose role is unknown (a token without a session) may try.

function inScope(project = projectState.current): boolean {
  return !session.role || session.global || !project || session.projects.includes(project)
}

/** The console session (extension jail_console) for an operator or admin of the project. */
export function canShell(project?: string): boolean {
  const r = session.role
  return hasExt('jail_console') && (!r || r === 'operator' || r === 'admin') && inScope(project)
}

/** Labels change with PATCH /jails/{name}, which needs admin in the project. */
export function canEditLabels(project?: string): boolean {
  const r = session.role
  return (!r || r === 'admin') && inScope(project)
}

/** The address of a jail's shell: the Console tab, connecting at once. Shareable. */
export const shellPath = (name: string) => `/jails/${encodeURIComponent(name)}/shell`

/**
 * Open the shell of a jail. A jail that is not running is started first (start is tier 1: it runs at once, a failure
 * is the toast's), and the shell connects as soon as it runs. A locked jail goes to its page, where Unlock is.
 */
export function goShell(router: Router, name: string, power: string): Promise<unknown> {
  if (power === 'locked') return router.push(`/jails/${encodeURIComponent(name)}`)
  if (power !== 'running' && power !== 'starting') void lifecycle(name, 'start').catch(() => undefined)
  return router.push(shellPath(name))
}

/** The command line that opens the same shell: the jail's shell key, else /bin/sh, as root. */
export function shellCommand(name: string, project: string): string {
  return `jailops shell ${name}${project ? ` --project ${project}` : ''}`
}

// ---- the last tab of each jail page, per console origin and project ----

const TAB_KEY = 'jailops.jailTab'

export function loadJailTab(project: string, name: string, scope = typeof location !== 'undefined' ? location.origin : ''): string {
  try {
    const all = JSON.parse(localStorage.getItem(TAB_KEY) ?? '{}') as Record<string, Record<string, string>>
    return all[scope]?.[`${project}/${name}`] ?? ''
  } catch {
    return ''
  }
}

export function saveJailTab(project: string, name: string, tab: string, scope = typeof location !== 'undefined' ? location.origin : ''): void {
  try {
    const all = JSON.parse(localStorage.getItem(TAB_KEY) ?? '{}') as Record<string, Record<string, string>>
    const mine = { ...(all[scope] ?? {}) }
    if (tab === 'overview') delete mine[`${project}/${name}`]
    else mine[`${project}/${name}`] = tab
    // a bounded map: the oldest entries go first
    const keys = Object.keys(mine)
    for (const k of keys.slice(0, Math.max(0, keys.length - 200))) delete mine[k]
    all[scope] = mine
    localStorage.setItem(TAB_KEY, JSON.stringify(all))
  } catch {
    /* storage blocked: every jail opens on its overview */
  }
}
