import { api } from '@/api/endpoints'
import { runOp } from '@jailops/shared/composables/ops'
import { confirmAction } from '@jailops/shared/composables/confirm'
import { plural } from '@jailops/shared/lib/format'
import { s } from '@/i18n'
import { isInstalledApp } from '@/lib/access'
import type { Jail, JailSnapshot } from '@jailops/shared/api/types'

export type Lifecycle = 'start' | 'stop' | 'restart'
const label: Record<Lifecycle, string> = { start: s.jails.start, stop: s.jails.stop, restart: s.jails.restart }

export function lifecycle(name: string, action: Lifecycle): Promise<unknown> {
  return runOp(s.jails.actionTitle(label[action], name), () => api.jails.action(name, { action }))
}

/**
 * Start runs at once (tier 1); stopping or restarting a running jail asks first (tier 2) and names the jail, so a
 * misplaced click does not cut off its users.
 */
export function askLifecycle(name: string, action: Lifecycle, power: string, done?: () => void): void {
  const run = () => lifecycle(name, action)
  if (action === 'start' || power !== 'running') {
    void run().then(() => done?.(), () => undefined)
    return
  }
  confirmAction({
    title: s.jails.actionTitle(label[action], name),
    confirmLabel: label[action],
    text: action === 'stop' ? s.jails.stopText(name) : s.jails.restartText(name),
    items: [name],
    itemsLabel: s.jails.affectedJails,
    danger: action === 'stop',
    run,
    done,
  })
}

/** Stop several jails after one confirmation that lists the running ones. */
export function askStopMany(jails: Array<{ metadata: { name: string }; status: { power: string } }>, done?: () => void): void {
  const names = jails.map((j) => j.metadata.name)
  const running = jails.filter((j) => j.status.power === 'running').map((j) => j.metadata.name)
  const run = () => lifecycleMany(names, 'stop')
  if (!running.length) {
    void run().then(() => done?.())
    return
  }
  confirmAction({ title: s.jails.bulkTitle(s.jails.stop, names.length), confirmLabel: s.jails.stopSel, text: s.jails.stopManyText, items: running, itemsLabel: s.jails.affectedJails, danger: true, run, done })
}

/** What deleting a jail destroys, one line each: its root and the snapshots. The volumes it attaches stay. */
export function deleteItems(j: Jail, snaps: JailSnapshot[]): string[] {
  return [s.jails.rootItem(j.metadata.name), ...(snaps.length ? [s.jails.snapshotItem(plural(snaps.length, 'snapshot'))] : [])]
}

/**
 * Delete a jail: data loss, so the name is typed (tier 3). An installed app is a jail too: there it is "uninstall",
 * a tier-2 confirmation. The volumes with the app's data stay.
 */
export function askDelete(j: Jail, snaps: JailSnapshot[], done?: () => void): void {
  const name = j.metadata.name
  const run = () => runOp(isInstalledApp(j) ? s.jails.uninstallTitle(appOf(j), name) : s.jails.deleteTitle(name), () => api.jails.remove(name))
  if (isInstalledApp(j)) {
    confirmAction({ title: s.jails.uninstallTitle(appOf(j), name), confirmLabel: s.jails.uninstall, text: s.jails.uninstallText(appOf(j), name), items: deleteItems(j, snaps), itemsLabel: s.jails.destroyed, danger: true, run, done })
    return
  }
  confirmAction({ title: s.jails.deleteTitle(name), confirmLabel: s.jails.delete, text: s.jails.deleteText, items: deleteItems(j, snaps), itemsLabel: s.jails.destroyed, typeName: name, typeLabel: s.jails.typeName(name), danger: true, run, done })
}

function appOf(j: Jail): string {
  return j.metadata.labels?.['jailops.app'] ?? ''
}

/** Run an action on several jails; every jail gets its own toast, failures do not stop the rest. */
export async function lifecycleMany(names: string[], action: Lifecycle): Promise<{ ok: string[]; failed: string[] }> {
  const res = await Promise.allSettled(names.map((n) => lifecycle(n, action)))
  const ok: string[] = []
  const failed: string[] = []
  res.forEach((r, i) => (r.status === 'fulfilled' ? ok : failed).push(names[i]))
  return { ok, failed }
}

export function matches(j: { metadata: { name: string; labels?: Record<string, string> }; spec: { image: string }; status: { addresses?: string[] } }, q: string): boolean {
  const needle = q.trim().toLowerCase()
  if (!needle) return true
  const hay = [j.metadata.name, j.spec.image, ...(j.status.addresses ?? []), ...Object.entries(j.metadata.labels ?? {}).map(([k, v]) => `${k}=${v}`)]
  return hay.some((h) => h.toLowerCase().includes(needle))
}

/** A jail whose encrypted volumes wait for their passphrase. */
export function isLocked(j: { status: { power: string; locked?: string[] } }): boolean {
  return j.status.power === 'locked' || (j.status.locked?.length ?? 0) > 0
}
