import { s } from '@/i18n'
import { bytes } from '@jailops/shared/lib/format'
import type { Volume } from '@jailops/shared/api/types'

/** What deleting a volume destroys, one line each: its files and its snapshots. */
export function volumeLoss(v: Volume, snapshots: number): string[] {
  const out = [s.volumes.filesItem(v.metadata.name, bytes(v.status?.used ?? 0))]
  if (snapshots) out.push(s.volumes.snapshotsItem(`${snapshots} snapshot${snapshots === 1 ? '' : 's'}`))
  return out
}

/** A volume that is a directory of the host, not a dataset. */
export const isHostDir = (v: Volume): boolean => !!v.spec.path

/** Whether the mount of a host-directory volume is gone, as the daemon's last look says. */
export const isLost = (v: Volume): boolean => v.status?.state === 'lost'

/** The path of a directory of a volume is clean and absolute, in the characters a jail's fstab takes. */
export function pathProblem(p: string): string {
  if (!/^\/[A-Za-z0-9._+@:=,/-]+$/.test(p) || p.split('/').slice(1).some((x) => x === '' || x === '.' || x === '..')) return s.volumes.pathInvalid
  return ''
}
