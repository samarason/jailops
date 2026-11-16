import { hasExt, session } from '@jailops/shared/composables/session'
import { isGlobalAdmin, projectState } from '@/composables/project'
import type { RenameKind } from '@/lib/rename'

// Who is offered Rename (extension rename). The server decides in the end; the console only avoids offering what it
// would refuse. Networks, images and projects need a global admin; a jail, a firewall policy, an address set and a
// profile an admin of their project; the host profiles (project "host") and the mandatory policy of a project a
// global admin. An identity whose role is unknown (a token without a session) may try.
export function canRename(kind: RenameKind, project: string = projectState.current, opts: { mandatory?: boolean } = {}): boolean {
  if (!hasExt('rename')) return false
  if (kind === 'network' || kind === 'image' || kind === 'project' || project === 'host' || opts.mandatory) return isGlobalAdmin()
  const r = session.role
  const inScope = !r || session.global || !project || session.projects.includes(project)
  return (!r || r === 'admin') && inScope
}
