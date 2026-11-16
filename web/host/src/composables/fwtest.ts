import { hasExt, session } from '@jailops/shared/composables/session'
import { projectState } from '@/composables/project'

/** The Test tab of the firewall page: the server offers the test (extension firewall_test). */
export const hasFirewallTest = (): boolean => hasExt('firewall_test')

/**
 * Who may run it: operator or admin in the project, like the endpoint. The server decides in the end; an identity whose
 * role is unknown (a token without a session) may try.
 */
export function canFirewallTest(project = projectState.current): boolean {
  const r = session.role
  const inScope = !r || session.global || !project || session.projects.includes(project)
  return hasFirewallTest() && (!r || r === 'operator' || r === 'admin') && inScope
}
