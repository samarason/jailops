import { reactive, computed } from 'vue'
import { core } from '../api/core'
import { getClient, setClient, Client, storeToken, storeCsrf, ApiError, type Transport } from '../api/client'
import type { ServerInfo } from '../api/types'
import { has, type Feature } from '../lib/features'

const DEMO_KEY = 'jailops.demo'

export const session = reactive({
  ready: false,
  info: null as ServerInfo | null,
  authed: false,
  demo: false,
  /** This build carries the demo (a demo build only: the console a daemon embeds never switches to canned data). */
  demoAvailable: false,
  error: null as ApiError | null,
  /** Set by the login form when the server asked for a TOTP code. */
  needTotp: false,
  /** The server answered with another role than this console is built for. */
  wrongRole: '' as string,
  /** Who the server says we are (from /auth/session): user name and role or permission. */
  user: '',
  role: '',
  kind: '',
  /** The projects the identity may act in; `global` means every project and host-level objects. */
  projects: [] as string[],
  global: false,
})

export const isHub = computed(() => !!session.info?.hub)
export function can(f: Feature): boolean {
  return has(session.info?.api_extensions, f)
}
/** True when the server lists the extension name. */
export function hasExt(name: string): boolean {
  return !!session.info?.api_extensions.includes(name)
}

/** True in a demo build (JAILOPS_DEMO_BUILD=1 at build time, web/shared/vite.app.ts); the embedded console is not one. */
export const demoBuild: boolean = import.meta.env.VITE_JAILOPS_DEMO === '1'

export function wantsDemo(search = location.search): boolean {
  if (new URLSearchParams(search).has('demo')) return true
  try {
    return sessionStorage.getItem(DEMO_KEY) === '1'
  } catch {
    return false
  }
}

export interface BootOptions {
  /** The role this console serves ("host" or "backup"). */
  role: 'host' | 'backup'
  /** Loads the demo transport; called only when `?demo` is present. Only a demo build passes it (demoBuild). */
  loadDemo?: (o: { signedOut: boolean }) => Promise<Transport>
}

let expectedRole: BootOptions['role'] = 'host'

/** Decide on the transport, then ask the server who we are. */
export async function boot(o: BootOptions): Promise<void> {
  expectedRole = o.role
  session.demoAvailable = !!o.loadDemo
  session.demo = !!o.loadDemo && wantsDemo()
  if (session.demo) {
    try {
      sessionStorage.setItem(DEMO_KEY, '1')
    } catch {
      /* ignore */
    }
    setClient(new Client(await o.loadDemo!({ signedOut: new URLSearchParams(location.search).get('demo') === 'login' })))
  }
  getClient().onUnauthorized(() => {
    session.authed = false
  })
  await refreshInfo()
  session.ready = true
}

export async function refreshInfo(): Promise<void> {
  try {
    session.info = await core.server()
    session.authed = session.info.auth === 'trusted'
    session.error = null
    session.wrongRole = session.info.role !== expectedRole ? session.info.role : ''
    if (session.authed) await loadIdentity()
  } catch (e) {
    session.authed = false
    session.error = e instanceof ApiError ? e : null
  }
}

async function loadIdentity(): Promise<void> {
  try {
    const me = await core.session()
    session.user = me.user
    session.role = me.role ?? me.permission ?? ''
    session.kind = me.kind ?? ''
    session.projects = me.projects ?? []
    session.global = !!me.global
    if (me.csrf) storeCsrf(me.csrf)
  } catch {
    /* a token identity may not have a session: the role stays unknown and the server decides */
  }
}

export async function loginWithToken(token: string): Promise<void> {
  storeToken(token.trim())
  try {
    await refreshInfo()
    if (!session.authed) throw new ApiError({ code: 'unauthorized', message: 'The token was not accepted.', hint: 'Create a token under Access, or check that it has not expired.' }, 401)
  } catch (e) {
    storeToken('')
    throw e
  }
}

export async function loginWithPassword(username: string, password: string, totp?: string): Promise<void> {
  try {
    const r = await core.login({ username, password, totp: totp || undefined })
    if (r.kind === 'sync' && r.data?.csrf) storeCsrf(r.data.csrf)
  } catch (e) {
    if (e instanceof ApiError && e.detail['totp'] === 'required') session.needTotp = true
    throw e
  }
  session.needTotp = false
  await refreshInfo()
}

export async function logout(): Promise<void> {
  try {
    await core.logout()
  } catch {
    /* the cookie may already be gone */
  }
  storeToken('')
  storeCsrf('')
  session.authed = false
  session.info = null
  session.user = ''
  session.role = ''
  session.kind = ''
  session.projects = []
  session.global = false
}
