import { createRouter, createWebHistory, type RouteRecordRaw, type Router, type RouterHistory } from 'vue-router'
import { guard } from '@jailops/shared/router'

export const routes: RouteRecordRaw[] = [
  { path: '/login', name: 'login', component: () => import('@/views/LoginView.vue'), meta: { public: true, title: 'Sign in' } },
  // The first-run wizard, while the host has no administrator (the login view sends there).
  { path: '/setup', name: 'setup', component: () => import('@/views/SetupView.vue'), meta: { public: true, title: 'Set up' } },
  { path: '/', name: 'overview', component: () => import('@/views/OverviewView.vue'), meta: { title: 'Overview' } },
  { path: '/jails', name: 'jails', component: () => import('@/views/JailsView.vue'), meta: { project: true, feature: 'jails', title: 'Jails' } },
  { path: '/volumes', name: 'volumes', component: () => import('@/views/VolumesView.vue'), meta: { project: true, ext: 'volumes', title: 'Volumes' } },
  { path: '/volumes/:name', name: 'volume', component: () => import('@/views/VolumeDetailView.vue'), meta: { project: true, ext: 'volumes', title: 'Volume' } },
  // The shell of a jail, shareable: its Console tab, connecting at once (`connect` is taken off once it is used).
  { path: '/jails/:name/shell', name: 'jail-shell', redirect: (to) => ({ name: 'jail', params: { name: to.params.name }, query: { tab: 'console', connect: '1' } }) },
  { path: '/jails/:name', name: 'jail', component: () => import('@/views/JailDetailView.vue'), meta: { project: true, feature: 'jails', title: 'Jail' } },
  { path: '/projects', name: 'projects', component: () => import('@/views/ProjectsView.vue'), meta: { feature: 'projects', title: 'Projects' } },
  { path: '/projects/:name', name: 'project', component: () => import('@/views/ProjectDetailView.vue'), meta: { feature: 'projects', title: 'Project' } },
  { path: '/storage', name: 'storage', component: () => import('@/views/StorageView.vue'), meta: { feature: 'storage', title: 'Storage' } },
  { path: '/profiles', name: 'profiles', component: () => import('@/views/ProfilesView.vue'), meta: { project: true, feature: 'jails', title: 'Profiles' } },
  { path: '/updates', name: 'updates', component: () => import('@/views/UpdatesView.vue'), meta: { project: true, ext: 'updates', title: 'Updates' } },
  { path: '/images', name: 'images', component: () => import('@/views/ImagesView.vue'), meta: { feature: 'images', title: 'Images' } },
  { path: '/apps', name: 'apps', component: () => import('@/views/AppsView.vue'), meta: { feature: 'apps', title: 'Apps' } },
  { path: '/apps/:name', name: 'app', component: () => import('@/views/AppDetailView.vue'), meta: { feature: 'apps', title: 'App' } },
  { path: '/networks', name: 'networks', component: () => import('@/views/NetworksView.vue'), meta: { feature: 'networks', title: 'Networks' } },
  { path: '/networks/wireguard', name: 'wireguard', component: () => import('@/views/WireGuardView.vue'), meta: { feature: 'networks', ext: 'wireguard', title: 'WireGuard' } },
  { path: '/firewall', name: 'firewall', component: () => import('@/views/FirewallView.vue'), meta: { project: true, feature: 'firewall', title: 'Firewall' } },
  // The firewall test, shareable: the Test tab of the firewall page; the question is in the query (from, to, proto, port).
  { path: '/firewall/test', name: 'firewall-test', redirect: (to) => ({ name: 'firewall', query: { ...to.query, tab: 'test' } }) },
  { path: '/backups', name: 'backups', component: () => import('@/views/BackupsView.vue'), meta: { project: true, feature: 'backups', title: 'Backups' } },
  { path: '/host', name: 'host', component: () => import('@/views/HostView.vue'), meta: { ext: 'host_identity', title: 'Host' } },
  { path: '/hosts', name: 'hosts', component: () => import('@/views/HostsView.vue'), meta: { hub: true, title: 'Hosts' } },
  { path: '/logs', name: 'logs', component: () => import('@/views/LogsView.vue'), meta: { title: 'Logs' } },
  { path: '/operations', name: 'operations', component: () => import('@/views/OperationsView.vue'), meta: { feature: 'operations', title: 'Operations' } },
  { path: '/events', name: 'events', component: () => import('@/views/EventsView.vue'), meta: { feature: 'events', title: 'Events' } },
  { path: '/doctor', name: 'doctor', component: () => import('@/views/DoctorView.vue'), meta: { feature: 'doctor', title: 'Doctor' } },
  { path: '/audit', name: 'audit', component: () => import('@/views/AuditView.vue'), meta: { feature: 'audit', title: 'Audit log' } },
  { path: '/access', name: 'access', component: () => import('@/views/AccessView.vue'), meta: { title: 'Access' } },
  { path: '/:rest(.*)*', name: 'notfound', component: () => import('@/views/NotFoundView.vue'), meta: { title: 'Not found' } },
]

export function makeRouter(history: RouterHistory = createWebHistory()): Router {
  const r = createRouter({ history, routes, scrollBehavior: () => ({ top: 0 }) })
  r.beforeEach((to) => guard(to))
  r.afterEach((to) => {
    document.title = `${to.meta.title ?? ''} - JailOps host console`.replace(/^ - /, '')
  })
  return r
}
