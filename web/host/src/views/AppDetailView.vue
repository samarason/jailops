<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { can } from '@jailops/shared/composables/session'
import { projectState } from '@/composables/project'
import { useInstallGate } from '@/composables/apps'
import { installedJails, paragraphs as paras, volumeName } from '@/lib/apps'
import { logFileOf } from '@/lib/logs'
import Icon from '@jailops/shared/components/Icon.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import AppIcon from '@/components/AppIcon.vue'
import StatePill from '@/components/StatePill.vue'
import AppInstallDialog from '@/components/AppInstallDialog.vue'
import NotesText from '@/components/NotesText.vue'
import type { Jail } from '@jailops/shared/api/types'

const route = useRoute()
const name = computed(() => String(route.params.name))
const gate = useInstallGate()

const l = useLoad(() => api.apps.get(name.value))
const jl = useLoad(async () => (projectState.current || !can('projects') ? installedJails(await api.jails.list(), name.value) : ([] as Jail[])))
watch([name, () => projectState.current], () => { void l.reload(); void jl.reload() })

const app = computed(() => l.data.value?.definition)
const installed = computed(() => jl.data.value ?? [])
const paragraphs = computed(() => paras(app.value?.description))
const installing = ref(false)
const notFound = computed(() => l.error.value?.code === 'not_found')
const invalid = computed(() => l.error.value?.code === 'invalid')
</script>

<template>
  <div>
    <router-link class="back" to="/apps"><Icon name="chevronLeft" />{{ s.apps.back }}</router-link>
    <template v-if="notFound || invalid">
      <div class="page-head"><h1 class="mono">{{ name }}</h1><span v-if="invalid" class="pill danger">{{ s.apps.invalid }}</span></div>
      <p v-if="notFound" class="empty">{{ s.apps.notFound }}</p>
      <div v-else class="stack" data-test="app-invalid"><Callout tone="warn">{{ s.apps.invalidDetail }}</Callout><ErrorPanel v-if="l.error.value" :error="l.error.value" /></div>
    </template>
    <LoadState v-else :loading="l.loading.value" :error="l.error.value" :has-data="!!app" @retry="l.reload">
      <div v-if="app && l.data.value" class="stack" :data-app="app.name">
        <section class="panel app-hero">
          <AppIcon :name="app.name" :title="app.title" :icon="l.data.value.icon" :size="72" />
          <div class="grow app-hero-main">
            <div class="row"><h1>{{ app.title }}</h1><span class="faint mono">{{ app.name }}</span><span v-if="l.data.value.source === 'local'" class="badge info" :title="l.data.value.overrides ? s.apps.overridesTitle : s.apps.localTitle" data-test="app-local">{{ l.data.value.overrides ? s.apps.overrides : s.apps.local }}</span></div>
            <p class="app-hero-sum">{{ app.summary }}</p>
            <div class="row app-hero-meta">
              <span class="chip">{{ s.apps.category[app.category] ?? app.category }}</span>
              <span v-if="app.packages[0]?.version" class="chip mono">{{ app.packages[0].version }}</span>
              <span v-if="app.license" class="faint">{{ s.apps.license }}: <span class="mono">{{ app.license }}</span></span>
              <a v-if="app.homepage" :href="app.homepage" target="_blank" rel="noopener noreferrer" data-test="homepage"><Icon name="externalLink" /> {{ s.apps.homepage }}</a>
            </div>
          </div>
          <div class="app-hero-act">
            <button class="btn btn-primary app-install-btn" type="button" :disabled="!!gate.block.value" :aria-describedby="gate.reason.value ? 'install-why' : undefined" data-test="app-install" @click="installing = true"><Icon name="pkg" />{{ s.apps.install }}</button>
            <p v-if="gate.reason.value" id="install-why" class="app-why" data-test="install-blocked">{{ gate.reason.value }} <router-link v-if="gate.toProject.value" :to="gate.toProject.value">{{ s.apps.toProject }}</router-link></p>
            <div v-if="installed.length" class="app-installed" data-test="installed-as">
              <span class="faint">{{ s.apps.installedAs }}</span>
              <span v-for="j in installed" :key="j.metadata.name" class="row app-installed-j"><router-link class="mono" :to="`/jails/${j.metadata.name}`">{{ j.metadata.name }}</router-link><StatePill :state="j.status.power" /></span>
            </div>
          </div>
        </section>

        <div class="app-detail-grid">
          <div class="stack">
            <section v-if="paragraphs.length" class="panel" aria-labelledby="ad-about">
              <header><h2 id="ad-about">{{ s.apps.about }}</h2></header>
              <div class="body app-prose"><p v-for="(p, i) in paragraphs" :key="i">{{ p }}</p></div>
            </section>

            <section class="panel" aria-labelledby="ad-ports" data-section="ports">
              <header><h2 id="ad-ports">{{ s.apps.ports }}</h2></header>
              <p v-if="!app.ports?.length" class="empty">{{ s.app.none }}</p>
              <div v-else class="table-wrap">
                <table>
                  <thead><tr><th>{{ s.apps.port }}</th><th>{{ s.apps.portDesc }}</th><th><span class="sr-only">{{ s.apps.exposed }}</span></th></tr></thead>
                  <tbody>
                    <tr v-for="p in app.ports" :key="p.port + p.proto">
                      <td class="nowrap"><span class="mono">{{ p.name }}</span> <span class="faint mono">{{ p.port }}/{{ p.proto }}</span></td>
                      <td class="muted">{{ p.description }}</td>
                      <td class="nowrap"><span v-if="p.expose" class="badge info">{{ s.apps.exposed }}</span><span v-else class="faint">{{ s.apps.internal }}</span></td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <p class="body faint app-note">{{ s.apps.exposeNote }}</p>
            </section>

            <section class="panel" aria-labelledby="ad-data" data-section="data">
              <header><h2 id="ad-data">{{ s.apps.data }}</h2></header>
              <div class="body">
                <p class="muted">{{ s.apps.dataLead }}</p>
                <p v-if="!app.data?.length" class="faint">{{ s.app.none }}</p>
                <ul class="app-paths">
                  <li v-for="d in app.data" :key="d.path"><Icon name="database" /><div><span class="mono">{{ d.path }}</span> <span class="faint">· {{ s.apps.volume }} <span class="mono">&lt;jail&gt;-{{ volumeName(d.path) }}</span></span><div class="muted">{{ d.description }}</div></div></li>
                </ul>
              </div>
            </section>

            <section class="panel" aria-labelledby="ad-config" data-section="config">
              <header><h2 id="ad-config">{{ s.apps.config }}</h2></header>
              <div class="body">
                <p v-if="!app.config?.length" class="faint">{{ s.app.none }}</p>
                <ul class="app-paths">
                  <li v-for="c in app.config" :key="c.path"><Icon name="fileCog" /><div><span class="mono">{{ c.path }}</span><span v-if="c.restart" class="pill info app-restart">{{ s.apps.restarts(c.restart) }}</span><div class="muted">{{ c.description }}</div></div></li>
                </ul>
              </div>
            </section>

            <section class="panel" aria-labelledby="ad-logs" data-section="logs">
              <header><h2 id="ad-logs">{{ s.apps.logs }}</h2></header>
              <div class="body">
                <p v-if="!app.logs?.length" class="faint">{{ s.app.none }}</p>
                <ul class="app-paths">
                  <li v-for="g in app.logs" :key="g.name" :data-log="g.name">
                    <Icon name="fileText" />
                    <div class="grow">
                      <span class="mono">{{ g.path }}</span> <span class="faint">· {{ g.name }}</span>
                      <div class="muted">{{ g.description }}</div>
                      <div v-if="installed.length" class="row app-loglinks">
                        <template v-if="logFileOf(g.path)">
                          <router-link v-for="j in installed" :key="j.metadata.name" class="btn btn-sm" :to="{ path: `/jails/${j.metadata.name}`, query: { tab: 'logs', file: logFileOf(g.path) } }" data-test="open-log"><Icon name="fileText" />{{ s.apps.openLog(j.metadata.name) }}</router-link>
                        </template>
                        <span v-else class="faint">{{ s.apps.outsideVarLog }}</span>
                      </div>
                    </div>
                  </li>
                </ul>
              </div>
            </section>

            <section class="panel" aria-labelledby="ad-pkgs">
              <header><h2 id="ad-pkgs">{{ s.apps.packages }}</h2></header>
              <div class="table-wrap">
                <table>
                  <thead><tr><th>{{ s.apps.pkgName }}</th><th>{{ s.apps.repo }}</th><th>{{ s.apps.pkgVersion }}</th></tr></thead>
                  <tbody><tr v-for="p in app.packages" :key="p.name"><td class="mono">{{ p.name }}</td><td>{{ s.apps.repoName[p.repo] ?? p.repo }}</td><td class="mono">{{ p.version || '-' }}</td></tr></tbody>
                </table>
              </div>
            </section>

            <section v-if="app.services?.length" class="panel" aria-labelledby="ad-svc">
              <header><h2 id="ad-svc">{{ s.apps.services }}</h2></header>
              <div class="table-wrap">
                <table>
                  <thead><tr><th>{{ s.apps.service }}</th><th>{{ s.apps.starts }}</th><th>{{ s.apps.rcKnobs }}</th></tr></thead>
                  <tbody>
                    <tr v-for="v in app.services" :key="v.name">
                      <td class="mono">{{ v.name }}</td>
                      <td>{{ v.start === false ? s.apps.enabledOnly : s.apps.startsYes }}</td>
                      <td class="mono"><div>{{ v.name }}_enable="YES"</div><div v-for="(val, k) in v.rc" :key="k">{{ k }}="{{ val }}"</div></td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>

            <section v-if="app.setup?.length" class="panel" aria-labelledby="ad-setup">
              <header><h2 id="ad-setup">{{ s.apps.setup }}</h2></header>
              <ol class="body app-setup"><li v-for="(cmd, i) in app.setup" :key="i" class="mono">{{ cmd.join(' ') }}</li></ol>
            </section>
          </div>

          <div class="stack">
            <section v-if="app.health" class="panel" aria-labelledby="ad-health" data-section="health">
              <header><h2 id="ad-health">{{ s.apps.health }}</h2><Icon name="heartPulse" /></header>
              <div class="body">
                <p v-if="app.health.tcp">{{ s.apps.healthTcp(app.health.tcp) }}</p>
                <p v-if="app.health.http">{{ s.apps.healthHttp(app.health.http.port, app.health.http.path, app.health.http.status ?? 200) }}</p>
                <p v-if="app.health.exec?.length">{{ s.apps.healthExec }}: <span class="mono">{{ app.health.exec.join(' ') }}</span></p>
                <p class="faint">{{ s.apps.healthWait(app.health.wait_seconds ?? 60) }}</p>
              </div>
            </section>

            <section v-if="app.resources" class="panel" aria-labelledby="ad-res" data-section="resources">
              <header><h2 id="ad-res">{{ s.apps.resources }}</h2></header>
              <div class="body">
                <div class="app-res">
                  <div v-if="app.resources.memory"><Icon name="memoryStick" /><span class="faint">{{ s.apps.memory }}</span><strong class="mono">{{ app.resources.memory }}</strong></div>
                  <div v-if="app.resources.disk"><Icon name="hardDrive" /><span class="faint">{{ s.apps.disk }}</span><strong class="mono">{{ app.resources.disk }}</strong></div>
                  <div v-if="app.resources.cpu"><Icon name="cpu" /><span class="faint">{{ s.apps.cpu }}</span><strong class="mono">{{ app.resources.cpu }}</strong></div>
                </div>
                <p class="faint app-note">{{ s.apps.resourcesLead }}</p>
              </div>
            </section>

            <section v-if="app.notes" class="panel" aria-labelledby="ad-notes" data-section="notes">
              <header><h2 id="ad-notes">{{ s.apps.notes }}</h2></header>
              <NotesText class="body app-notes" :text="app.notes" />
            </section>

            <section class="panel" aria-labelledby="ad-def">
              <header><h2 id="ad-def">{{ s.apps.definition }}</h2></header>
              <div class="body">
                <dl class="kv">
                  <dt>{{ s.apps.image }}</dt><dd>{{ s.apps.releaseMin(app.image.os, app.image.release_min) }}</dd>
                  <dt>{{ s.apps.file }}</dt><dd class="mono app-path" data-test="app-file"><template v-for="(seg, i) in l.data.value.file.split('/')" :key="i">{{ i ? '/' : '' }}<wbr v-if="i" />{{ seg }}</template></dd>
                  <dt>{{ s.apps.hash }}</dt><dd class="mono app-hash" data-test="app-hash">{{ l.data.value.hash }}</dd>
                </dl>
              </div>
            </section>
          </div>
        </div>
        <AppInstallDialog :open="installing" :detail="l.data.value" @close="installing = false" @done="jl.reload" />
      </div>
    </LoadState>
  </div>
</template>

<style>
.app-hero { display: flex; gap: 16px; padding: 16px; align-items: flex-start; flex-wrap: wrap; background: linear-gradient(180deg, var(--accent-soft), var(--surface) 70%); }
.app-hero-main { min-width: min(100%, 260px); flex: 1 1 320px; }
.app-hero h1 { font-size: 24px; }
.app-hero-sum { color: var(--text-2); font-size: 15px; margin: 4px 0 8px; }
.app-hero-meta { gap: 10px; }
.app-hero-meta .chip { margin: 0; }
.app-hero-meta a { display: inline-flex; gap: 4px; align-items: center; }
.app-hero-act { display: grid; gap: 8px; justify-items: start; flex: 0 1 280px; min-width: 0; }
.app-install-btn { min-height: 38px; padding: 6px 18px; font-weight: 600; }
.app-why { font-size: 12px; color: var(--text-2); margin: 0; max-width: 280px; }
.app-installed { display: grid; gap: 4px; font-size: 13px; }
.app-installed-j { gap: 6px; }
.app-detail-grid { display: grid; gap: 12px; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); align-items: start; }
.app-prose p { max-width: 75ch; }
.app-paths { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }
.app-paths li { display: flex; gap: 10px; align-items: flex-start; overflow-wrap: anywhere; }
.app-paths li > .icon { margin-top: 2px; color: var(--text-3); }
.app-restart { margin-left: 8px; }
.app-loglinks { margin-top: 4px; }
.app-note { font-size: 12px; margin: 0; }
.panel > .app-setup { margin: 0; padding-left: 36px; display: grid; gap: 2px; overflow-wrap: anywhere; }
.app-res { display: grid; gap: 8px; margin-bottom: 8px; }
.app-res > div { display: grid; grid-template-columns: 20px 1fr auto; gap: 8px; align-items: center; }
.app-res .icon { color: var(--text-3); }
.app-notes p:last-child { margin: 0; }
.app-hash { font-size: 12px; }
/* a path breaks after a slash, never inside a name */
dl.kv dd.app-path { overflow-wrap: normal; word-break: normal; }
@media (max-width: 1000px) { .app-detail-grid { grid-template-columns: minmax(0, 1fr); } }
</style>
