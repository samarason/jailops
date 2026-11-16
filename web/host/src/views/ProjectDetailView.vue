<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { isHub, hasExt } from '@jailops/shared/composables/session'
import { bytes, sentence } from '@jailops/shared/lib/format'
import { codeText } from '@jailops/shared/lib/describe'
import { confirmAction } from '@jailops/shared/composables/confirm'
import type { Condition } from '@jailops/shared/api/types'
import Icon from '@jailops/shared/components/Icon.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import QuotaBars from '@/components/QuotaBars.vue'
import ProjectForm from '@/components/ProjectForm.vue'
import { isGlobalAdmin, projectState, refreshProjects, switchProject } from '@/composables/project'
import RenameDialog from '@/components/RenameDialog.vue'
import { canRename } from '@/composables/rename'
import { renamedAddress } from '@/lib/rename'

const route = useRoute()
const router = useRouter()
const name = computed(() => String(route.params.name))
const l = useLoad(async () => {
  const [pr, networks, storage] = await Promise.all([api.projects.get(name.value), api.networks.list().catch(() => []), api.storage.list().catch(() => [])])
  const agg = isHub.value && hasExt('fleet_projects') && pr.data.spec.hosts?.length ? await api.projects.aggregate(name.value).catch(() => undefined) : undefined
  return { project: pr.data, etag: pr.etag, networks, storage, agg }
})
const p = computed(() => l.data.value?.project)
const canWrite = computed(() => isGlobalAdmin())
const editing = ref(false)
const renaming = ref(false)
/** After a rename the page moves to the new address; the project switcher follows when it was the current one. */
async function renamed(to: string): Promise<void> {
  const from = name.value
  if (projectState.current === from) switchProject(to)
  await refreshProjects()
  await router.replace(renamedAddress('project', from, to, route.fullPath) ?? `/projects/${encodeURIComponent(to)}`)
}
const notFound = computed(() => l.error.value?.code === 'not_found')

// Deleting a project is tier 3: the name is typed, even when it is empty.
function del(): void {
  const n = name.value
  confirmAction({
    title: s.projects.deleteTitle(n), confirmLabel: s.projects.deleteGo, danger: true, text: s.projects.deleteText, typeName: n,
    run: () => runOp(s.projects.deleteTitle(n), () => api.projects.remove(n)),
    done: () => void refreshProjects().then(() => router.replace('/projects')),
  })
}
/** A condition in words: "Host:bsd02" names the host, a reason code becomes a sentence. */
const condWhat = (c: Condition) => (c.type.startsWith('Host:') ? c.type.slice(5) : sentence(c.type))
const condText = (c: Condition) => s.projects.hostCondition(codeText(c.reason) || '', c.message ?? '')
</script>

<template>
  <div>
    <router-link class="back" to="/projects"><Icon name="chevronLeft" />{{ s.projects.back }}</router-link>
    <template v-if="notFound"><div class="page-head"><h1>{{ s.app.notFoundTitle }}</h1></div><p class="empty panel">{{ s.projects.notFound }}</p></template>
    <LoadState :loading="l.loading.value" :error="notFound ? null : l.error.value" :has-data="!!p" @retry="l.reload">
      <div v-if="p" class="stack" :data-project-detail="p.metadata.name">
        <div class="page-head">
          <div class="row"><h1 class="mono">{{ p.metadata.name }}</h1><span v-if="p.spec.hosts?.length" class="badge info">{{ s.projects.fleet }}</span></div>
          <div class="row">
            <button class="btn" type="button" :disabled="!canWrite" data-test="edit-project" @click="editing = true">{{ s.projects.edit }}</button>
            <button v-if="canRename('project')" class="btn" type="button" data-test="project-rename" @click="renaming = true">{{ s.rename.open(s.rename.kinds.project) }}</button>
            <button class="btn btn-danger" type="button" :disabled="!canWrite" data-test="project-delete" @click="del">{{ s.projects.delete }}</button>
          </div>
        </div>
        <p v-if="p.spec.comment" class="muted">{{ p.spec.comment }}</p>

        <section class="panel"><header><h2>{{ s.projects.quotas }}</h2></header>
          <div class="body"><QuotaBars :project="p" />
            <dl class="kv" style="margin-top: 8px"><dt>{{ s.projects.diskUsed }}</dt><dd class="mono">{{ bytes(p.status.disk_used) }}</dd><dt>{{ s.projects.memoryUsed }}</dt><dd class="mono">{{ bytes(p.status.memory_used) }}</dd><dt>{{ s.projects.jailsUsed }}</dt><dd class="mono">{{ p.status.jails }}</dd></dl>
            <p class="hint muted">{{ s.projects.sums }}</p></div>
        </section>

        <div class="grid-2">
          <section class="panel" data-section="networks"><header><h2>{{ s.projects.grantNetworks }}</h2></header>
            <p v-if="!p.spec.networks?.length" class="empty">-</p>
            <div v-else class="table-wrap"><table><thead><tr><th>{{ s.projects.network }}</th></tr></thead>
              <tbody><tr v-for="n in p.spec.networks" :key="n.network"><td class="mono">{{ n.network }}</td></tr></tbody></table></div>
          </section>
          <section class="panel" data-section="storage"><header><h2>{{ s.projects.grantStorage }}</h2></header>
            <p v-if="!p.spec.storage?.length" class="empty">-</p>
            <div v-else class="table-wrap"><table><thead><tr><th>{{ s.projects.storage }}</th><th>{{ s.projects.quotaField }}</th></tr></thead>
              <tbody><tr v-for="x in p.spec.storage" :key="x.storage"><td class="mono">{{ x.storage === '*' ? '* (' + s.projects.wildcard + ')' : x.storage }}</td><td class="mono">{{ x.quota || s.projects.unlimited }}</td></tr></tbody></table></div>
          </section>
        </div>

        <section class="panel"><header><h2>{{ s.projects.firewall }}</h2></header>
          <div class="body"><span v-if="p.spec.firewall_policies?.length" class="mono" data-test="mandatory-policy">{{ p.spec.firewall_policies.join(', ') }}</span><span v-else class="faint">-</span>
            <p class="muted" style="margin-top: 6px">{{ s.projects.images }}: <span class="mono">{{ p.spec.images?.join(', ') || s.projects.allImages }}</span></p></div>
        </section>

        <section v-if="p.status.conditions?.length" class="panel"><header><h2>{{ s.projects.conditions }}</h2></header>
          <ul class="plain body"><li v-for="c in p.status.conditions" :key="c.type"><span class="pill" :class="c.status === 'True' ? 'ok' : 'danger'">{{ condWhat(c) }}</span> <span class="muted">{{ condText(c) }}</span></li></ul></section>

        <section v-if="p.spec.hosts?.length" class="panel" data-section="hosts">
          <header><h2>{{ s.projects.hostStatus }}</h2><span class="mono faint">{{ p.spec.hosts.join(', ') }}</span></header>
          <p v-if="!l.data.value?.agg" class="empty">{{ s.projects.hubOnly }}</p>
          <div v-else class="table-wrap"><table data-test="host-status" class="rtable">
            <thead><tr><th>{{ s.projects.host }}</th><th>{{ s.projects.reach }}</th><th>{{ s.projects.status }}</th><th class="num">{{ s.projects.jailsUsed }}</th><th>{{ s.projects.memoryUsed }}</th></tr></thead>
            <tbody>
              <tr v-for="h in l.data.value.agg.hosts" :key="h.host" :data-host="h.host" :class="{ drift: !!h.error || !h.online }">
                <td class="mono" :data-label="s.projects.host">{{ h.host }}</td>
                <td :data-label="s.projects.reach"><span class="pill" :class="h.online ? 'ok' : 'danger'">{{ h.online ? s.projects.online : s.projects.offline }}</span></td>
                <td :data-label="s.projects.status"><span class="pill" :class="h.applied ? (h.in_sync ? 'ok' : 'warn') : 'danger'">{{ !h.applied ? s.projects.notApplied : h.in_sync ? s.projects.inSync : s.projects.outOfSync }}</span>
                  <div v-for="c in h.conditions ?? []" :key="c.type" class="muted" data-test="host-cond">{{ condText(c) }}</div>
                  <div v-if="h.error" class="err" style="color: var(--danger)" :title="`${s.error.code}: ${h.error.code}`" data-test="host-error">{{ s.projects.noAnswer(h.host, h.error.message) }}</div></td>
                <td class="num mono" :data-label="s.projects.jailsUsed">{{ h.status?.jails ?? '-' }}</td><td class="mono" :data-label="s.projects.memoryUsed">{{ h.status ? bytes(h.status.memory_used) : '-' }}</td>
              </tr>
              <tr><th scope="row" colspan="3">{{ s.projects.total }}</th><td class="num mono" :data-label="s.projects.jailsUsed">{{ l.data.value.agg.total.jails }}</td><td class="mono" :data-label="s.projects.memoryUsed">{{ bytes(l.data.value.agg.total.memory_used) }}</td></tr>
            </tbody></table></div>
        </section>

        <RenameDialog :open="renaming" kind="project" :name="p.metadata.name" :etag="l.data.value?.etag" @close="renaming = false" @done="renamed" />
        <ProjectForm :open="editing" :project="p" :etag="l.data.value?.etag" :networks="l.data.value?.networks ?? []" :storage="l.data.value?.storage ?? []" @close="editing = false" @done="l.reload" />
      </div>
    </LoadState>
  </div>
</template>
