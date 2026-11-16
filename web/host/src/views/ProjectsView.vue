<script setup lang="ts">
import { computed, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { session } from '@jailops/shared/composables/session'
import { switchProject, projectState, refreshProjects, isGlobalAdmin } from '@/composables/project'
import Icon from '@jailops/shared/components/Icon.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import QuotaBars from '@/components/QuotaBars.vue'
import ProjectForm from '@/components/ProjectForm.vue'
import { orderProjects } from '@/lib/projectScope'

const l = useLoad(async () => ({ projects: orderProjects(await api.projects.list()), networks: await api.networks.list().catch(() => []), storage: await api.storage.list().catch(() => []) }))
const creating = ref(false)
const canWrite = computed(() => isGlobalAdmin())
const grants = (p: { spec: { networks?: { network: string }[] } }) => (p.spec.networks ?? []).map((n) => n.network).join(', ') || '-'
const stor = (p: { spec: { storage?: { storage: string }[] } }) => (p.spec.storage ?? []).map((n) => n.storage).join(', ') || '-'
async function done(): Promise<void> {
  await l.reload()
  await refreshProjects()
}
</script>

<template>
  <div>
    <div class="page-head">
      <h1>{{ s.projects.title }}</h1>
      <button class="btn btn-primary" type="button" :disabled="!canWrite" data-test="new-project" @click="creating = true"><Icon name="plus" />{{ s.projects.create }}</button>
    </div>
    <Callout v-if="!canWrite" style="margin-bottom: 12px">{{ s.projects.onlyGlobal }} <span v-if="session.projects.length">{{ s.project.restricted(session.projects.length) }}</span></Callout>
    <p class="muted">{{ s.projects.isolation }}</p>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div class="panel" style="margin-top: 12px">
        <p v-if="!l.data.value?.projects.length" class="empty">{{ s.projects.empty }}</p>
        <div v-else class="table-wrap"><table data-test="projects-table" class="rtable">
          <thead><tr><th>{{ s.projects.name }}</th><th>{{ s.projects.networks }}</th><th>{{ s.projects.storage }}</th><th style="min-width: 220px">{{ s.projects.usage }}</th><th><span class="sr-only">{{ s.app.actions }}</span></th></tr></thead>
          <tbody><tr v-for="p in l.data.value?.projects" :key="p.metadata.name" :data-project="p.metadata.name">
            <td :data-label="s.projects.name">
              <router-link class="mono" :to="`/projects/${p.metadata.name}`">{{ p.metadata.name }}</router-link>
              <span v-if="p.metadata.name === projectState.current" class="pill info" style="margin-left: 6px">{{ s.projects.current }}</span>
              <span v-if="p.spec.hosts?.length" class="badge info" style="margin-left: 6px">{{ s.projects.fleet }}</span>
              <div v-if="p.spec.comment" class="faint">{{ p.spec.comment }}</div>
            </td>
            <td class="mono" :data-label="s.projects.networks">{{ grants(p) }}</td><td class="mono" :data-label="s.projects.storage">{{ stor(p) }}</td>
            <td :data-label="s.projects.usage"><QuotaBars :project="p" /><span class="faint">{{ s.projects.jailsCount(p.status.jails ?? 0) }}</span></td>
            <td class="nowrap actions"><button class="btn btn-sm" type="button" :disabled="p.metadata.name === projectState.current" @click="switchProject(p.metadata.name)">{{ s.project.switch }}</button></td>
          </tr></tbody></table></div>
      </div>
    </LoadState>
    <ProjectForm :open="creating" :project="null" :networks="l.data.value?.networks ?? []" :storage="l.data.value?.storage ?? []" @close="creating = false" @done="done" />
  </div>
</template>
