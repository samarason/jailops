<script setup lang="ts">
import { computed, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { session } from '@jailops/shared/composables/session'
import { actionText } from '@jailops/shared/lib/describe'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import RoleNote from '@/components/RoleNote.vue'
import { allows } from '@/lib/roles'
import type { NodeAuditEntry } from '@/types'

const admin = computed(() => allows(session.role, 'admin'))
const action = ref('')
const extra = ref<NodeAuditEntry[]>([])
const l = useLoad(async () => (admin.value ? api.audit({ action: action.value || undefined }) : []))
const rows = computed(() => [...(l.data.value ?? []), ...extra.value])
async function older(): Promise<void> {
  const last = rows.value.at(-1)
  if (last) extra.value = [...extra.value, ...(await api.audit({ action: action.value || undefined, before: last.id }))]
}
async function apply(): Promise<void> {
  extra.value = []
  await l.reload()
}
const action_ = (a: string) => s.audit.actions[a] ?? actionText(a, {})
const detail = (d: unknown) => (d && JSON.stringify(d) !== '{}' ? JSON.stringify(d) : '')
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.audit.title }}</h1></div>
    <RoleNote need="admin" gate />
    <template v-if="admin">
      <form class="row toolbar" @submit.prevent="apply"><input v-model="action" type="search" :placeholder="s.audit.filter" :aria-label="s.audit.filter" style="max-width: 360px" /><button class="btn" type="submit">{{ s.audit.apply }}</button></form>
      <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
        <div class="panel">
          <p v-if="!rows.length" class="empty">{{ s.audit.empty }}</p>
          <div v-else class="table-wrap"><table class="rtable">
            <thead><tr><th>{{ s.audit.time }}</th><th>{{ s.audit.who }}</th><th>{{ s.audit.action }}</th><th>{{ s.audit.target }}</th><th class="hide-sm">{{ s.audit.detail }}</th><th class="hide-sm">{{ s.audit.source }}</th></tr></thead>
            <tbody><tr v-for="r in rows" :key="r.id">
              <td class="faint" :data-label="s.audit.time"><TimeStamp :ts="r.at" seconds /></td><td class="mono" :data-label="s.audit.who">{{ r.actor }}</td><td :data-label="s.audit.action" :title="r.action" :data-action="r.action">{{ action_(r.action) }}</td><td class="mono" :data-label="s.audit.target">{{ r.target || '-' }}</td>
              <td class="mono faint hide-sm" :data-label="s.audit.detail">{{ detail(r.detail) }}</td><td class="mono faint hide-sm" :data-label="s.audit.source">{{ r.remote || '-' }}</td>
            </tr></tbody></table></div>
        </div>
        <div v-if="rows.length >= 100" style="margin-top: 12px"><button class="btn" type="button" @click="older">{{ s.audit.older }}</button></div>
      </LoadState>
    </template>
  </div>
</template>
