<script setup lang="ts">
import { computed, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { sentence } from '@jailops/shared/lib/format'
import { actionText, objectOf } from '@jailops/shared/lib/describe'
import { hostKinds } from '@/lib/objects'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import type { AuditEntry } from '@jailops/shared/api/types'

const l = useLoad(() => api.audit.list())
const q = ref('')
// what an entry did, in words, and the object by name with a link (the route and path stay in the tooltip)
const what = (r: AuditEntry) => actionText(r.action, hostKinds)
const obj = (r: AuditEntry) => objectOf(r.resource, hostKinds)
const rows = computed(() => {
  const n = q.value.trim().toLowerCase()
  return (l.data.value ?? []).filter((r) => !n || [r.requestor, r.action, what(r), r.resource ?? '', obj(r)?.name ?? ''].some((x) => x.toLowerCase().includes(n)))
})
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.audit.title }}</h1></div>
    <div class="row toolbar"><input v-model="q" type="search" :placeholder="s.audit.filter" :aria-label="s.audit.filter" style="max-width: 420px" /></div>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div class="panel">
        <p v-if="!rows.length" class="empty">{{ s.audit.empty }}</p>
        <div v-else class="table-wrap">
          <table class="rtable" data-test="audit-table">
            <thead><tr><th>{{ s.audit.time }}</th><th>{{ s.audit.who }}</th><th>{{ s.audit.action }}</th><th>{{ s.audit.resource }}</th><th>{{ s.audit.result }}</th><th>{{ s.audit.source }}</th></tr></thead>
            <tbody>
              <tr v-for="r in rows" :key="r.id" :data-audit="r.id">
                <td class="faint" :data-label="s.audit.time"><TimeStamp :ts="r.timestamp" seconds /></td>
                <td class="mono" :data-label="s.audit.who">{{ r.requestor }}</td>
                <td :data-label="s.audit.action" :title="r.action">{{ what(r) }}</td>
                <td :data-label="s.audit.resource">
                  <template v-if="obj(r)"><span class="faint">{{ obj(r)!.kind }}</span> <router-link v-if="obj(r)!.to" class="mono" :to="obj(r)!.to!">{{ obj(r)!.name }}</router-link><span v-else class="mono">{{ obj(r)!.name }}</span></template>
                  <span v-else class="mono">{{ r.resource || '-' }}</span>
                </td>
                <td :data-label="s.audit.result"><span v-if="r.result" class="pill" :class="r.result === 'ok' ? 'ok' : 'danger'">{{ sentence(r.result) }}</span></td>
                <td class="mono faint" :data-label="s.audit.source">{{ r.source_ip || '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </LoadState>
  </div>
</template>
