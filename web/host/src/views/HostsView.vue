<script setup lang="ts">
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { session } from '@jailops/shared/composables/session'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'

const l = useLoad(() => api.remotes.list())
const hubExt = () => session.info?.api_extensions.length ?? 0
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.hosts.title }}</h1><span class="muted">{{ s.hosts.lead }}</span></div>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div class="panel">
        <p v-if="!l.data.value?.length" class="empty">{{ s.hosts.empty }}</p>
        <div v-else class="table-wrap">
          <table class="rtable" data-test="hosts-table">
            <thead><tr><th>{{ s.hosts.name }}</th><th>{{ s.hosts.status }}</th><th>{{ s.hosts.address }}</th><th>{{ s.hosts.version }}</th><th class="num">{{ s.hosts.extensions }}</th><th>{{ s.hosts.lastSeen }}</th></tr></thead>
            <tbody>
              <tr v-for="r in l.data.value" :key="r.metadata.name">
                <td class="mono" :data-label="s.hosts.name">{{ r.metadata.name }}</td>
                <td :data-label="s.hosts.status"><span class="pill" :class="r.status.online ? 'ok' : 'danger'">{{ r.status.online ? s.hosts.online : s.hosts.offline }}</span></td>
                <td class="mono" :data-label="s.hosts.address">{{ r.spec.address }}</td>
                <td class="mono" :data-label="s.hosts.version">{{ r.status.version || '-' }}</td>
                <td class="num mono" :data-label="s.hosts.extensions">{{ r.status.extensions ?? '-' }}<span v-if="(r.status.extensions ?? 0) && (r.status.extensions ?? 0) < hubExt()" class="badge warn" style="margin-left: 6px" :title="s.hosts.skew">{{ s.hosts.fewer }}</span></td>
                <td class="faint" :data-label="s.hosts.lastSeen"><TimeStamp :ts="r.status.last_seen" /></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </LoadState>
  </div>
</template>
