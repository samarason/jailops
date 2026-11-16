<script setup lang="ts">
import { computed } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import type { DoctorStatus } from '@jailops/shared/api/types'

const l = useLoad(() => api.doctor())
const order: Record<DoctorStatus, number> = { fail: 0, warn: 1, unknown: 2, info: 3, ok: 4 }
const tone: Record<DoctorStatus, string> = { fail: 'danger', warn: 'warn', unknown: 'info', info: 'info', ok: 'ok' }
const checks = computed(() => [...(l.data.value?.checks ?? [])].sort((a, b) => order[a.status] - order[b.status] || a.name.localeCompare(b.name)))
const counts = computed(() => {
  const c: Record<DoctorStatus, number> = { fail: 0, warn: 0, unknown: 0, info: 0, ok: 0 }
  for (const k of l.data.value?.checks ?? []) c[k.status]++
  return c
})
</script>

<template>
  <div>
    <div class="page-head">
      <h1>{{ s.doctor.title }}</h1>
      <button class="btn" type="button" @click="l.reload">{{ s.doctor.rerun }}</button>
    </div>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div v-if="l.data.value" class="stack">
        <div class="row">
          <span class="pill" :class="tone[l.data.value.status]" data-test="doctor-status">{{ s.doctor.status[l.data.value.status] }}</span>
          <span class="muted">{{ s.doctor.summary(counts.fail, counts.warn, counts.unknown, counts.ok, counts.info) }}</span>
          <span class="faint"><TimeStamp :ts="l.data.value.time" /></span>
        </div>
        <div class="panel">
          <p v-if="!checks.length" class="empty">{{ s.doctor.empty }}</p>
          <div v-else class="table-wrap"><table class="rtable" data-test="doctor-table">
            <thead><tr><th>{{ s.doctor.check }}</th><th>{{ s.doctor.result }}</th><th>{{ s.doctor.message }}</th></tr></thead>
            <tbody><tr v-for="c in checks" :key="c.name" :class="{ drift: c.status === 'fail' }" :data-check="c.name">
              <td class="mono" :data-label="s.doctor.check">{{ c.name }}</td>
              <td :data-label="s.doctor.result"><span class="pill" :class="tone[c.status]">{{ s.doctor.status[c.status] }}</span></td>
              <td :data-label="s.doctor.message">{{ c.message }}
                <div v-if="c.hint && c.status !== 'ok'" class="muted"><strong>{{ s.error.hint }}:</strong> {{ c.hint }}</div>
                <div v-if="c.detail && Object.keys(c.detail).length" class="mono faint">{{ Object.entries(c.detail).map(([k, v]) => `${k}=${v}`).join(' ') }}</div></td>
            </tr></tbody></table></div>
        </div>
      </div>
    </LoadState>
  </div>
</template>
