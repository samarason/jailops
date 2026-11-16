<script setup lang="ts">
import { computed } from 'vue'
import { s } from '@/i18n'
import { bytes, parseSize } from '@jailops/shared/lib/format'
import Meter from '@jailops/shared/components/Meter.vue'
import { quotaRows } from '@/lib/projectScope'
import type { Project } from '@jailops/shared/api/types'

const props = defineProps<{ project: Project }>()
const rows = computed(() => quotaRows(props.project.spec, props.project.status, parseSize))
const fmt = (key: string, v: number) => (key === 'memory' ? bytes(v) : String(v))
</script>

<template>
  <div class="quota-bars" data-test="quota-bars">
    <p v-if="!rows.length" class="muted">{{ s.project.noQuota }}</p>
    <div v-for="r in rows" :key="r.key" class="qrow" :data-quota="r.key">
      <span class="faint">{{ s.project.quotaNames[r.key] }}</span>
      <Meter :value="r.pct" :label="s.project.quotaNames[r.key]" :warn-at="75" :danger-at="95" />
      <span class="mono nowrap-cell">{{ fmt(r.key, r.used) }} / {{ fmt(r.key, r.limit) }}</span>
    </div>
  </div>
</template>

<style>
.nowrap-cell { white-space: nowrap; }
.qrow { display: grid; grid-template-columns: 110px 1fr minmax(140px, auto); gap: 12px; align-items: center; margin-bottom: 6px; }
@media (max-width: 800px) { .qrow { grid-template-columns: 1fr; gap: 2px; } }
</style>
