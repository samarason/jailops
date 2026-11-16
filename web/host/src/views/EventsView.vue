<script setup lang="ts">
import { computed, ref } from 'vue'
import { s } from '@/i18n'
import { eventState } from '@jailops/shared/composables/events'
import { sentence } from '@jailops/shared/lib/format'
import { objectOf } from '@jailops/shared/lib/describe'
import { hostKinds } from '@/lib/objects'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import type { ApiEvent } from '@jailops/shared/api/types'

const type = ref('')
const paused = ref(false)
const held = ref<ApiEvent[] | null>(null)

const view = computed(() => (held.value ?? eventState.items).filter((e) => !type.value || e.type === type.value))
function pause(): void {
  paused.value = !paused.value
  held.value = paused.value ? [...eventState.items] : null
}
function clear(): void {
  eventState.items.length = 0
  if (held.value) held.value = []
}
function summary(e: ApiEvent): { text: string; source: string; who: string } {
  const m = (e.metadata ?? {}) as Record<string, unknown>
  if (e.type === 'lifecycle') {
    // the object by kind and name, not its API path
    const o = objectOf(String(m.source ?? ''), hostKinds)
    const detail = m.detail ? `: ${String(m.detail)}` : ''
    return { text: sentence(String(m.action ?? '')) + detail, source: o ? `${o.kind} ${o.name}` : String(m.source ?? ''), who: String(m.requestor ?? '') }
  }
  if (e.type === 'operation') return { text: `${m.description ?? ''} ${m.status ?? ''}`.trim(), source: String(m.id ?? ''), who: '' }
  return { text: String(m.message ?? JSON.stringify(m)), source: '', who: '' }
}
</script>

<template>
  <div>
    <div class="page-head">
      <h1>{{ s.ops.eventsTitle }}</h1>
      <span class="pill" :class="eventState.link === 'live' ? 'ok pulse' : 'warn'" data-test="link">{{ eventState.link === 'live' ? s.app.live : eventState.link === 'reconnecting' ? s.app.reconnecting(Math.ceil(eventState.retryIn / 1000)) : s.app.connecting }}</span>
    </div>
    <div class="row toolbar">
      <select v-model="type" :aria-label="s.ops.filterType" style="width: auto"><option value="">{{ s.ops.allTypes }}</option><option value="lifecycle">{{ sentence('lifecycle') }}</option><option value="operation">{{ sentence('operation') }}</option><option value="logging">{{ sentence('logging') }}</option></select>
      <button class="btn" type="button" :aria-pressed="paused" @click="pause"><Icon name="pause" />{{ paused ? s.ops.resume : s.ops.pause }}</button>
      <button class="btn" type="button" @click="clear">{{ s.ops.clear }}</button>
    </div>
    <p v-if="paused" class="muted">{{ s.ops.paused }}</p>
    <div class="panel">
      <p v-if="!view.length" class="empty">{{ s.ops.eventsEmpty }}</p>
      <div v-else class="table-wrap">
        <table data-test="events" class="rtable">
          <thead><tr><th>{{ s.ops.time }}</th><th>{{ s.ops.type }}</th><th>{{ s.ops.event }}</th><th>{{ s.ops.source }}</th><th>{{ s.ops.requestor }}</th></tr></thead>
          <tbody>
            <tr v-for="(e, i) in view" :key="e.timestamp + i">
              <td class="faint" :data-label="s.ops.time"><TimeStamp :ts="e.timestamp" seconds /></td>
              <td :data-label="s.ops.type"><span class="pill" :class="e.type === 'lifecycle' ? 'info' : e.type === 'operation' ? '' : 'warn'">{{ sentence(e.type) }}</span></td>
              <td :data-label="s.ops.event">{{ summary(e).text }}</td>
              <td class="faint" :data-label="s.ops.source">{{ summary(e).source }}</td>
              <td class="mono faint" :data-label="s.ops.requestor">{{ summary(e).who }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
