<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { session } from '@jailops/shared/composables/session'
import { ApiError } from '@jailops/shared/api/client'
import { bytes, stamp } from '@jailops/shared/lib/format'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import Modal from '@jailops/shared/components/Modal.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import RoleNote from '@/components/RoleNote.vue'
import { allows } from '@/lib/roles'
import type { Snapshot } from '@/types'

const l = useLoad(() => api.groups.list())
const group = ref('')
const snaps = useLoad(async () => (group.value ? api.groups.snapshots(group.value) : []))
const operate = computed(() => allows(session.role, 'backup-admin'))
const rows = computed(() => [...(snaps.data.value ?? [])].sort((a, b) => b.committed_at.localeCompare(a.committed_at)))
const cur = computed(() => l.data.value?.find((g) => g.group_id === group.value))

watch(() => l.data.value, (g) => { if (g?.length && !group.value) group.value = g[0].group_id }, { immediate: true })
watch(group, () => void snaps.reload())

const target = ref<Snapshot | null>(null)
const delay = ref('')
const busy = ref(false)
const error = ref<ApiError | null>(null)
const failed = (x: Snapshot) => x.verify_state === 'failed'

function open(x: Snapshot): void {
  target.value = x
  delay.value = ''
  error.value = null
}
async function request(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    await runOp(s.snapshots.requestTitle(target.value!.snapshot_id), () => api.groups.requestDeletion(group.value, target.value!.snapshot_id, delay.value.trim() || undefined))
    target.value = null
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
function toggleProtect(x: Snapshot): void {
  runOp(x.protected ? s.snapshots.unprotectTitle(x.snapshot_id) : s.snapshots.protectTitle(x.snapshot_id), () => api.groups.setProtected(group.value, x.snapshot_id, !x.protected)).catch(() => undefined)
}
function cancel(x: Snapshot): void {
  runOp(s.deletions.cancelTitle(x.snapshot_id), () => api.groups.cancelDeletion(group.value, x.snapshot_id)).catch(() => undefined)
}
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.snapshots.title }}</h1></div>
    <p class="muted">{{ s.snapshots.lead }}</p>
    <Callout style="margin: 12px 0" data-test="keyless">{{ s.keyless }}</Callout>
    <RoleNote need="backup-admin" />
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <p v-if="!l.data.value?.length" class="empty panel" style="margin-top: 12px">{{ s.snapshots.noGroups }}</p>
      <div v-else class="grp-layout" style="margin-top: 12px">
        <ul class="plain picker" :aria-label="s.snapshots.groups">
          <li v-for="g in l.data.value" :key="g.group_id">
            <button type="button" class="btn btn-ghost" :class="{ sel: group === g.group_id }" :aria-current="group === g.group_id" :data-group="g.group_id" @click="group = g.group_id">
              <span class="mono grow">{{ g.group_id }}</span>
              <span v-if="g.failed" class="pill danger">{{ s.snapshots.failedCount(g.failed) }}</span>
              <span v-else class="faint">{{ g.snapshots }}</span>
            </button>
          </li>
        </ul>
        <section class="panel" :data-snapshots-of="group">
          <header>
            <div class="row"><h2 class="mono">{{ group }}</h2><span v-if="cur" class="faint">{{ cur.host_name }} · {{ s.snapshots.snapshots(cur.snapshots) }}<template v-if="cur.latest"> · {{ s.snapshots.latest }} <TimeStamp :ts="cur.latest" /></template></span></div>
          </header>
          <LoadState :loading="snaps.loading.value" :error="snaps.error.value" :has-data="!!snaps.data.value" @retry="snaps.reload">
            <p v-if="!rows.length" class="empty">{{ s.snapshots.empty }}</p>
            <div v-else class="table-wrap"><table class="rtable">
              <thead><tr><th>{{ s.snapshots.id }}</th><th class="num">{{ s.snapshots.chunks }}</th><th class="num hide-sm">{{ s.snapshots.index }}</th><th>{{ s.snapshots.state }}</th><th><span class="sr-only">{{ s.snapshots.actions }}</span></th></tr></thead>
              <tbody><tr v-for="x in rows" :key="x.snapshot_id" :class="{ drift: failed(x) }" :data-snapshot="x.snapshot_id">
                <td :data-label="s.snapshots.id"><span class="mono">{{ x.snapshot_id }}</span><br /><span class="faint"><TimeStamp :ts="x.committed_at" /><span v-if="x.source">{{ s.snapshots.committedSource(x.source) }}</span></span></td>
                <td class="num mono" :data-label="s.snapshots.chunks">{{ x.chunk_count.toLocaleString('en') }}</td>
                <td class="num mono hide-sm nowrap" :data-label="s.snapshots.index">{{ bytes(x.index_bytes) }}</td>
                <td :data-label="s.snapshots.state">
                  <span v-if="failed(x)" class="pill danger" data-test="failed">{{ s.snapshots.failed }}</span>
                  <span v-else-if="x.verify_state === 'ok'" class="pill ok" data-test="verified">{{ s.snapshots.verified }}</span>
                  <span v-else class="pill warn">{{ s.snapshots.unverified }}</span>
                  <span v-if="x.protected" class="pill info" data-test="protected" style="margin-left: 4px"><Icon name="lock" />{{ s.snapshots.protected }}</span>
                  <span v-if="x.pending_deletion_after" class="pill danger" data-test="pending" style="margin-left: 4px">{{ s.snapshots.pending }}</span>
                  <div v-if="x.pending_deletion_after" class="faint">{{ s.snapshots.pendingAfter(stamp(x.pending_deletion_after), x.pending_deletion_by ?? '-') }}</div>
                  <ul v-if="failed(x) && x.verify_problems?.length" class="plain faint mono" style="font-size: 12px"><li v-for="p in x.verify_problems" :key="p">{{ p }}</li></ul>
                </td>
                <td class="actions"><div class="row-actions">
                  <button class="btn btn-sm" type="button" :disabled="!operate" data-test="protect" :aria-label="`${x.protected ? s.snapshots.unprotect : s.snapshots.protect} ${x.snapshot_id}`" @click="toggleProtect(x)">{{ x.protected ? s.snapshots.unprotect : s.snapshots.protect }}</button>
                  <button v-if="x.pending_deletion_after" class="btn btn-sm" type="button" :disabled="!operate" @click="cancel(x)" :aria-label="`${s.snapshots.cancelDelete} ${x.snapshot_id}`">{{ s.snapshots.cancelDelete }}</button>
                  <button v-else class="btn btn-sm btn-danger" type="button" :disabled="!operate || x.protected" :title="x.protected ? s.snapshots.protectedHint : ''" data-test="request" :aria-label="`${s.snapshots.requestDelete} ${x.snapshot_id}`" @click="open(x)">{{ s.snapshots.requestDelete }}</button>
                </div><p v-if="x.protected && operate" class="faint why-row">{{ s.snapshots.protectedHint }}</p></td>
              </tr></tbody></table></div>
          </LoadState>
        </section>
      </div>
    </LoadState>

    <Modal :open="!!target" :title="s.snapshots.requestTitle(target?.snapshot_id ?? '')" @close="target = null">
      <form id="rq" @submit.prevent="request">
        <Callout tone="warn">{{ s.snapshots.requestText }}</Callout>
        <div class="field" style="margin-top: 12px"><label for="rq-delay">{{ s.snapshots.delay }}</label><input id="rq-delay" v-model="delay" class="mono" type="text" placeholder="72h" /><span class="hint">{{ s.snapshots.delayHint }}</span></div>
        <ErrorPanel v-if="error" :error="error" />
      </form>
      <template #footer><button class="btn" type="button" @click="target = null">{{ s.app.cancel }}</button><button class="btn btn-danger" type="submit" form="rq" :disabled="busy" data-test="request-go">{{ s.snapshots.submit }}</button></template>
    </Modal>
  </div>
</template>

<style>
.grp-layout { display: grid; grid-template-columns: 240px minmax(0, 1fr); gap: 12px; align-items: start; }
.picker { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 4px; }
.picker .btn { width: 100%; justify-content: flex-start; text-align: left; }
.picker .btn .grow { text-align: left; }
.why-row { margin: 4px 0 0; font-size: 12px; max-width: 30ch; }
.picker .btn.sel { background: var(--accent-soft); font-weight: 600; }
@media (max-width: 800px) { .grp-layout { grid-template-columns: minmax(0, 1fr); } }
</style>
