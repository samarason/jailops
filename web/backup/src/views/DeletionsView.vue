<script setup lang="ts">
import { computed } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { session } from '@jailops/shared/composables/session'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import { confirmAction } from '@jailops/shared/composables/confirm'
import Callout from '@jailops/shared/components/Callout.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import RoleNote from '@/components/RoleNote.vue'
import { allows } from '@/lib/roles'
import type { Snapshot } from '@/types'

interface Row extends Snapshot { _group: string }
const l = useLoad(async () => {
  const groups = (await api.groups.list()).filter((g) => g.pending_deletion > 0)
  const all = await Promise.all(groups.map(async (g) => (await api.groups.snapshots(g.group_id)).map((x) => ({ ...x, _group: g.group_id }) as Row)))
  return all.flat().filter((x) => x.pending_deletion_after)
})
const operate = computed(() => allows(session.role, 'backup-admin'))
const rows = computed(() => [...(l.data.value ?? [])].sort((a, b) => (a.pending_deletion_after ?? '').localeCompare(b.pending_deletion_after ?? '')))
const ready = (x: Row) => !!x.pending_deletion_after && Date.parse(x.pending_deletion_after) <= Date.now()

function askCancel(x: Row): void {
  confirmAction({
    title: s.deletions.cancelTitle(x.snapshot_id), confirmLabel: s.deletions.cancel, text: s.deletions.cancelText,
    run: () => runOp(s.deletions.cancelTitle(x.snapshot_id), () => api.groups.cancelDeletion(x._group, x.snapshot_id)), done: () => void l.reload(),
  })
}
// executing removes the snapshot for good: the id is typed
function openExec(x: Row): void {
  confirmAction({
    title: s.deletions.executeTitle(x.snapshot_id), confirmLabel: s.deletions.execute, danger: true, text: s.deletions.executeText,
    items: [`${x._group} / ${x.snapshot_id}`], typeName: x.snapshot_id, typeLabel: s.deletions.typeId(x.snapshot_id),
    run: () => runOp(s.deletions.executeTitle(x.snapshot_id), () => api.groups.executeDeletion(x._group, x.snapshot_id)), done: () => void l.reload(),
  })
}
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.deletions.title }}</h1></div>
    <Callout style="margin-bottom: 12px">{{ s.deletions.lead }}</Callout>
    <RoleNote need="backup-admin" />
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div class="panel" style="margin-top: 12px">
        <p v-if="!rows.length" class="empty">{{ s.deletions.empty }}</p>
        <div v-else class="table-wrap"><table class="rtable">
          <thead><tr><th>{{ s.deletions.snapshot }}</th><th class="hide-sm">{{ s.deletions.requestedBy }}</th><th>{{ s.deletions.executes }}</th><th>{{ s.deletions.state }}</th><th><span class="sr-only">{{ s.app.actions }}</span></th></tr></thead>
          <tbody><tr v-for="x in rows" :key="x._group + x.snapshot_id" :data-deletion="x.snapshot_id">
            <td :data-label="s.deletions.snapshot"><span class="mono">{{ x.snapshot_id }}</span><br /><span class="faint mono">{{ x._group }}</span></td>
            <td class="hide-sm" :data-label="s.deletions.requestedBy"><TimeStamp :ts="x.pending_deletion_requested_at" /> <span class="faint">{{ s.deletions.requested(x.pending_deletion_by ?? '-') }}</span></td>
            <td :data-label="s.deletions.executes"><TimeStamp :ts="x.pending_deletion_after" /></td>
            <td :data-label="s.deletions.state"><span class="pill" :class="ready(x) ? 'danger' : 'warn'">{{ ready(x) ? s.deletions.ready : s.deletions.waiting }}</span></td>
            <td class="actions"><div class="row-actions">
              <button class="btn btn-sm" type="button" :disabled="!operate" @click="askCancel(x)" :aria-label="`${s.deletions.cancel} ${x.snapshot_id}`">{{ s.deletions.cancel }}</button>
              <button class="btn btn-sm btn-danger" type="button" :disabled="!operate || !ready(x)" data-test="execute" :aria-label="`${s.deletions.execute} ${x.snapshot_id}`" @click="openExec(x)">{{ s.deletions.execute }}</button>
            </div></td>
          </tr></tbody></table></div>
      </div>
    </LoadState>

    
  </div>
</template>
