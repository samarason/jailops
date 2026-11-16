<script setup lang="ts">
import { computed, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { can, hasExt } from '@jailops/shared/composables/session'
import { runOp } from '@jailops/shared/composables/ops'
import { bytes, stamp, sentence } from '@jailops/shared/lib/format'
import { useTabQuery } from '@jailops/shared/composables/tabs'
import TabBar from '@jailops/shared/components/TabBar.vue'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ConfirmDialog from '@jailops/shared/components/ConfirmDialog.vue'
import BackupKeyPanel from '@/components/BackupKeyPanel.vue'
import RestoreWizard from '@/components/RestoreWizard.vue'
import type { Backup } from '@jailops/shared/api/types'

const l = useLoad(async () => {
  const [targets, policies, backups] = await Promise.all([api.backups.targets(), api.backups.policies(), api.backups.list()])
  return { targets, policies, backups }
})
type Tab = 'snapshots' | 'runs' | 'targets' | 'policies' | 'key'
const tabItems = computed(() => [
  { key: 'snapshots' as Tab, label: s.backups.snapshots }, { key: 'runs' as Tab, label: s.backups.lastRuns }, { key: 'targets' as Tab, label: s.backups.targets },
  { key: 'policies' as Tab, label: s.backups.policies }, ...(hasExt('backup_key') ? [{ key: 'key' as Tab, label: s.backups.keyTab }] : []),
])
const { tab } = useTabQuery(() => tabItems.value.map((t) => t.key), 'snapshots' as Tab)
const restoring = ref<Backup | null>(null)
const deleting = ref<Backup | null>(null)

// a volume is a backup of its own, so a jail and a volume of the same name are two groups
const isVolume = (b: Backup) => b.spec.kind === 'volume'
const groupKey = (b: Backup) => (isVolume(b) ? 'volume:' : 'jail:') + b.spec.jail
const byJail = computed(() => {
  const m = new Map<string, Backup[]>()
  for (const b of l.data.value?.backups ?? []) {
    const k = groupKey(b)
    if (!m.has(k)) m.set(k, [])
    m.get(k)!.push(b)
  }
  for (const v of m.values()) v.sort((a, b) => (b.metadata.created_at ?? '').localeCompare(a.metadata.created_at ?? ''))
  return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]))
})
const runs = computed(() => byJail.value.map(([key, list]) => ({ key, jail: list[0].spec.jail, volume: isVolume(list[0]), last: list[0] })))

const requestDelete = () => runOp(s.backups.deleteTitle(deleting.value!.spec.snapshot), () => api.backups.requestDeletion(deleting.value!.metadata.name))
const depth = ref<'deep' | 'extract' | 'full'>('deep')
const verify = (b: Backup) => runOp(s.backups.verifyTitle(b.spec.snapshot), () => api.backups.verify(b.metadata.name, { depth: depth.value })).catch(() => undefined)
const run = (n: string, noVolumes = false) => runOp(s.backups.runTitle(n), () => api.backups.run({ policy: n, ...(noVolumes ? { no_volumes: true } : {}) })).catch(() => undefined)
const retention = (r: object) => Object.entries(r as Record<string, number | undefined>).filter(([, v]) => v).map(([k, v]) => `${v} ${k}`).join(', ') || '-'
const sel = (m: Record<string, string> | undefined) => Object.entries(m ?? {}).map(([k, v]) => `${k}=${v}`).join(', ') || '-'
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.backups.title }}</h1></div>
    <Callout style="margin-bottom: 12px">{{ s.backups.keyless }}</Callout>
    <TabBar v-model="tab" :tabs="tabItems" :label="s.backups.sections" id="bk" />
    <div id="bk-panel" role="tabpanel" :aria-labelledby="`bk-tab-${tab}`">
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div v-if="tab === 'snapshots'" class="stack">
        <p v-if="!byJail.length" class="empty panel">{{ s.backups.noBackups }}</p>
        <section v-for="[key, list] in byJail" :key="key" class="panel" :data-jail="list[0].spec.jail" :data-kind="isVolume(list[0]) ? 'volume' : 'jail'">
          <header><h2 class="mono">{{ list[0].spec.jail }}</h2><span v-if="isVolume(list[0])" class="pill info" data-test="volume-backup">{{ s.backups.kindVolume }}</span><span class="faint">{{ s.backups.count(list.length) }}</span></header>
          <div class="table-wrap">
            <table class="rtable">
              <thead><tr><th>{{ s.backups.snapshot }}</th><th class="num">{{ s.backups.size }}</th><th class="num">{{ s.backups.newBytes }}</th><th>{{ s.backups.state }}</th><th><span class="sr-only">{{ s.app.actions }}</span></th></tr></thead>
              <tbody>
                <tr v-for="b in list" :key="b.metadata.name" :data-backup="b.metadata.name" :class="{ drift: b.status.failed }">
                  <td :data-label="s.backups.snapshot"><TimeStamp :ts="b.metadata.created_at" /><br /><span class="mono faint bk-snap">{{ b.spec.snapshot }}</span> <span class="faint">· {{ b.spec.full ? s.backups.full : s.backups.incremental }}</span></td>
                  <td class="num mono" :data-label="s.backups.size">{{ bytes(b.status.bytes) }}</td>
                  <td class="num mono" :data-label="s.backups.newBytes">{{ bytes(b.status.new_bytes) }}</td>
                  <td :data-label="s.backups.state">
                    <span v-if="b.status.failed" class="pill danger" data-test="failed">{{ s.backups.failed }}</span>
                    <span v-else-if="b.status.verified" class="pill ok">{{ s.backups.verified }}</span>
                    <span v-else class="pill warn">{{ s.backups.unverified }}</span>
                    <span v-if="b.status.protected" class="pill info" data-test="protected" style="margin-left: 4px"><Icon name="lock" />{{ s.backups.protected }}</span>
                    <span v-if="b.status.pending_deletion" class="pill danger" data-test="pending" style="margin-left: 4px">{{ s.backups.pendingDeletion }}</span>
                    <div v-if="b.status.pending_deletion" class="faint">{{ s.backups.pendingUntil(stamp(b.status.pending_deletion)) }}</div>
                  </td>
                  <td class="actions">
                    <div class="row-actions">
                    <button v-if="can('restore')" class="btn btn-sm" type="button" :disabled="b.status.failed" @click="restoring = b">{{ s.backups.restore }}</button>
                    <select v-if="hasExt('backup_verify')" v-model="depth" class="depth" :aria-label="s.backups.depth"><option value="deep">{{ s.backups.depths.deep }}</option><option value="extract">{{ s.backups.depths.extract }}</option><option value="full">{{ s.backups.depths.full }}</option></select><button v-if="hasExt('backup_verify')" class="btn btn-sm" type="button" @click="verify(b)">{{ s.backups.verify }}</button>
                    <button v-if="!b.status.pending_deletion" class="btn btn-sm btn-danger" type="button" :disabled="b.status.protected" @click="deleting = b">{{ s.backups.requestDelete }}</button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <div v-else-if="tab === 'runs'" class="panel">
        <header><span class="muted">{{ s.backups.lastRunsHint }}</span></header>
        <p v-if="!runs.length" class="empty">{{ s.backups.noBackups }}</p>
        <div v-else class="table-wrap"><table class="rtable">
          <thead><tr><th>{{ s.backups.name }}</th><th>{{ s.backups.kind }}</th><th>{{ s.backups.policy }}</th><th>{{ s.backups.lastBackup }}</th><th>{{ s.backups.state }}</th></tr></thead>
          <tbody><tr v-for="r in runs" :key="r.key">
            <td class="mono" :data-label="s.backups.name">{{ r.jail }}</td><td :data-label="s.backups.kind">{{ r.volume ? s.backups.kindVolume : s.backups.kindJail }}</td><td class="mono" :data-label="s.backups.policy">{{ r.last.spec.policy || '-' }}</td><td :data-label="s.backups.lastBackup"><TimeStamp :ts="r.last.metadata.created_at" /> <span class="faint">{{ bytes(r.last.status.new_bytes) }}</span></td>
            <td :data-label="s.backups.state"><span class="pill" :class="r.last.status.failed ? 'danger' : r.last.status.verified ? 'ok' : 'warn'">{{ r.last.status.failed ? s.backups.failed : r.last.status.verified ? s.backups.verified : s.backups.unverified }}</span></td>
          </tr></tbody></table></div>
      </div>

      <BackupKeyPanel v-else-if="tab === 'key'" />

      <div v-else-if="tab === 'targets'" class="panel">
        <p v-if="!l.data.value?.targets.length" class="empty">{{ s.backups.noTargets }}</p>
        <div v-else class="table-wrap"><table class="rtable">
          <thead><tr><th>{{ s.backups.name }}</th><th>{{ s.backups.kind }}</th><th>{{ s.backups.address }}</th><th>{{ s.backups.fingerprint }}</th></tr></thead>
          <tbody><tr v-for="t in l.data.value?.targets" :key="t.metadata.name">
            <td class="mono" :data-label="s.backups.name">{{ t.metadata.name }}</td><td :data-label="s.backups.kind">{{ sentence(t.spec.kind) }}</td><td class="mono" :data-label="s.backups.address">{{ t.spec.address || t.spec.path || '-' }}</td><td class="mono faint" :data-label="s.backups.fingerprint">{{ t.spec.fingerprint?.slice(0, 23) || '-' }}</td>
          </tr></tbody></table></div>
      </div>

      <div v-else class="panel">
        <p v-if="!l.data.value?.policies.length" class="empty">{{ s.backups.noPolicies }}</p>
        <div v-else class="table-wrap"><table class="rtable">
          <thead><tr><th>{{ s.backups.name }}</th><th>{{ s.backups.selector }}</th><th>{{ s.backups.targets }}</th><th>{{ s.backups.schedule }}</th><th>{{ s.backups.retention }}</th><th>{{ s.backups.verifySchedule }}</th><th><span class="sr-only">{{ s.app.actions }}</span></th></tr></thead>
          <tbody><tr v-for="p in l.data.value?.policies" :key="p.metadata.name">
            <td class="mono" :data-label="s.backups.name">{{ p.metadata.name }}<span v-if="p.spec.exclude_volumes" class="pill" style="margin-left: 6px" data-test="volumes-excluded">{{ s.backups.volumesExcluded }}</span></td>
            <td class="mono" :data-label="s.backups.selector">{{ sel(p.spec.selector) }}</td><td class="mono" :data-label="s.backups.targets">{{ (p.spec.targets ?? []).join(', ') }}</td><td class="mono" :data-label="s.backups.schedule">{{ p.spec.schedule }}</td>
            <td :data-label="s.backups.retention">{{ retention(p.spec.retention) }}</td>
            <td class="mono" :data-label="s.backups.verifySchedule">{{ p.spec.verify_schedule || '-' }}<span v-if="p.spec.verify_mode" class="faint"> ({{ p.spec.verify_mode }})</span></td>
            <td class="actions"><div class="row-actions"><button v-if="hasExt('backup_run')" class="btn btn-sm" type="button" @click="run(p.metadata.name)">{{ s.backups.run }}</button><button v-if="hasExt('backup_run') && !p.spec.exclude_volumes" class="btn btn-sm" type="button" data-test="run-no-volumes" @click="run(p.metadata.name, true)">{{ s.backups.runNoVolumes }}</button></div></td>
          </tr></tbody></table></div>
      </div>
    </LoadState>
    </div>

    <RestoreWizard :open="!!restoring" :backup="restoring" @close="restoring = null" @done="l.reload" />
    <ConfirmDialog :open="!!deleting" :title="s.backups.deleteTitle(deleting?.spec.snapshot ?? '')" :confirm-label="s.backups.requestDelete" danger :run="requestDelete" @close="deleting = null">
      <Callout tone="warn">{{ s.backups.deleteText }}</Callout>
    </ConfirmDialog>
  </div>
</template>

<style>
.row-actions select.depth { width: auto; min-width: 0; }
.bk-snap { font-size: 12px; overflow-wrap: anywhere; }
</style>
