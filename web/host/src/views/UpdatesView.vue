<script setup lang="ts">
import { computed, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import Modal from '@jailops/shared/components/Modal.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import { projectState } from '@/composables/project'

const l = useLoad(() => api.updates.list())
const sel = ref<Set<string>>(new Set())
const rows = computed(() => [...(l.data.value ?? [])].sort((a, b) => a.jail.localeCompare(b.jail)))
const withUpdates = computed(() => rows.value.filter((r) => r.available))
const chosen = computed(() => rows.value.filter((r) => sel.value.has(r.jail) && r.available))
const toggle = (n: string) => { const x = new Set(sel.value); x.has(n) ? x.delete(n) : x.add(n); sel.value = x }
const allSel = computed(() => withUpdates.value.length > 0 && withUpdates.value.every((r) => sel.value.has(r.jail)))
const toggleAll = () => (sel.value = allSel.value ? new Set() : new Set(withUpdates.value.map((r) => r.jail)))

const batch = ref<string[] | null>(null)
const typed = ref('')
const busy = ref(false)
function openBatch(names: string[]): void {
  batch.value = names
  typed.value = ''
}
async function checkAll(): Promise<void> {
  await runOp(s.updates.checkAllTitle, () => api.updates.check({ all: true })).catch(() => undefined)
  await l.reload()
}
async function go(): Promise<void> {
  busy.value = true
  try {
    await runOp(s.updates.batchTitle(projectState.current, batch.value?.length ?? 0), () => api.updates.apply({ jails: batch.value ?? [] }))
    batch.value = null
    sel.value = new Set()
    await l.reload()
  } catch {
    /* the toast carries the error */
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.updates.title }}</h1>
      <div class="row"><button class="btn" type="button" data-test="check-all" @click="checkAll">{{ s.updates.checkAll }}</button><button class="btn" type="button" :disabled="!chosen.length" data-test="apply-selected" @click="openBatch(chosen.map((r) => r.jail))">{{ s.updates.applySelected }}</button>
        <button class="btn btn-primary" type="button" :disabled="!withUpdates.length" data-test="apply-project" @click="openBatch(withUpdates.map((r) => r.jail))">{{ s.updates.applyProject(projectState.current) }}</button></div></div>
    <p class="muted">{{ s.updates.fleetLead }} <strong>{{ s.updates.withUpdates(withUpdates.length) }}</strong></p>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div class="panel" style="margin-top: 12px"><p v-if="!rows.length" class="empty">{{ s.jails.emptyNone }}</p>
        <div v-else class="table-wrap"><table data-test="updates-table" class="rtable">
          <thead><tr><th style="width: 32px"><input type="checkbox" :checked="allSel" :aria-label="s.updates.selectAll" @change="toggleAll" /></th><th>{{ s.updates.jail }}</th><th>{{ s.updates.mode }}</th><th>{{ s.updates.lastCheck }}</th><th>{{ s.updates.available }}</th></tr></thead>
          <tbody><tr v-for="r in rows" :key="r.jail" :data-jail="r.jail">
            <td class="check-cell"><input type="checkbox" :checked="sel.has(r.jail)" :disabled="!r.available" :aria-label="r.jail" @change="toggle(r.jail)" /></td>
            <td :data-label="s.updates.jail"><router-link class="mono" :to="`/jails/${r.jail}`">{{ r.jail }}</router-link></td>
            <td :data-label="s.updates.mode"><span class="pill" :class="r.mode === 'managed' ? 'info' : ''">{{ s.updates.modes[r.mode ?? 'manual'] }}</span></td><td class="faint" :data-label="s.updates.lastCheck"><TimeStamp :ts="r.checked_at" /></td>
            <td :data-label="s.updates.available"><template v-if="r.available"><span v-if="r.packages?.length" class="chip">{{ s.updates.pkgChip(r.packages.length) }}</span><span v-if="r.os" class="chip">{{ s.updates.osChip(r.os.from, r.os.to) }}</span></template><span v-else-if="r.error" class="pill warn" :title="r.error">{{ s.updates.checkFailed }}</span><span v-else class="faint">{{ s.updates.none }}</span></td>
          </tr></tbody></table></div></div>
    </LoadState>

    <Modal :open="!!batch" :title="s.updates.batchTitle(projectState.current, batch?.length ?? 0)" @close="batch = null">
      <form id="ub" @submit.prevent="go">
        <Callout tone="warn">{{ s.updates.batchText }}</Callout>
        <ul class="plain mono" style="margin: 12px 0"><li v-for="n in batch" :key="n">{{ n }}</li></ul>
        <div class="field"><label for="ub-typed">{{ s.projects.typeName(projectState.current) }}</label><input id="ub-typed" v-model="typed" class="mono" type="text" autocomplete="off" spellcheck="false" /></div>
      </form>
      <template #footer><button class="btn" type="button" @click="batch = null">{{ s.app.cancel }}</button><button class="btn btn-primary" type="submit" form="ub" :disabled="busy || typed !== projectState.current" data-test="batch-go">{{ s.updates.apply }}</button></template>
    </Modal>
  </div>
</template>
