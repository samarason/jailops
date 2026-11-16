<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { ApiError } from '@jailops/shared/api/client'
import { stamp } from '@jailops/shared/lib/format'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import Modal from '@jailops/shared/components/Modal.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import { updatePlan } from '@/lib/updates'
import type { Jail, UpdateMode, UpdateReport } from '@jailops/shared/api/types'

const props = defineProps<{ jail: Jail }>()
const emit = defineEmits<{ saved: [] }>()
const name = computed(() => props.jail.metadata.name)
const l = useLoad(async () => {
  const [reports, history] = await Promise.all([api.updates.list(), api.updates.history(name.value)])
  return { report: reports.find((r) => r.jail === name.value), history }
})
const report = computed<UpdateReport | undefined>(() => l.data.value?.report)
const spec = computed(() => props.jail.spec.update ?? {})
const policy = reactive({ mode: 'manual' as UpdateMode, schedule: '', packages: true, os: true, reboot: 'manual' as 'manual' | 'auto' })
watch(() => props.jail, () => Object.assign(policy, { mode: spec.value.mode ?? 'manual', schedule: spec.value.schedule ?? '', packages: spec.value.packages ?? true, os: spec.value.os ?? true, reboot: spec.value.reboot ?? 'manual' }), { immediate: true })
const modes: UpdateMode[] = ['manual', 'notify', 'managed']
const error = ref<ApiError | null>(null)
const busy = ref(false)
const open = ref(false)
const previewed = ref(false)

const pdirty = computed(() => policy.mode !== (spec.value.mode ?? 'manual') || policy.schedule !== (spec.value.schedule ?? '') || policy.packages !== (spec.value.packages ?? true) || policy.os !== (spec.value.os ?? true) || policy.reboot !== (spec.value.reboot ?? 'manual'))
const plan = computed(() => updatePlan(report.value, s.updates))
const available = computed(() => !!report.value?.available)
async function savePolicy(): Promise<void> {
  error.value = null
  try {
    await runOp(s.updates.policyTitle(name.value), () => api.jailConfig.post(name.value, { set: { 'updates.mode': policy.mode, 'updates.schedule': policy.schedule, 'updates.packages': String(policy.packages), 'updates.os': String(policy.os), 'updates.reboot': policy.reboot }, unset: policy.schedule ? [] : ['updates.schedule'] }))
    emit('saved')
  } catch (e) {
    error.value = e instanceof ApiError ? e : null
  }
}
async function check(): Promise<void> {
  error.value = null
  try {
    await runOp(s.updates.checkTitle(name.value), () => api.updates.check({ jails: [name.value] }))
    await l.reload()
  } catch (e) {
    error.value = e instanceof ApiError ? e : null
  }
}
function openApply(): void {
  previewed.value = false
  error.value = null
  open.value = true
}
async function apply(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    await runOp(s.updates.applyTitle(name.value), () => api.updates.apply({ jails: [name.value] }))
    open.value = false
    await l.reload()
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
const tone = (r: string) => (r === 'ok' ? 'ok' : r === 'rolled_back' ? 'warn' : 'danger')
</script>

<template>
  <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
    <div v-if="l.data.value" class="stack" data-test="updates-tab">
      <ErrorPanel v-if="error && !open" :error="error" />
      <section class="panel">
        <header><h2>{{ s.updates.title }}</h2>
          <div class="row"><button class="btn btn-sm" type="button" data-test="update-check" @click="check">{{ s.updates.check }}</button>
            <button class="btn btn-sm btn-primary" type="button" :disabled="!available" data-test="update-apply" @click="openApply">{{ s.updates.apply }}</button></div></header>
        <div class="body stack">
          <div class="grid-2">
            <div class="field"><label for="up-mode">{{ s.updates.mode }}</label>
              <select id="up-mode" v-model="policy.mode" data-test="update-mode"><option v-for="m in modes" :key="m" :value="m">{{ s.updates.modes[m] }}</option></select>
              <span class="hint">{{ s.updates.modeText[policy.mode] }}</span></div>
            <div class="field"><label for="up-sched">{{ s.updates.schedule }}</label><input id="up-sched" v-model="policy.schedule" class="mono" type="text" placeholder="0 3 * * 0" :disabled="policy.mode === 'manual'" /></div>
          </div>
          <div class="row">
            <label class="check"><input v-model="policy.packages" type="checkbox" />{{ s.updates.packages }}</label>
            <label class="check"><input v-model="policy.os" type="checkbox" />{{ s.updates.os }}</label>
            <label class="check"><input :checked="policy.reboot === 'auto'" type="checkbox" @change="policy.reboot = ($event.target as HTMLInputElement).checked ? 'auto' : 'manual'" />{{ s.updates.reboot }}</label>
          </div>
          <Callout v-if="policy.mode === 'managed'" tone="warn">{{ s.updates.managedWarn }}</Callout>
          <div class="row"><button class="btn btn-primary" type="button" :disabled="!pdirty" data-test="policy-save" @click="savePolicy">{{ s.updates.savePolicy }}</button>
            <span class="faint">{{ s.updates.lastCheck }}: <TimeStamp v-if="report" :ts="report.checked_at" /><template v-else>{{ s.updates.never }}</template></span></div>
        </div>
      </section>

      <section class="panel"><header><h2>{{ s.updates.available }}</h2></header>
        <Callout v-if="report?.error" tone="warn" data-test="check-error">{{ report.error }}</Callout>
        <p v-else-if="!available" class="empty" data-test="no-updates">{{ s.updates.none }}</p>
        <ul v-else class="plain body" data-test="available">
          <li v-if="report?.packages?.length"><span class="pill info">packages</span> {{ s.updates.packagesAvail(report.packages.length) }}<div class="mono faint"><span v-for="p in report.packages" :key="p.name" class="chip">{{ p.name }} {{ p.from }} &rarr; {{ p.to }}</span></div></li>
          <li v-if="report?.os"><span class="pill info">os</span> {{ s.updates.osAvail }} <span class="mono faint">{{ report.os.from }} &rarr; {{ report.os.to }}</span></li>
        </ul>
      </section>

      <section class="panel"><header><h2>{{ s.updates.history }}</h2></header>
        <p v-if="!l.data.value.history.length" class="empty">{{ s.updates.noHistory }}</p>
        <div v-else class="table-wrap"><table data-test="history">
          <thead><tr><th>{{ s.updates.time }}</th><th>{{ s.updates.kind }}</th><th class="hide-sm">{{ s.updates.snapshot }}</th><th>{{ s.updates.result }}</th></tr></thead>
          <tbody><tr v-for="h in l.data.value.history" :key="h.id">
            <td class="faint nowrap">{{ stamp(h.started) }}<div v-if="h.scheduled" class="faint">scheduled</div></td><td>{{ h.kind }}<div v-if="h.from" class="mono faint">{{ h.from }} &rarr; {{ h.to }}</div></td><td class="mono hide-sm">{{ h.snapshot || '-' }}</td>
            <td><span class="pill" :class="tone(h.result)">{{ s.updates.results[h.result] }}</span><div v-if="h.error" class="faint">{{ h.error }}</div><div v-if="h.note" class="faint">{{ h.note }}</div><div v-if="h.root_rolled_back" class="faint">{{ s.updates.rootRollbackNote }}</div></td>
          </tr></tbody></table></div>
      </section>

      <Modal :open="open" :title="s.updates.applyTitle(name)" wide @close="open = false">
        <div class="stack">
          <div class="row"><button class="btn" type="button" data-test="update-preview" @click="previewed = true">{{ s.updates.preview }}</button></div>
          <div v-if="previewed" data-test="update-plan" class="stack">
            <h3>{{ s.updates.plan }}</h3>
            <ol class="steps"><li v-for="st in plan" :key="st">{{ st }}</li></ol>
            <p class="muted">{{ s.updates.rootRollbackNote }}</p>
            <Callout v-if="report?.os" tone="warn">{{ s.updates.restartMaybe }}</Callout>
          </div>
          <p v-else class="muted">{{ s.updates.needPreview }}</p>
          <ErrorPanel v-if="error" :error="error" />
        </div>
        <template #footer><span v-if="!previewed" class="why-disabled">{{ s.updates.needPreview }}</span><button class="btn" type="button" @click="open = false">{{ s.app.cancel }}</button><button class="btn btn-primary" type="button" :disabled="!previewed || busy" data-test="update-go" @click="apply">{{ s.updates.apply }}</button></template>
      </Modal>
    </div>
  </LoadState>
</template>
