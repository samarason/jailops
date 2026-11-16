<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { useFormCheck } from '@jailops/shared/composables/form'
import { runOp } from '@jailops/shared/composables/ops'
import { isSystemLabel, labelKeyProblem, labelText, labelValueProblem, userLabels } from '@/lib/labels'
import Modal from '@jailops/shared/components/Modal.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import type { Jail } from '@jailops/shared/api/types'

// One label set on, or removed from, the selected jails: a merge patch per jail (`jailops label NAME KEY=VALUE` for
// each). The dialog lists the jails, so it is its own confirmation; a jail that refuses is named with the reason and
// the others keep their change.
const props = defineProps<{ open: boolean; jails: Jail[]; known: Map<string, Map<string, number>> }>()
const emit = defineEmits<{ close: []; done: [] }>()

const mode = ref<'add' | 'remove'>('add')
const key = ref('')
const value = ref('')
const drop = ref('')
const busy = ref(false)
const failed = ref<Array<{ jail: string; message: string }>>([])

const present = computed(() => [...new Set(props.jails.flatMap((j) => userLabels(j.metadata.labels).map(([k]) => k)))].sort())
const keys = computed(() => [...props.known.keys()].filter((k) => !isSystemLabel(k)).sort())
const values = computed(() => [...(props.known.get(key.value)?.keys() ?? [])].sort())
const check = useFormCheck((): Record<string, string> => (mode.value === 'add'
  ? { 'bl-key': isSystemLabel(key.value) ? s.labels.problems.system : s.labels.problems[labelKeyProblem(key.value)] ?? '', 'bl-value': s.labels.problems[labelValueProblem(value.value)] ?? '' }
  : { 'bl-drop': drop.value ? '' : s.labels.bulkNoKeys }))
const applyLabel = computed(() => (mode.value === 'add' ? s.labels.bulkApplyAdd(key.value ? labelText(key.value, value.value) : '', props.jails.length) : s.labels.bulkApplyRemove(drop.value, props.jails.length)))

watch(() => props.open, (o) => {
  if (!o) return
  failed.value = []
  mode.value = 'add'
  key.value = ''
  value.value = ''
  drop.value = present.value[0] ?? ''
  check.reset()
})

async function apply(): Promise<void> {
  busy.value = true
  failed.value = []
  const patch = mode.value === 'add' ? { [key.value]: value.value } : { [drop.value]: null }
  const targets = mode.value === 'add' ? props.jails : props.jails.filter((j) => drop.value in (j.metadata.labels ?? {}))
  // one toast for the whole change; it fails only when no jail took it
  await runOp(s.labels.bulkTitle(targets.length), async () => {
    const res = await Promise.allSettled(targets.map((j) => api.jails.patchLabels(j.metadata.name, patch)))
    res.forEach((r, i) => {
      if (r.status === 'rejected') failed.value.push({ jail: targets[i].metadata.name, message: r.reason instanceof ApiError ? r.reason.message : String(r.reason) })
    })
    if (targets.length && failed.value.length === targets.length) throw new ApiError({ code: 'invalid', message: s.labels.bulkFailed(failed.value.length) })
    return { kind: 'sync' as const, data: undefined }
  }).catch(() => undefined)
  busy.value = false
  emit('done')
  if (!failed.value.length) emit('close')
}
</script>

<template>
  <Modal :open="open" :title="s.labels.bulkTitle(jails.length)" @close="emit('close')">
    <form id="bulk-labels" class="stack" novalidate data-test="bulk-labels" @submit.prevent="check.submit(apply)">
      <fieldset class="bl-mode">
        <legend class="sr-only">{{ s.labels.bulk }}</legend>
        <label class="check"><input v-model="mode" type="radio" value="add" data-test="bl-add" /> {{ s.labels.bulkAdd }}</label>
        <label class="check"><input v-model="mode" type="radio" value="remove" data-test="bl-remove" /> {{ s.labels.bulkRemove }}</label>
      </fieldset>
      <div v-if="mode === 'add'" class="bl-row">
        <div class="field">
          <label for="bl-key">{{ s.labels.key }} <span class="req" aria-hidden="true">*</span></label>
          <input id="bl-key" v-model.trim="key" class="mono" type="text" list="bl-keys" autocomplete="off" spellcheck="false" autocapitalize="off" :placeholder="s.labels.keyHint" :aria-invalid="!!check.err('bl-key')" :aria-describedby="check.err('bl-key') ? 'bl-key-err' : undefined" data-test="bl-key" @blur="key && check.touch('bl-key')" />
          <span v-if="check.err('bl-key')" id="bl-key-err" class="field-error" role="alert">{{ check.err('bl-key') }}</span>
        </div>
        <div class="field">
          <label for="bl-value">{{ s.labels.value }}</label>
          <input id="bl-value" v-model="value" class="mono" type="text" list="bl-values" autocomplete="off" spellcheck="false" autocapitalize="off" :aria-invalid="!!check.err('bl-value')" :aria-describedby="check.err('bl-value') ? 'bl-value-err' : undefined" data-test="bl-value" @blur="value && check.touch('bl-value')" />
          <span v-if="check.err('bl-value')" id="bl-value-err" class="field-error" role="alert">{{ check.err('bl-value') }}</span>
        </div>
        <datalist id="bl-keys"><option v-for="k in keys" :key="k" :value="k" /></datalist>
        <datalist id="bl-values"><option v-for="v in values" :key="v" :value="v" /></datalist>
      </div>
      <div v-else class="field">
        <label for="bl-drop">{{ s.labels.bulkKeyPick }}</label>
        <select id="bl-drop" v-model="drop" class="mono" :aria-invalid="!!check.err('bl-drop')" :aria-describedby="check.err('bl-drop') ? 'bl-drop-err' : undefined" data-test="bl-drop">
          <option v-for="k in present" :key="k" :value="k">{{ k }}</option>
        </select>
        <span v-if="check.err('bl-drop') || !present.length" id="bl-drop-err" class="field-error" role="alert">{{ s.labels.bulkNoKeys }}</span>
      </div>
      <div>
        <div class="faint bl-jails-title">{{ s.labels.bulkJails }}</div>
        <ul class="bl-jails"><li v-for="j in jails" :key="j.metadata.name" class="mono">{{ j.metadata.name }}</li></ul>
      </div>
      <p class="hint faint bl-note">{{ s.labels.bulkNote }}</p>
      <Callout v-if="failed.length" tone="danger" data-test="bl-failed">
        <p>{{ s.labels.bulkFailed(failed.length) }}</p>
        <ul class="plain"><li v-for="f in failed" :key="f.jail"><span class="mono">{{ f.jail }}</span>: {{ f.message }}</li></ul>
      </Callout>
    </form>
    <template #footer>
      <span v-if="!check.ok.value && check.tried.value" class="why-disabled">{{ s.form.fixFirst(check.reason.value) }}</span>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button class="btn btn-primary" type="submit" form="bulk-labels" :disabled="busy" :aria-disabled="!check.ok.value" data-test="bl-apply">{{ applyLabel }}</button>
    </template>
  </Modal>
</template>

<style>
.bl-mode { border: 0; padding: 0; margin: 0; display: flex; gap: 16px; flex-wrap: wrap; }
.bl-mode .check { display: inline-flex; gap: 6px; align-items: center; }
.bl-row { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 0 12px; }
.bl-jails-title { font-size: 13px; margin-bottom: 4px; }
.bl-jails { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 4px 12px; max-height: 120px; overflow-y: auto; font-size: 13px; }
.bl-note { margin: 0; font-size: 12px; }
@media (max-width: 600px) { .bl-row { grid-template-columns: minmax(0, 1fr); } }
</style>
