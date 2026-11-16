<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { useFormCheck } from '@jailops/shared/composables/form'
import { canEditLabels } from '@/composables/shell'
import { isSystemLabel, knownLabels, labelKeyProblem, labelText, labelValueProblem, MAX_LABELS, userLabels, withLabel, type Labels } from '@/lib/labels'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import LabelChips from '@/components/LabelChips.vue'
import type { Jail } from '@jailops/shared/api/types'

// The messages of the two fields show after a submit, not when a field is left: a message that appeared on leaving
// the key would move the Add button away from under a finger that is tapping it on a phone.
// The labels of a jail under its name: chips that filter the jail list, and for an administrator of the project an
// editor that adds and removes one label at a time with a merge patch (a null removes a key, other keys stay as they
// are, so two people editing different keys do not overwrite each other).
const props = defineProps<{ jail: Jail }>()
const emit = defineEmits<{ saved: [] }>()
const router = useRouter()

const labels = ref<Labels>({ ...(props.jail.metadata.labels ?? {}) })
watch(() => props.jail.metadata.labels, (l) => (labels.value = { ...(l ?? {}) }))
const mine = computed(() => userLabels(labels.value))
const system = computed(() => Object.entries(labels.value).filter(([k]) => isSystemLabel(k)).sort(([a], [b]) => a.localeCompare(b)))
// the row leaves out the definition hash: a long value nobody reads there
const systemShown = computed(() => system.value.filter(([k]) => !k.endsWith('.hash')))
const editable = computed(() => canEditLabels(props.jail.metadata.project))

const editing = ref(false)
const key = ref('')
const value = ref('')
const busy = ref(false)
const error = ref<ApiError | null>(null)
const status = ref('')
const keyEl = ref<HTMLInputElement | null>(null)
const known = ref(new Map<string, Map<string, number>>())

const check = useFormCheck(() => ({
  'lbl-key': isSystemLabel(key.value) ? s.labels.problems.system : s.labels.problems[labelKeyProblem(key.value)] ?? '',
  'lbl-value': s.labels.problems[labelValueProblem(value.value)] ?? (!(key.value in labels.value) && Object.keys(labels.value).length >= MAX_LABELS ? s.labels.problems.tooMany : ''),
}))
const keys = computed(() => [...known.value.keys()].filter((k) => !isSystemLabel(k)).sort())
const values = computed(() => [...(known.value.get(key.value)?.keys() ?? [])].sort())

async function open(): Promise<void> {
  editing.value = true
  error.value = null
  status.value = ''
  check.reset()
  await nextTick()
  keyEl.value?.focus()
  // the keys and values the project already uses, for the suggestions
  api.jails.list(props.jail.metadata.project).then((l) => (known.value = knownLabels(l))).catch(() => undefined)
}

async function patch(p: Record<string, string | null>, done: string): Promise<boolean> {
  busy.value = true
  error.value = null
  status.value = ''
  try {
    const r = await api.jails.patchLabels(props.jail.metadata.name, p)
    const j = r.kind === 'sync' ? (r.data as Jail | undefined) : undefined
    if (j?.metadata) labels.value = { ...(j.metadata.labels ?? {}) }
    status.value = done
    emit('saved')
    return true
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
    return false
  } finally {
    busy.value = false
  }
}

async function add(): Promise<void> {
  const k = key.value
  if (await patch({ [k]: value.value }, `${s.labels.saved}: ${labelText(k, value.value)}`)) {
    key.value = ''
    value.value = ''
    check.reset()
    keyEl.value?.focus()
  }
}
async function remove(k: string): Promise<void> {
  const text = labelText(k, labels.value[k] ?? '')
  if (await patch({ [k]: null }, `${s.labels.saved}: ${s.labels.remove(text)}`)) await nextTick(() => keyEl.value?.focus())
}
function filter(k: string, v: string): void {
  void router.push({ path: '/jails', query: { q: withLabel('', k, v) } })
}
</script>

<template>
  <section class="jlabels" :aria-label="s.labels.title" data-test="jail-labels">
    <div class="jlabels-row">
      <span class="faint jlabels-title"><Icon name="tag" />{{ s.labels.title }}</span>
      <LabelChips v-if="mine.length && !editing" :labels="labels" :max="12" pick @pick="filter" />
      <span v-else-if="!editing" class="faint">{{ s.labels.none }}</span>
      <span v-for="[k, v] in systemShown" v-show="!editing" :key="k" class="lchip lsys" :title="s.labels.system"><span class="lk">{{ k }}</span><span class="lv">{{ v }}</span></span>
      <button v-if="editable && !editing" class="btn btn-sm btn-ghost" type="button" data-test="labels-edit" @click="open"><Icon name="tag" />{{ s.labels.edit }}</button>
    </div>
    <div v-if="editing" class="panel jlabels-edit" data-test="labels-editor">
      <ul v-if="mine.length" class="jlabels-list" :aria-label="s.labels.title">
        <li v-for="[k, v] in mine" :key="k" class="lchip ledit" :data-label="labelText(k, v)">
          <span class="lk">{{ k }}</span><span class="lv" :title="v">{{ v }}</span>
          <button class="lx" type="button" :aria-label="s.labels.remove(labelText(k, v))" :disabled="busy" :data-remove="k" @click="remove(k)"><Icon name="x" /></button>
        </li>
      </ul>
      <p v-else class="faint jlabels-none">{{ s.labels.none }}</p>
      <p v-if="system.length" class="faint jlabels-sys">{{ s.labels.systemHint }} <span v-for="[k, v] in system" :key="k" class="mono">{{ labelText(k, v) }} </span></p>
      <form class="jlabels-form" novalidate @submit.prevent="check.submit(add)">
        <div class="field">
          <label for="lbl-key">{{ s.labels.key }} <span class="req" aria-hidden="true">*</span></label>
          <input id="lbl-key" ref="keyEl" v-model.trim="key" class="mono" type="text" list="lbl-keys" autocomplete="off" spellcheck="false" autocapitalize="off" :placeholder="s.labels.keyHint" :aria-invalid="!!check.err('lbl-key')" :aria-describedby="check.err('lbl-key') ? 'lbl-key-err' : undefined" data-test="label-key" />
          <span v-if="check.err('lbl-key')" id="lbl-key-err" class="field-error" role="alert">{{ check.err('lbl-key') }}</span>
        </div>
        <span class="jlabels-eq mono" aria-hidden="true">=</span>
        <div class="field">
          <label for="lbl-value">{{ s.labels.value }}</label>
          <input id="lbl-value" v-model="value" class="mono" type="text" list="lbl-values" autocomplete="off" spellcheck="false" autocapitalize="off" :aria-invalid="!!check.err('lbl-value')" :aria-describedby="check.err('lbl-value') ? 'lbl-value-err' : undefined" data-test="label-value" />
          <span v-if="check.err('lbl-value')" id="lbl-value-err" class="field-error" role="alert">{{ check.err('lbl-value') }}</span>
        </div>
        <div class="jlabels-go">
          <button class="btn btn-primary" type="submit" :disabled="busy" :aria-disabled="!check.ok.value" data-test="label-add"><Icon name="plus" />{{ s.labels.add }}</button>
          <button class="btn" type="button" data-test="labels-done" @click="editing = false">{{ s.labels.done }}</button>
        </div>
        <datalist id="lbl-keys"><option v-for="k in keys" :key="k" :value="k" /></datalist>
        <datalist id="lbl-values"><option v-for="v in values" :key="v" :value="v" /></datalist>
      </form>
      <ErrorPanel v-if="error" :error="error" />
      <span class="sr-only" role="status" data-test="labels-status">{{ status }}</span>
    </div>
  </section>
</template>

<style>
.jlabels { display: grid; gap: 8px; }
.jlabels-row { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; min-height: 28px; }
.jlabels-row > .lchips { flex: 0 1 auto; }
.jlabels-title { display: inline-flex; align-items: center; gap: 4px; font-size: 13px; margin-right: 2px; }
.jlabels-title .icon { width: 14px; height: 14px; }
.lchip.lsys { border-style: dashed; }
.lchip.lsys .lv { background: transparent; color: var(--text-2); }
.jlabels-edit { padding: 12px; display: grid; gap: 10px; }
.jlabels-list { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 6px; }
.lchip.ledit { max-width: 100%; }
.lchip .lx { display: inline-flex; align-items: center; justify-content: center; min-width: 26px; padding: 0 4px; border: 0; border-left: 1px solid var(--border); background: var(--surface); color: var(--text-2); cursor: pointer; }
.lchip .lx:hover:not(:disabled) { color: var(--danger); background: var(--danger-bg); }
.lchip .lx:focus-visible { outline: 2px solid var(--focus); outline-offset: -2px; }
.lchip .lx .icon { width: 14px; height: 14px; }
.jlabels-none, .jlabels-sys { margin: 0; font-size: 13px; }
.jlabels-form { display: grid; grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr) auto; gap: 0 8px; align-items: start; }
.jlabels-form .field { margin-bottom: 0; }
.jlabels-eq { padding-top: 30px; color: var(--text-3); }
.jlabels-go { display: flex; gap: 6px; padding-top: 22px; }
@media (max-width: 700px) {
  .jlabels-form { grid-template-columns: minmax(0, 1fr); gap: 8px; }
  .jlabels-eq { display: none; }
  .jlabels-go { padding-top: 0; }
}
</style>
