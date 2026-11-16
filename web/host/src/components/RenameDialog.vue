<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import { useFormCheck } from '@jailops/shared/composables/form'
import { nameHint } from '@jailops/shared/lib/names'
import { sentence } from '@jailops/shared/lib/format'
import { capFirst, countsText, groupChanges, renameProblem, renameRule, type RenameKind } from '@/lib/rename'
import type { MutationResult, Rename, RenameResult } from '@jailops/shared/api/types'
import Modal from '@jailops/shared/components/Modal.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'

// Rename an object (extension rename), tier 2: the dialog names what the rename changes before it runs. Once the new
// name follows the kind's rule, a dry run (debounced) lists the changes, their counts and the server's warnings;
// Rename runs it as an operation with the If-Match the page read. A refusal of the dry run (a taken name, a running
// jail, a managed object) is shown in words in place of the plan.
const props = defineProps<{ open: boolean; kind: RenameKind; name: string; etag?: string; project?: string }>()
const emit = defineEmits<{ close: []; done: [to: string] }>()

/** How long the dialog waits after the last key before it asks for the plan. */
const DEBOUNCE_MS = 300

const to = ref('')
const plan = ref<RenameResult | null>(null)
const planFor = ref('')
const planning = ref(false)
const planError = ref<ApiError | null>(null)
const planErrorFor = ref('')
const busy = ref(false)
const error = ref<ApiError | null>(null)
let seq = 0
let timer: ReturnType<typeof setTimeout> | undefined

const word = computed(() => s.rename.kinds[props.kind] ?? props.kind)
const check = useFormCheck(() => ({ 'rn-name': renameProblem(props.kind, props.name, to.value, s.rename.same) }))
const fresh = computed(() => !!plan.value && planFor.value === to.value)
const refused = computed(() => !!planError.value && planErrorFor.value === to.value)
const groups = computed(() => groupChanges(plan.value?.changes))
const counts = computed(() => countsText(plan.value?.counts, s.rename.count, s.rename.and))
/** Why Rename does nothing yet, next to the button. */
const why = computed(() => {
  if (!to.value) return s.rename.needName
  if (check.reason.value) return `${s.rename.newName}: ${check.reason.value}`
  if (refused.value) return s.rename.planFailed
  return fresh.value ? '' : s.rename.needPlan
})

function send(dry: boolean, newName: string): Promise<MutationResult<RenameResult>> {
  const b: Rename = { new_name: newName, ...(dry ? { dry_run: true } : {}) }
  const n = props.name
  switch (props.kind) {
    case 'network': return api.rename.network(n, b, props.etag)
    case 'image': return api.rename.image(n, b, props.etag)
    case 'project': return api.rename.project(n, b, props.etag)
    case 'jail': return api.rename.jail(n, b, props.etag)
    case 'policy': return api.rename.policy(n, b, props.etag)
    case 'addressSet': return api.rename.addressSet(n, b, props.etag)
    case 'profile': return api.rename.profile(n, b, props.etag, props.project)
  }
}

async function dryRun(newName: string, mine: number): Promise<void> {
  planning.value = true
  try {
    const r = await send(true, newName)
    // a dry run answers at once; should a server answer with an operation, its metadata is the plan
    const res = r.kind === 'sync' ? r.data : ((await runOp(s.rename.title(word.value, props.name), () => Promise.resolve(r), { silent: true })).op?.metadata as RenameResult | undefined)
    if (mine !== seq) return
    plan.value = res ?? { kind: 'Network', from: props.name, to: newName, changes: [], counts: {} }
    planFor.value = newName
    planError.value = null
  } catch (e) {
    if (mine !== seq) return
    planError.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
    planErrorFor.value = newName
  } finally {
    if (mine === seq) planning.value = false
  }
}

watch(to, (v) => {
  const mine = ++seq
  clearTimeout(timer)
  planning.value = false
  if (renameProblem(props.kind, props.name, v, s.rename.same)) return
  planning.value = true
  timer = setTimeout(() => void dryRun(v, mine), DEBOUNCE_MS)
})

watch(() => props.open, (o) => {
  seq++
  clearTimeout(timer)
  if (!o) return
  to.value = ''
  plan.value = null
  planFor.value = ''
  planError.value = null
  planErrorFor.value = ''
  planning.value = false
  error.value = null
  check.reset()
}, { immediate: true })
onBeforeUnmount(() => clearTimeout(timer))

const go = () => check.submit(async () => {
  if (busy.value) return
  if (!fresh.value) {
    // the plan is not there yet (or the server refused the name): the reason sits next to the button
    if (refused.value) document.getElementById('rn-name')?.focus()
    return
  }
  const from = props.name
  const newName = to.value
  busy.value = true
  error.value = null
  try {
    await runOp(s.rename.op(word.value, from, newName), () => send(false, newName))
    emit('done', newName)
    emit('close')
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
})
</script>

<template>
  <Modal :open="open" :title="s.rename.title(word, name)" wide @close="emit('close')">
    <form id="rn" novalidate class="stack" data-test="rename-form" data-tier="2" @submit.prevent="go">
      <p class="muted" style="margin: 0">{{ s.rename.lead }}</p>
      <div class="field"><label for="rn-name">{{ s.rename.newName }} <span class="req" aria-hidden="true">*</span></label>
        <input id="rn-name" v-model="to" class="mono" type="text" autocomplete="off" spellcheck="false" :placeholder="name" required :aria-invalid="!!check.err('rn-name')" aria-describedby="rn-name-h rn-name-e" data-test="rename-name" @input="check.touch('rn-name')" />
        <span id="rn-name-h" class="hint">{{ nameHint(renameRule[kind]) }}</span>
        <span id="rn-name-e" class="field-error" role="alert">{{ check.err('rn-name') }}</span></div>
      <section class="rn-plan" :aria-label="s.rename.planLabel" aria-live="polite" :aria-busy="planning" data-test="rename-plan">
        <p v-if="!to || renameProblem(kind, name, to, s.rename.same)" class="muted">{{ s.rename.needName }}</p>
        <p v-else-if="planning && !fresh" class="muted" data-test="rename-planning">{{ s.rename.planning }}...</p>
        <ErrorPanel v-else-if="refused && planError" :error="planError" />
        <template v-else-if="plan">
          <p v-if="!fresh" class="muted">{{ s.rename.stale }}</p>
          <h3>{{ s.rename.planHeading }}</h3>
          <p data-test="rename-summary">{{ s.rename.summary(counts) }}</p>
          <div v-for="g in groups" :key="g.kind" :data-group="g.kind">
            <h4 class="rn-group">{{ s.rename.groups[g.kind] ?? sentence(g.kind) }}</h4>
            <ul class="rn-list">
              <li v-for="(c, i) in g.items" :key="i" data-test="rename-change"><span class="mono">{{ c.object }}</span><span v-if="c.detail" class="muted mono rn-detail">{{ c.detail }}</span></li>
            </ul>
          </div>
          <Callout v-if="plan.warnings?.length" tone="warn" data-test="rename-warnings">
            <strong>{{ s.rename.warnings }}</strong>
            <ul class="rn-warn"><li v-for="w in plan.warnings" :key="w">{{ capFirst(w) }}</li></ul>
          </Callout>
        </template>
      </section>
      <ErrorPanel v-if="error" :error="error" />
    </form>
    <template #footer>
      <span v-if="why" class="why-disabled" data-test="rename-why">{{ why }}</span>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button class="btn btn-primary" type="submit" form="rn" :disabled="busy" :aria-disabled="!!why" data-test="rename-go">{{ s.rename.go }}</button>
    </template>
  </Modal>
</template>

<style>
.rn-plan h3 { margin: 0 0 4px; font-size: 14px; }
.rn-plan > p { margin: 0 0 8px; }
.rn-group { margin: 8px 0 2px; font-size: 13px; font-weight: 600; }
.rn-list { margin: 0; padding-left: 18px; display: grid; gap: 2px; }
.rn-list li { overflow-wrap: anywhere; }
.rn-detail { margin-left: 8px; }
.rn-warn { margin: 4px 0 0; padding-left: 18px; }
</style>
