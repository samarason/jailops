<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import { can } from '@jailops/shared/composables/session'
import { bytes, stamp, snapshotLabel } from '@jailops/shared/lib/format'
import { bytesAtStake, canSubmit, needsConfirm, request } from '@/lib/rollback'
import type { JailSnapshot, RollbackScope } from '@jailops/shared/api/types'
import Modal from '@jailops/shared/components/Modal.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'

const props = defineProps<{ open: boolean; jail: string; snapshots: JailSnapshot[]; initial?: string }>()
const emit = defineEmits<{ close: []; done: [] }>()

const snapshot = ref('')
const scope = ref<RollbackScope>('root')
const typed = ref('')
const tried = ref(false)
const busy = ref(false)
const error = ref<ApiError | null>(null)

const sorted = computed(() => [...props.snapshots].sort((a, b) => (b.metadata.created_at ?? '').localeCompare(a.metadata.created_at ?? '')))
const chosen = computed(() => props.snapshots.find((x) => x.metadata.name === snapshot.value))
const stake = computed(() => bytesAtStake(scope.value, chosen.value))
const ok = computed(() => canSubmit(scope.value, typed.value, props.jail, snapshot.value))
const scopes = computed<RollbackScope[]>(() => (can('rollback_scopes') ? ['root', 'data', 'all'] : ['root']))
const scopeText: Record<RollbackScope, [string, string]> = {
  root: [s.rollback.root, s.rollback.rootText],
  data: [s.rollback.data, s.rollback.dataText],
  all: [s.rollback.all, s.rollback.allText],
}

watch(() => props.open, (o) => {
  if (!o) return
  snapshot.value = props.initial ?? sorted.value[0]?.metadata.name ?? ''
  scope.value = 'root'
  typed.value = ''
  tried.value = false
  error.value = null
}, { immediate: true })

// Data and both scopes are data loss: the jail name is typed (tier 3); a root rollback is this dialog alone (tier 2).
const why = computed(() => (!snapshot.value ? s.rollback.pickSnapshot : needsConfirm(scope.value) && typed.value !== props.jail ? s.rollback.typeFirst(props.jail) : ''))
async function go(): Promise<void> {
  tried.value = true
  if (!ok.value) {
    document.getElementById(snapshot.value ? 'rb-confirm' : 'rb-snap')?.focus()
    return
  }
  busy.value = true
  error.value = null
  try {
    await runOp(s.rollback.title(props.jail), () => api.jails.rollback(props.jail, request(scope.value, snapshot.value)))
    emit('done')
    emit('close')
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Modal :open="open" :title="s.rollback.title(jail)" @close="emit('close')">
    <form id="rb" @submit.prevent="go">
      <div class="field">
        <label for="rb-snap">{{ s.rollback.snapshot }}</label>
        <select id="rb-snap" v-model="snapshot">
          <option v-for="x in sorted" :key="x.metadata.name" :value="x.metadata.name">{{ snapshotLabel(x.metadata.name) === x.metadata.name ? `${x.metadata.name} - ${stamp(x.metadata.created_at)}` : snapshotLabel(x.metadata.name) }}</option>
        </select>
      </div>
      <fieldset class="field scopes">
        <legend class="label">{{ s.rollback.scope }}</legend>
        <label v-for="sc in scopes" :key="sc" class="scope" :class="{ sel: scope === sc, hot: needsConfirm(sc) }">
          <input v-model="scope" type="radio" name="scope" :value="sc" />
          <span><strong>{{ scopeText[sc][0] }}</strong><br /><span class="muted">{{ scopeText[sc][1] }}</span></span>
        </label>
      </fieldset>
      <Callout v-if="needsConfirm(scope)" tone="danger">
        <p>
          <strong>{{ s.rollback.willLose }}: <span data-test="stake" class="mono">{{ bytes(stake) }}</span></strong>
        </p>
        <p v-if="!stake" class="muted">{{ s.rollback.willLoseNone }}</p>
        <p>{{ s.rollback.expert }}</p>
        <div class="field" style="margin: 8px 0 0">
          <label for="rb-confirm">{{ s.rollback.confirmLabel(jail) }} <span class="req" aria-hidden="true">*</span></label>
          <input id="rb-confirm" v-model="typed" class="mono" type="text" autocomplete="off" spellcheck="false" data-test="rollback-type" :class="{ invalid: (typed || tried) && typed !== jail }" :aria-invalid="(!!typed || tried) && typed !== jail" :aria-describedby="(typed || tried) && typed !== jail ? 'rb-confirm-err' : undefined" />
          <span v-if="(typed || tried) && typed !== jail" id="rb-confirm-err" class="err" role="alert">{{ s.rollback.mismatch }}</span>
        </div>
      </Callout>
      <ErrorPanel v-if="error" :error="error" style="margin-top: 12px" />
    </form>
    <template #footer>
      <span v-if="why" class="why-disabled" data-test="rollback-why">{{ why }}</span>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button class="btn" :class="needsConfirm(scope) ? 'btn-danger' : 'btn-primary'" type="submit" form="rb" :disabled="busy" :aria-disabled="!ok" data-test="rollback-go">{{ s.rollback.confirm }}</button>
    </template>
  </Modal>
</template>

<style>
.scopes { border: 0; padding: 0; margin: 0 0 12px; }
.scope { display: flex; gap: 10px; padding: 8px; border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 6px; cursor: pointer; }
.scope.sel { border-color: var(--border-strong); background: var(--surface-2); }
.scope.hot.sel { border-color: var(--danger); }
</style>
