<script setup lang="ts">
import { computed, nextTick, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import Modal from '@jailops/shared/components/Modal.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import { blankSink, checkSink, formOf, plaintextRemote, sinkBody, withSink, FACILITIES } from '@/lib/logforward'
import type { LogSink } from '@jailops/shared/api/types'

// Adds a sink, or edits one (sink set): the whole list is sent back with If-Match, so an edit made elsewhere
// meanwhile is a conflict instead of being overwritten.
const props = defineProps<{ open: boolean; sink: LogSink | null; sinks: LogSink[]; etag: string }>()
const emit = defineEmits<{ close: []; done: [] }>()
const f = reactive(blankSink())
const busy = ref(false)
const error = ref<ApiError | null>(null)
const submitted = ref(false)
const taken = computed(() => props.sinks.map((k) => k.name).filter((n) => n !== props.sink?.name))
const problems = computed(() => checkSink(f, taken.value))
const msg = (k: string): string => {
  if (submitted.value && ((k === 'name' && !f.name) || (k === 'to' && !f.to))) return s.forward.problems.required
  const p = problems.value[k]
  return p ? s.forward.problems[p] ?? p : ''
}
const ready = computed(() => !!f.name && !!f.to && !Object.keys(problems.value).length)
// the first problem with the name of its field, for the text next to Save
const firstMsg = computed(() => {
  const k = ['name', 'to', ...Object.keys(problems.value)].find((x) => msg(x))
  if (!k) return ''
  const label = (s.forward as Record<string, unknown>)[k]
  return `${typeof label === 'string' ? label : k}: ${msg(k)}`
})
const clear = computed(() => plaintextRemote(f.type, f.to))

watch(() => props.open, (o) => {
  if (!o) return
  Object.assign(f, props.sink ? formOf(props.sink) : blankSink())
  submitted.value = false
  error.value = null
})

async function save(): Promise<void> {
  submitted.value = true
  if (!ready.value) {
    // the first field with a message gets the focus
    await nextTick()
    document.querySelector<HTMLElement>('#lsf [aria-invalid="true"]')?.focus()
    return
  }
  busy.value = true
  error.value = null
  try {
    await api.logs.putForward({ sinks: withSink(props.sinks, sinkBody(f), props.sink?.name) }, props.etag)
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
  <Modal :open="open" :title="sink ? s.forward.editTitle(sink.name) : s.forward.addTitle" wide @close="emit('close')">
    <form id="lsf" novalidate @submit.prevent="save">
      <div class="form-2">
        <div class="field">
          <label for="lsf-name">{{ s.forward.name }} <span class="req" aria-hidden="true">*</span></label>
          <input id="lsf-name" v-model="f.name" class="mono" type="text" autocomplete="off" required :aria-invalid="!!msg('name')" aria-describedby="lsf-name-h lsf-name-e" />
          <span id="lsf-name-h" class="hint">{{ s.forward.nameHint }}</span>
          <span id="lsf-name-e" class="field-error" role="alert">{{ msg('name') }}</span>
        </div>
        <div class="field">
          <label for="lsf-type">{{ s.forward.type }}</label>
          <select id="lsf-type" v-model="f.type" data-test="lsf-type"><option value="syslog">{{ s.forward.syslog }}</option><option value="webhook">{{ s.forward.webhook }}</option></select>
        </div>
      </div>
      <div class="field">
        <label for="lsf-to">{{ s.forward.to }} <span class="req" aria-hidden="true">*</span></label>
        <input id="lsf-to" v-model="f.to" class="mono" type="text" autocomplete="off" required :placeholder="f.type === 'syslog' ? 'tls://logs.example.com:6514' : 'https://hooks.example.com/logs'" :aria-invalid="!!msg('to')" aria-describedby="lsf-to-h lsf-to-e" />
        <span id="lsf-to-h" class="hint">{{ f.type === 'syslog' ? s.forward.toHintSyslog : s.forward.toHintWebhook }}</span>
        <span id="lsf-to-e" class="field-error" role="alert">{{ msg('to') }}</span>
      </div>
      <Callout v-if="clear" tone="warn" data-test="lsf-plaintext">{{ s.forward.plaintext }}</Callout>
      <div class="form-2">
        <div v-if="f.type === 'syslog'" class="field">
          <label for="lsf-fac">{{ s.forward.facility }}</label>
          <select id="lsf-fac" v-model="f.facility"><option v-for="x in FACILITIES" :key="x" :value="x">{{ x }}</option></select>
        </div>
        <div class="field">
          <label for="lsf-queue">{{ s.forward.queue }}</label>
          <input id="lsf-queue" v-model="f.queue" class="mono" type="text" inputmode="numeric" placeholder="10000" autocomplete="off" :aria-invalid="!!msg('queue')" aria-describedby="lsf-queue-h lsf-queue-e" />
          <span id="lsf-queue-h" class="hint">{{ s.forward.queueHint }}</span>
          <span id="lsf-queue-e" class="field-error" role="alert">{{ msg('queue') }}</span>
        </div>
      </div>
      <div class="field">
        <label for="lsf-ca">{{ s.forward.caFile }}</label>
        <input id="lsf-ca" v-model="f.caFile" class="mono" type="text" autocomplete="off" placeholder="/usr/local/etc/jailops/sinks/logs-ca.pem" :aria-invalid="!!msg('caFile')" aria-describedby="lsf-ca-h lsf-ca-e" />
        <span id="lsf-ca-h" class="hint">{{ s.forward.caHint }}</span>
        <span id="lsf-ca-e" class="field-error" role="alert">{{ msg('caFile') }}</span>
      </div>
      <div v-if="f.type === 'webhook'" class="field">
        <label for="lsf-token">{{ s.forward.tokenFile }}</label>
        <input id="lsf-token" v-model="f.tokenFile" class="mono" type="text" autocomplete="off" placeholder="/usr/local/etc/jailops/sinks/hook.token" :aria-invalid="!!msg('tokenFile')" aria-describedby="lsf-token-h lsf-token-e" />
        <span id="lsf-token-h" class="hint">{{ s.forward.tokenHint }}</span>
        <span id="lsf-token-e" class="field-error" role="alert">{{ msg('tokenFile') }}</span>
      </div>
      <fieldset class="lsf-set">
        <legend>{{ s.forward.sourcesTitle }}</legend>
        <label class="check"><input v-model="f.jailLogs" type="checkbox" data-test="lsf-jail-logs" />{{ s.forward.jailLogs }}</label>
        <label class="check"><input v-model="f.appLogs" type="checkbox" :disabled="!f.jailLogs" />{{ s.forward.appLogs }}</label>
        <label class="check"><input v-model="f.audit" type="checkbox" data-test="lsf-audit" />{{ s.forward.audit }}</label>
        <span class="field-error" role="alert">{{ msg('audit') }}</span>
        <template v-if="f.jailLogs">
          <div v-for="[k, label, hint] in ([['projects', s.forward.projects, s.forward.listHint], ['jails', s.forward.jails, s.forward.listHint], ['labels', s.forward.labels, s.forward.labelsHint], ['excludeJails', s.forward.excludeJails, s.forward.listHint], ['excludeLabels', s.forward.excludeLabels, s.forward.labelsHint], ['files', s.forward.files, s.forward.filesHint]] as const)" :key="k" class="field">
            <label :for="`lsf-${k}`">{{ label }}</label>
            <input :id="`lsf-${k}`" v-model="f[k]" class="mono" type="text" autocomplete="off" :aria-invalid="!!msg(k)" :aria-describedby="`lsf-${k}-h lsf-${k}-e`" />
            <span :id="`lsf-${k}-h`" class="hint">{{ hint }}</span>
            <span :id="`lsf-${k}-e`" class="field-error" role="alert">{{ msg(k) }}</span>
          </div>
        </template>
      </fieldset>
      <ErrorPanel v-if="error" :error="error" style="margin-top: 12px" />
    </form>
    <template #footer>
      <span v-if="submitted && firstMsg" class="why-disabled" data-test="lsf-why">{{ s.form.fixFirst(firstMsg) }}</span>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button class="btn btn-primary" type="submit" form="lsf" :disabled="busy" data-test="lsf-save">{{ s.forward.save }}</button>
    </template>
  </Modal>
</template>

<style scoped>
.lsf-set { border: 1px solid var(--border); border-radius: var(--radius); padding: 8px 12px; margin: 0 0 12px; display: grid; gap: 4px; }
.lsf-set legend { padding: 0 4px; color: var(--text-2); }
</style>
