<script setup lang="ts">
import { clone } from '@/lib/clone'
import { computed, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import { lifecycle } from '@/composables/jailActions'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import { rowsFor, grouped, getValue, setValue, validate, diff, configChange, helpText, type Row } from '@/lib/configKeys'
import type { ConfigResult } from '@/types'
import type { Jail } from '@jailops/shared/api/types'

const props = defineProps<{ jail: Jail; sources: Record<string, { value: string; source: string }> }>()
const emit = defineEmits<{ saved: [] }>()

const draft = ref<Jail['spec']>(clone(props.jail.spec))
const original = computed(() => props.jail.spec)
const error = ref<ApiError | null>(null)
const busy = ref(false)
const needRestart = ref<string[]>([])
const showSources = ref(false)

watch(() => props.jail, (j) => { draft.value = clone(j.spec) })

const msgs = {
  int: s.config.invalidInt, size: s.config.invalidSize, rate: s.config.invalidRate, mac: s.config.invalidMac, address: s.config.invalidAddress,
  listen: s.config.invalidListen, bool: s.config.invalidBool, name: s.config.invalidPattern, enum: s.config.invalidEnum,
}
const rows = computed(() => rowsFor(draft.value).filter((r) => r.key.type !== 'device'))
const groups = computed(() => grouped(rows.value))
const values = ref<Record<string, string>>({})
watch(draft, () => { /* keep values in sync when the draft is replaced */ }, { deep: false })
const read = (r: Row) => (r.name in values.value ? values.value[r.name] : getValue(draft.value, r.key, r.dev))
const errors = computed(() => {
  const e: Record<string, string> = {}
  for (const r of rows.value) {
    const m = validate(r.key, read(r), msgs)
    if (m) e[r.name] = m
  }
  return e
})
function edit(r: Row, v: string): void {
  values.value = { ...values.value, [r.name]: v }
  if (!validate(r.key, v, msgs)) draft.value = setValue(draft.value, r.key, r.dev, v)
}
const delta = computed(() => diff(original.value, draft.value))
const dirty = computed(() => delta.value.changed.length > 0)
const fixed = (r: Row) => r.key.name === 'image'
function revert(): void {
  draft.value = clone(original.value)
  values.value = {}
  error.value = null
}

async function save(): Promise<void> {
  if (Object.keys(errors.value).length) {
    error.value = new ApiError({ code: 'invalid' as never, message: s.config.fixErrors })
    return
  }
  busy.value = true
  error.value = null
  try {
    const r = await runOp<ConfigResult>(s.config.savingTitle(props.jail.metadata.name), () => api.jailConfig.post(props.jail.metadata.name, configChange(original.value, draft.value)))
    // The server says what needs a restart; the jail itself was not restarted.
    needRestart.value = ((r.op?.metadata ?? r.data) as ConfigResult | undefined)?.restart_required ?? []
    values.value = {}
    emit('saved')
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
const restarting = ref(false)
async function restart(): Promise<void> {
  restarting.value = true
  try {
    await lifecycle(props.jail.metadata.name, 'restart')
    needRestart.value = []
  } catch (e) {
    error.value = e instanceof ApiError ? e : null
  } finally {
    restarting.value = false
  }
}
</script>

<template>
  <div class="stack" data-test="config-tab">
    <p class="muted">{{ s.config.lead }} <span class="faint">{{ s.config.registry(rows.length, s.config.srcServer) }}</span></p>

    <Callout v-if="needRestart.length" tone="warn" data-test="restart-banner">
      <p><strong>{{ s.config.notRestarted }}</strong> {{ s.config.restartText(needRestart.join(', ')) }}</p>
      <div class="row"><button class="btn btn-primary btn-sm" type="button" :disabled="restarting" data-test="restart-now" @click="restart">{{ s.config.restart }}</button><button class="btn btn-sm" type="button" @click="needRestart = []">{{ s.config.restartLater }}</button></div>
    </Callout>

    <div class="row" style="justify-content: space-between">
      <label class="check"><input v-model="showSources" type="checkbox" />{{ s.config.expanded }}</label>
      <div class="row">
        <span v-if="dirty" class="pill warn" data-test="unsaved">{{ s.config.unsaved(delta.changed.length) }}</span>
        <button class="btn" type="button" :disabled="!dirty" @click="revert">{{ s.config.revert }}</button>
        <button class="btn btn-primary" type="button" :disabled="!dirty || busy" data-test="config-save" @click="save">{{ s.config.save }}</button>
      </div>
    </div>
    <ErrorPanel v-if="error" :error="error" />

    <section v-for="[g, list] in groups" :key="g" class="panel" :data-group="g">
      <header><h2>{{ s.config.groups[g] ?? g }}</h2></header>
      <div class="table-wrap"><table>
        <thead class="sr-only"><tr><th>{{ s.profiles.key }}</th><th>{{ s.profiles.value }}</th></tr></thead>
        <tbody>
          <tr v-for="r in list" :key="r.name" :data-key="r.name" :class="{ drift: delta.changed.includes(r.name) }">
            <td style="width: 34%">
              <label :for="'k-' + r.name" class="mono">{{ r.name }}</label>
              <div class="row" style="gap: 4px; margin-top: 2px">
                <span v-if="r.key.restart_required" class="badge warn" data-test="restart-badge">{{ s.config.restartBadge }}</span>
                <span v-if="r.key.admin" class="badge info">admin</span>
                <span v-if="showSources && sources[r.name]" class="faint" data-test="source">{{ s.config.source }}: {{ sources[r.name].source === 'jail' ? s.devices.fromJail : s.devices.fromProfile(sources[r.name].source) }}</span>
              </div>
            </td>
            <td>
              <select v-if="r.key.type === 'enum'" :id="'k-' + r.name" :value="read(r)" :class="{ invalid: errors[r.name] }" @change="edit(r, ($event.target as HTMLSelectElement).value)">
                <option value="">-</option><option v-for="o in r.key.values" :key="o" :value="o">{{ o }}</option>
              </select>
              <select v-else-if="r.key.type === 'bool'" :id="'k-' + r.name" :value="read(r)" @change="edit(r, ($event.target as HTMLSelectElement).value)">
                <option value="">-</option><option value="true">true</option><option value="false">false</option>
              </select>
              <input v-else :id="'k-' + r.name" class="mono" :class="{ invalid: errors[r.name] }" type="text" :value="read(r)" :disabled="fixed(r)" :placeholder="r.key.example" :aria-invalid="!!errors[r.name]" @input="edit(r, ($event.target as HTMLInputElement).value)" />
              <span v-if="errors[r.name]" class="err" data-test="config-error">{{ errors[r.name] }}</span>
              <span class="hint faint">{{ r.key.name === 'shell' ? s.config.shellHint : r.key.name === 'prompt' ? s.config.promptHint : helpText(r.key.description) }}</span>
            </td>
          </tr>
        </tbody>
      </table></div>
    </section>
  </div>
</template>
