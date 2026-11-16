<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { allowBody, defaultDb, validateAllow, type AllowForm, type SourceKind } from '@/lib/access'
import Modal from '@jailops/shared/components/Modal.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import CopyField from '@jailops/shared/components/CopyField.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import type { AppAccess, AppAllowResult } from '@jailops/shared/api/types'

// Allow a source to reach an installed app. The connection string of a new role lives in this component's state
// only, from the answer until the dialog closes: nothing stores it.
const props = defineProps<{ open: boolean; access: AppAccess }>()
const emit = defineEmits<{ close: []; done: [] }>()

const f = reactive<AllowForm>({ kind: 'jail', jail: '', set: '', cidr: '', ports: '', db: '' })
const jails = ref<string[]>([])
const sets = ref<string[]>([])
const filter = ref('')
const touched = ref(false)
const busy = ref(false)
const error = ref<ApiError | null>(null)
const preview = ref<AppAllowResult | null>(null)
const result = ref<AppAllowResult | null>(null)

const withDb = computed(() => !!props.access.type)
const issues = computed(() => validateAllow(f, withDb.value))
const valid = computed(() => !Object.keys(issues.value).length)
const shown = (k: 'source' | 'ports' | 'db') => {
  const i = issues.value[k]
  return i && (touched.value || k !== 'source' || (f.kind === 'cidr' && !!f.cidr)) ? s.appAccess.issue[i] : ''
}
const matching = computed(() => jails.value.filter((n) => n.includes(filter.value.trim().toLowerCase())))
const dbDefault = computed(() => (f.kind === 'jail' && f.jail ? defaultDb(f.jail) : ''))
const kinds: Array<[SourceKind, string]> = [['jail', s.appAccess.kindJail], ['set', s.appAccess.kindSet], ['cidr', s.appAccess.kindCidr], ['host', s.appAccess.kindHost]]

watch(() => props.open, (o) => {
  // every opening starts empty: a connection string never outlives the dialog
  Object.assign(f, { kind: 'jail', jail: '', set: '', cidr: '', ports: '', db: '' })
  filter.value = ''
  touched.value = false
  error.value = null
  preview.value = null
  result.value = null
  if (!o) return
  api.jails.list().then((l) => (jails.value = l.map((j) => j.metadata.name).filter((n) => n !== props.access.jail).sort())).catch(() => (jails.value = []))
  api.firewall.addressSets().then((l) => (sets.value = l.map((x) => x.metadata.name).sort())).catch(() => (sets.value = []))
}, { immediate: true })
watch(() => [f.kind, f.jail, f.set, f.cidr, f.ports, f.db], () => (preview.value = null))

async function send(dry: boolean): Promise<void> {
  touched.value = true
  if (!valid.value) return
  busy.value = true
  error.value = null
  try {
    const r = await api.appAccess.allow(props.access.jail, allowBody(f, withDb.value, dry))
    const res = r.kind === 'sync' ? (r.data as AppAllowResult) : null
    if (dry) preview.value = res
    else {
      result.value = res
      emit('done')
    }
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Modal :open="open" :title="s.appAccess.dialogTitle(access.jail)" wide @close="emit('close')">
    <div class="stack" data-test="allow-dialog">
      <template v-if="!result">
        <form id="allow-form" class="stack" novalidate @submit.prevent="send(false)">
          <fieldset class="acc-kinds">
            <legend>{{ s.appAccess.sourceKind }}</legend>
            <label v-for="[k, label] in kinds" :key="k" class="acc-kind"><input v-model="f.kind" type="radio" name="acc-kind" :value="k" :data-test="`kind-${k}`" /> {{ label }}</label>
          </fieldset>
          <div v-if="f.kind === 'jail'" class="field">
            <label for="acc-filter">{{ s.appAccess.findJail }}</label>
            <input id="acc-filter" v-model="filter" type="search" autocomplete="off" data-test="allow-filter" />
            <p v-if="!matching.length" class="faint">{{ s.appAccess.noJails }}</p>
            <div v-else class="acc-list" role="radiogroup" :aria-label="s.appAccess.kindJail" data-test="allow-jails">
              <label v-for="n in matching" :key="n" class="acc-pick" :class="{ on: f.jail === n }"><input v-model="f.jail" type="radio" name="acc-jail" :value="n" /><span class="mono">jail:{{ n }}</span></label>
            </div>
            <span v-if="shown('source')" class="field-error" role="alert">{{ shown('source') }}</span>
          </div>
          <div v-else-if="f.kind === 'set'" class="field">
            <label for="acc-set">{{ s.appAccess.kindSet }}</label>
            <p v-if="!sets.length" class="faint">{{ s.appAccess.noSets }}</p>
            <select v-else id="acc-set" v-model="f.set" data-test="allow-set">
              <option value="">-</option>
              <option v-for="n in sets" :key="n" :value="n">set:{{ n }}</option>
            </select>
            <span v-if="shown('source')" class="field-error" role="alert">{{ shown('source') }}</span>
          </div>
          <div v-else-if="f.kind === 'cidr'" class="field">
            <label for="acc-cidr">{{ s.appAccess.cidr }}</label>
            <input id="acc-cidr" v-model.trim="f.cidr" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!shown('source')" :aria-describedby="shown('source') ? 'acc-cidr-err' : 'acc-cidr-hint'" data-test="allow-cidr" />
            <span v-if="shown('source') && f.cidr" id="acc-cidr-err" class="field-error" role="alert">{{ shown('source') }}</span>
            <span v-else id="acc-cidr-hint" class="hint">{{ s.appAccess.cidrHint }}</span>
          </div>
          <p v-else class="muted">{{ s.appAccess.hostText }}</p>
          <div class="acc-row">
            <div class="field">
              <label for="acc-ports">{{ s.appAccess.portsField }}</label>
              <input id="acc-ports" v-model.trim="f.ports" class="mono" type="text" autocomplete="off" :placeholder="access.ports.join(', ')" :aria-invalid="!!shown('ports')" :aria-describedby="shown('ports') ? 'acc-ports-err' : 'acc-ports-hint'" data-test="allow-ports" />
              <span v-if="shown('ports')" id="acc-ports-err" class="field-error" role="alert">{{ shown('ports') }}</span>
              <span v-else id="acc-ports-hint" class="hint">{{ s.appAccess.portsHint(access.ports.join(', ')) }}</span>
            </div>
            <div v-if="withDb" class="field">
              <label for="acc-db">{{ s.appAccess.db }}</label>
              <input id="acc-db" v-model.trim="f.db" class="mono" type="text" autocomplete="off" spellcheck="false" :placeholder="dbDefault" :aria-invalid="!!shown('db')" :aria-describedby="shown('db') ? 'acc-db-err' : 'acc-db-hint'" data-test="allow-db" />
              <span v-if="shown('db') && (touched || f.db)" id="acc-db-err" class="field-error" role="alert">{{ shown('db') }}</span>
              <span v-else id="acc-db-hint" class="hint">{{ s.appAccess.dbHint(dbDefault) }}</span>
            </div>
          </div>
        </form>
        <section v-if="preview" class="acc-preview" data-test="allow-preview" aria-labelledby="acc-prev-h">
          <h3 id="acc-prev-h">{{ s.appAccess.previewTitle }}</h3>
          <dl class="kv">
            <dt>{{ s.appAccess.typed }}</dt><dd><div v-for="r in preview.grant.rules" :key="r" class="mono">{{ r }}</div></dd>
            <template v-if="preview.grant.hba?.length"><dt>{{ s.appAccess.hba }}</dt><dd><div v-for="r in preview.grant.hba" :key="r" class="mono">{{ r }}</div></dd></template>
            <template v-if="preview.sql?.length"><dt>{{ s.appAccess.sql }}</dt><dd><div v-for="r in preview.sql" :key="r" class="mono">{{ r }}</div></dd></template>
          </dl>
          <ul class="plain muted"><li v-for="st in preview.steps" :key="st">{{ st }}</li></ul>
        </section>
        <ErrorPanel v-if="error" :error="error" />
      </template>
      <template v-else>
        <Callout tone="ok" data-test="allow-ok">{{ result.changed ? s.appAccess.done(result.grant.source, access.jail) : s.appAccess.unchanged(result.grant.source, access.jail) }}</Callout>
        <dl class="kv">
          <dt>{{ s.appAccess.typed }}</dt><dd><div v-for="r in result.grant.rules" :key="r" class="mono">{{ r }}</div></dd>
          <template v-if="result.grant.hba?.length"><dt>{{ s.appAccess.hba }}</dt><dd><div v-for="r in result.grant.hba" :key="r" class="mono">{{ r }}</div></dd></template>
          <template v-if="result.grant.database"><dt>{{ s.appAccess.database }}</dt><dd class="mono">{{ result.grant.database }} ({{ s.appAccess.roleOf(result.grant.role || result.grant.database) }})</dd></template>
        </dl>
        <section v-if="result.connection_string" class="acc-secret" data-test="allow-secret" aria-labelledby="acc-secret-h">
          <h3 id="acc-secret-h"><Icon name="lock" />{{ s.appAccess.secretTitle }}</h3>
          <p class="muted">{{ s.appAccess.secretText }}</p>
          <CopyField :value="result.connection_string" :label="s.appAccess.secretTitle" />
        </section>
        <section v-if="result.notes?.length" aria-labelledby="acc-notes-h">
          <h3 id="acc-notes-h">{{ s.appAccess.notes }}</h3>
          <ul class="plain muted"><li v-for="n in result.notes" :key="n">{{ n }}</li></ul>
        </section>
      </template>
    </div>
    <template #footer>
      <template v-if="!result">
        <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
        <button class="btn" type="button" :disabled="busy" data-test="allow-preview-btn" @click="send(true)">{{ busy ? s.appAccess.previewing : s.appAccess.preview }}</button>
        <button class="btn btn-primary" type="submit" form="allow-form" :disabled="busy" data-test="allow-go"><Icon name="plus" />{{ busy ? s.appAccess.allowing : s.appAccess.go }}</button>
      </template>
      <button v-else class="btn btn-primary" type="button" data-test="allow-close" @click="emit('close')">{{ s.appAccess.close }}</button>
    </template>
  </Modal>
</template>

<style>
.acc-kinds { border: 0; padding: 0; margin: 0; display: flex; flex-wrap: wrap; gap: 4px 16px; }
.acc-kinds legend { font-weight: 500; font-size: 13px; padding: 0; margin-bottom: 4px; }
.acc-kind { display: inline-flex; gap: 6px; align-items: center; }
.acc-list { display: grid; gap: 2px; max-height: 180px; overflow-y: auto; border: 1px solid var(--border); border-radius: var(--radius); padding: 4px; margin-top: 6px; }
.acc-pick { display: flex; gap: 8px; align-items: center; padding: 4px 6px; border-radius: var(--radius); cursor: pointer; }
.acc-pick.on { background: var(--accent-soft); }
.acc-row { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 12px; }
.acc-preview, .acc-secret { background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius); padding: 8px 12px; }
.acc-secret h3 { display: flex; gap: 6px; align-items: center; }
.acc-preview .mono, .acc-secret .mono { overflow-wrap: anywhere; }
@media (max-width: 600px) { .acc-row { grid-template-columns: minmax(0, 1fr); } }
</style>
