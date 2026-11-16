<script setup lang="ts">
// The nightly upgrade of one image (spec.auto_upgrade) and what it did (status.auto_upgrade): a global admin turns it
// on, picks the time and whether the packages inside the jails are upgraded too, and saves with a merge patch;
// everyone else reads it. A failed last run stays on the card as a notice until a later run does better.
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import { useFormCheck } from '@jailops/shared/composables/form'
import { stamp } from '@jailops/shared/lib/format'
import { autoAtProblem, autoUpgradeSpec, DEFAULT_AUTO_AT } from '@/lib/images'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import type { Image } from '@jailops/shared/api/types'

const props = defineProps<{ image: Image; editable: boolean }>()
const emit = defineEmits<{ saved: [] }>()

const name = computed(() => props.image.metadata.name)
const spec = computed(() => props.image.spec.auto_upgrade)
const status = computed(() => props.image.status.auto_upgrade)
const recent = computed(() => status.value?.recent ?? [])
const lastFailed = computed(() => (recent.value[0]?.result === 'failed' ? recent.value[0] : null))
const at = computed(() => spec.value?.at || DEFAULT_AUTO_AT)

// the form starts from the definition, and again when the definition changes (a save); a reload that brings the same
// definition keeps what is being edited
const f = reactive({ auto: false, at: DEFAULT_AUTO_AT, packages: true })
const fromSpec = () => Object.assign(f, { auto: !!spec.value?.enabled, at: at.value, packages: spec.value ? !!spec.value.packages : true })
watch(() => JSON.stringify(spec.value ?? null), fromSpec, { immediate: true })
const dirty = computed(() => f.auto !== !!spec.value?.enabled || (f.auto && (f.at !== at.value || f.packages !== !!spec.value?.packages)))

const id = (x: string) => `au-${x}-${name.value}`
const check = useFormCheck(() => ({ [id('at')]: f.auto ? autoAtProblem(f.at) : '' }))
const busy = ref(false)
const error = ref<ApiError | null>(null)

// turning it on proposes the packages too
function toggled(): void {
  if (f.auto && !spec.value?.enabled) f.packages = true
}

const save = () => check.submit(async () => {
  busy.value = true
  error.value = null
  try {
    await runOp(s.autoUpgrade.saveOp(name.value), () => api.images.autoUpgrade(name.value, autoUpgradeSpec(f.auto, f.at, f.packages)))
    check.reset()
    emit('saved')
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
})
const tone = (r: string) => (r === 'ok' ? 'ok' : r === 'failed' ? 'danger' : 'info')
</script>

<template>
  <section class="body au" :aria-labelledby="id('h')" data-test="auto-upgrade" :data-enabled="!!spec?.enabled">
    <h3 :id="id('h')" class="au-h">{{ s.autoUpgrade.title }}</h3>
    <Callout v-if="lastFailed" tone="danger" data-test="auto-upgrade-failed">
      <strong>{{ s.autoUpgrade.lastFailed(stamp(lastFailed.started)) }}</strong>
      <span v-if="lastFailed.detail" class="au-detail mono">{{ lastFailed.detail }}</span>
      <span class="au-detail">{{ s.autoUpgrade.lastFailedText }}</span>
    </Callout>

    <form v-if="editable" :id="id('form')" class="au-form" novalidate @submit.prevent="save">
      <label class="check"><input v-model="f.auto" type="checkbox" :aria-describedby="id('explain')" data-test="auto-upgrade-on" @change="toggled" />{{ s.autoUpgrade.enable }}</label>
      <span :id="id('explain')" class="hint au-explain">{{ s.autoUpgrade.explain }}</span>
      <div v-if="f.auto" class="au-row">
        <div class="field au-at">
          <label :for="id('at')">{{ s.autoUpgrade.at }} <span class="req" aria-hidden="true">*</span></label>
          <input :id="id('at')" v-model="f.at" class="mono" type="time" required :aria-invalid="!!check.err(id('at'))" :aria-describedby="check.err(id('at')) ? id('at-err') : id('at-h')" data-test="auto-upgrade-at" @blur="check.touch(id('at'))" />
          <span v-if="check.err(id('at'))" :id="id('at-err')" class="field-error" role="alert">{{ check.err(id('at')) }}</span>
          <span v-else :id="id('at-h')" class="hint">{{ s.autoUpgrade.atHint }}</span>
        </div>
        <label class="check au-packages"><input v-model="f.packages" type="checkbox" data-test="auto-upgrade-packages" />{{ s.autoUpgrade.packages }}</label>
      </div>
      <div v-if="dirty" class="row">
        <span v-if="check.tried.value && check.reason.value" class="why-disabled">{{ check.reason.value }}</span>
        <button class="btn btn-primary btn-sm" type="submit" :disabled="busy" :aria-disabled="!check.ok.value" data-test="auto-upgrade-save">{{ s.autoUpgrade.save }}</button>
      </div>
      <ErrorPanel v-if="error" :error="error" />
    </form>
    <p v-else class="muted au-state" data-test="auto-upgrade-state">
      {{ spec?.enabled ? s.autoUpgrade.on(at, !!spec.packages) : s.autoUpgrade.off }} <span class="faint">{{ s.autoUpgrade.readOnly }}</span>
    </p>
    <p v-if="editable && spec?.enabled && !dirty" class="muted au-state" data-test="auto-upgrade-summary">{{ s.autoUpgrade.on(at, !!spec.packages) }}</p>

    <p v-if="spec?.enabled && status?.next" class="au-next" data-test="auto-upgrade-next">{{ s.autoUpgrade.next }}: <TimeStamp :ts="status.next" /></p>

    <template v-if="recent.length">
      <h4 :id="id('recent')" class="au-sub">{{ s.autoUpgrade.recent }}</h4>
      <div class="table-wrap">
        <table class="rtable" :aria-labelledby="id('recent')" data-test="auto-upgrade-runs">
          <thead><tr><th>{{ s.autoUpgrade.started }}</th><th>{{ s.autoUpgrade.result }}</th><th>{{ s.autoUpgrade.generation }}</th><th>{{ s.autoUpgrade.jails }}</th><th>{{ s.autoUpgrade.detail }}</th></tr></thead>
          <tbody>
            <tr v-for="r in recent" :key="r.started" :data-result="r.result">
              <td :data-label="s.autoUpgrade.started"><TimeStamp :ts="r.started" /></td>
              <td :data-label="s.autoUpgrade.result"><span class="pill" :class="tone(r.result)">{{ s.autoUpgrade.results[r.result] ?? r.result }}</span></td>
              <td class="mono" :data-label="s.autoUpgrade.generation">{{ r.generation || '-' }}</td>
              <td :data-label="s.autoUpgrade.jails">{{ s.autoUpgrade.jailCounts(r.jails_moved ?? 0, r.jails_upgraded ?? 0, r.jails_failed ?? 0) }}</td>
              <td class="au-cell-detail" :data-label="s.autoUpgrade.detail">{{ r.detail || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
    <p v-else-if="spec?.enabled" class="faint au-state">{{ s.autoUpgrade.none }}</p>
  </section>
</template>

<style>
.au { display: grid; gap: 8px; border-top: 1px solid var(--border); }
.au-h { font-size: 14px; margin: 0; }
.au-sub { font-size: 13px; margin: 4px 0 0; }
.au-form { display: grid; gap: 6px; }
.au-explain { display: block; max-width: 75ch; }
.au-row { display: flex; flex-wrap: wrap; gap: 4px 20px; align-items: center; }
.au-at { margin: 0; }
.au-at input { max-width: 9em; }
.au-state, .au-next { margin: 0; }
.au-detail { display: block; margin-top: 4px; overflow-wrap: anywhere; }
.au-cell-detail { overflow-wrap: anywhere; max-width: 40ch; }
</style>
