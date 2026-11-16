<script setup lang="ts">
// Create an image and, by default, build its first generation: the definition (with the nightly upgrade, on for a
// FreeBSD image), then the build as an operation followed here with its progress. Creating is tier 1 (it changes nothing that exists); a failed build keeps the
// definition, and Try again builds it again.
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { session } from '@jailops/shared/composables/session'
import { useFormCheck } from '@jailops/shared/composables/form'
import { useImageCreate } from '@/composables/imageCreate'
import { imageProblems, initialImageForm, type ImageForm } from '@/lib/images'
import Modal from '@jailops/shared/components/Modal.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import ImageFields from './ImageFields.vue'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ close: []; done: [name: string] }>()

const f = reactive<ImageForm>(initialImageForm(session.info))
const taken = ref<string[]>([])
// the dialog shows the build to its end (a toast would cover its buttons on a phone); closed, the Operations page has it
const run = useImageCreate({ silent: true })
const ids: Record<string, string> = { name: 'img-name', release: 'img-release', arch: 'img-arch', keys: 'img-keys', at: 'img-at' }
const check = useFormCheck(() => {
  const p = imageProblems(f, taken.value)
  return Object.fromEntries(Object.entries(ids).map(([k, id]) => [id, p[k as keyof typeof p] ?? '']))
})
const labels: Record<string, string> = { 'img-name': s.imageCreate.name, 'img-release': s.imageCreate.release, 'img-arch': s.imageCreate.arch, 'img-keys': s.imageCreate.keys, 'img-at': s.autoUpgrade.at }
const why = computed(() => (check.firstId.value ? s.form.fixFirst(`${labels[check.firstId.value]}: ${check.reason.value}`) : ''))
const phase = run.phase
const editing = computed(() => phase.value === 'idle' || (phase.value === 'failed' && run.failedAt.value === 'create'))
const name = computed(() => run.created.value || f.name)

watch(() => props.open, (o) => {
  if (!o) return
  Object.assign(f, initialImageForm(session.info))
  run.reset()
  check.reset()
  taken.value = []
  api.images.list().then((l) => (taken.value = l.map((i) => i.metadata.name))).catch(() => undefined)
})

async function go(): Promise<void> {
  if (await run.run(f)) emit('done', f.name)
}
const submit = () => (editing.value ? check.submit(go) : go())
</script>

<template>
  <Modal :open="open" :title="s.imageCreate.title" @close="emit('close')">
    <form id="img-create" novalidate data-test="image-create" :data-phase="phase" @submit.prevent="submit">
      <p class="muted img-lead">{{ s.imageCreate.lead }}</p>
      <p class="hint faint img-lead">{{ s.form.requiredNote }}</p>
      <ImageFields :f="f" :err="check.err" :touch="check.touch" kinds build-box :disabled="!editing" />
      <div v-if="phase === 'creating' || phase === 'building'" class="img-run" role="status" data-test="image-progress">
        <p class="img-status"><span class="pill info pulse">{{ phase === 'creating' ? s.imageCreate.creating(name) : s.imageCreate.building(name, run.progress.value) }}</span></p>
        <div class="meter" aria-hidden="true"><span :style="{ width: Math.max(3, run.progress.value) + '%' }"></span></div>
        <p class="hint">{{ s.imageCreate.buildNote }}</p>
      </div>
      <Callout v-if="phase === 'done'" tone="ok" data-test="image-done">{{ f.build ? s.imageCreate.done(name) : s.imageCreate.doneNoBuild(name) }}</Callout>
      <Callout v-if="phase === 'cancelled'" tone="warn" data-test="image-cancelled">{{ s.imageCreate.cancelled(name) }}</Callout>
      <template v-if="phase === 'failed' && run.error.value">
        <p class="img-failed" data-test="image-failed">{{ run.failedAt.value === 'build' ? s.imageCreate.buildFailed(name) : s.imageCreate.createFailed }}</p>
        <ErrorPanel :error="run.error.value" />
        <Callout v-if="run.failedAt.value === 'build'" tone="info" data-test="image-check">{{ f.kind === 'freebsd' ? s.imageCreate.check : s.imageCreate.checkLinux }}</Callout>
      </template>
    </form>
    <template #footer>
      <span v-if="editing && why" class="why-disabled" data-test="image-create-why">{{ why }}</span>
      <button v-if="phase === 'building' && run.mayCancel.value" class="btn btn-danger" type="button" data-test="image-cancel" @click="run.cancel">{{ s.imageCreate.cancel }}</button>
      <button class="btn" type="button" data-test="image-close" @click="emit('close')">{{ phase === 'idle' ? s.app.cancel : s.imageCreate.close }}</button>
      <button v-if="editing" class="btn btn-primary" type="submit" form="img-create" :disabled="run.busy.value" :aria-disabled="!check.ok.value" data-test="image-create-go"><Icon name="plus" />{{ f.build ? s.imageCreate.goBuild : s.imageCreate.go }}</button>
      <button v-else-if="phase === 'failed' || phase === 'cancelled'" class="btn btn-primary" type="submit" form="img-create" data-test="image-retry">{{ s.imageCreate.retry }}</button>
    </template>
  </Modal>
</template>

<style>
.img-lead { margin: 0 0 8px; }
.img-run { margin-top: 12px; display: grid; gap: 6px; }
.img-status { margin: 0; }
.img-failed { margin: 12px 0 6px; font-weight: 500; }
</style>
