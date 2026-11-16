<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import { useFormCheck } from '@jailops/shared/composables/form'
import Modal from '@jailops/shared/components/Modal.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import type { Volume } from '@jailops/shared/api/types'

// Attach a volume of the project to a stopped jail at a path of the jail. The volumes that can be attached are those
// that are not attached to this jail already (an encrypted volume that another jail has is left out).
const props = defineProps<{ open: boolean; jail: string; attached: string[] }>()
const emit = defineEmits<{ close: []; done: [] }>()

const volumes = ref<Volume[]>([])
const loadError = ref<ApiError | null>(null)
const f = reactive({ volume: '', mount: '', readOnly: false, copy: false })
const busy = ref(false)
const error = ref<ApiError | null>(null)

const chosenHostDir = computed(() => !!volumes.value.find((v) => v.metadata.name === f.volume)?.spec.path)
watch(chosenHostDir, (h) => { if (h) f.copy = false })
const choices = computed(() => volumes.value.filter((v) => !props.attached.includes(v.metadata.name) && !(v.spec.encrypted && (v.status?.attached_to?.length ?? 0) > 0)))
const mountOk = (m: string) => /^\/[^\s"\\]*$/.test(m) && m !== '/' && !m.includes('..')
const check = useFormCheck(() => ({
  'av-volume': f.volume ? '' : s.jails.volumeNameNeeded,
  'av-mount': !f.mount ? s.jails.mountNeeded : !mountOk(f.mount) ? s.jails.mountInvalid : '',
}))

watch(() => props.open, async (o) => {
  if (!o) return
  Object.assign(f, { volume: '', mount: '', readOnly: false, copy: false })
  error.value = loadError.value = null
  check.reset()
  try {
    volumes.value = await api.volumes.list()
    if (choices.value.length) f.volume = choices.value[0].metadata.name
  } catch (e) {
    loadError.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  }
})

const go = () => check.submit(async () => {
  busy.value = true
  error.value = null
  try {
    await runOp(s.jail.attachTitle(props.jail), () => api.jails.attach(props.jail, { volume: f.volume, mount: f.mount, ...(f.readOnly ? { read_only: true } : {}), ...(f.copy ? { copy_existing: true } : {}) }))
    emit('done')
    emit('close')
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
})
</script>

<template>
  <Modal :open="open" :title="s.jail.attachTitle(jail)" @close="emit('close')">
    <form id="attach-form" novalidate @submit.prevent="go">
      <p class="muted">{{ s.jail.attachLead }}</p>
      <ErrorPanel v-if="loadError" :error="loadError" />
      <p v-else-if="!choices.length" class="empty" data-test="attach-none">{{ s.jail.noVolumesToAttach }} <router-link to="/volumes" @click="emit('close')">{{ s.nav.volumes }}</router-link></p>
      <template v-else>
        <div class="field">
          <label for="av-volume">{{ s.jails.volumeName }} <span class="req" aria-hidden="true">*</span></label>
          <select id="av-volume" v-model="f.volume" class="mono" data-test="attach-volume" :aria-invalid="!!check.err('av-volume')">
            <option v-for="v in choices" :key="v.metadata.name" :value="v.metadata.name">{{ v.metadata.name }}</option>
          </select>
          <span class="field-error" role="alert">{{ check.err('av-volume') }}</span>
        </div>
        <div class="field">
          <label for="av-mount">{{ s.jails.volumeMount }} <span class="req" aria-hidden="true">*</span></label>
          <input id="av-mount" v-model="f.mount" class="mono" type="text" placeholder="/var/db/app" autocomplete="off" data-test="attach-mount" aria-describedby="av-mount-e" :aria-invalid="!!check.err('av-mount')" @input="check.touch('av-mount')" />
          <span id="av-mount-e" class="field-error" role="alert">{{ check.err('av-mount') }}</span>
        </div>
        <label class="check"><input v-model="f.readOnly" type="checkbox" data-test="attach-ro" /> {{ s.jails.volumeReadOnly }}</label>
        <template v-if="!chosenHostDir">
        <label class="check"><input v-model="f.copy" type="checkbox" data-test="attach-copy" aria-describedby="av-copy-h" /> {{ s.jail.copyExisting }}</label>
        <span id="av-copy-h" class="hint">{{ s.jail.copyExistingHint }}</span>
        </template>
        <ErrorPanel v-if="error" :error="error" style="margin-top: 12px" />
      </template>
    </form>
    <template #footer>
      <span v-if="check.reason.value" class="why-disabled">{{ check.reason.value }}</span>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button class="btn btn-primary" type="submit" form="attach-form" :disabled="busy || !choices.length" :aria-disabled="!check.ok.value" data-test="attach-go">{{ s.jail.attach }}</button>
    </template>
  </Modal>
</template>
