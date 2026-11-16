<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import { useFormCheck } from '@jailops/shared/composables/form'
import { nameHint, nameProblem } from '@jailops/shared/lib/names'
import Modal from '@jailops/shared/components/Modal.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import ImageCreateDialog from './ImageCreateDialog.vue'
import { isGlobalAdmin } from '@/composables/project'
import { session } from '@jailops/shared/composables/session'
import { defaultImage, freebsdImages, hostRelease, imageLabel } from '@/lib/images'
import { parseLabelField } from '@/lib/labels'
import type { Image, Network, Project, Storage, Volume } from '@jailops/shared/api/types'

const props = defineProps<{ open: boolean; project: Project | undefined; images: Image[]; storage: Storage[]; networks: Network[] }>()
const emit = defineEmits<{ close: []; done: [] }>()

const f = reactive({ name: '', image: '', storage: '', network: '', shell: '', labels: '' })
const labelField = computed(() => parseLabelField(f.labels))
// one optional volume of the project, attached at a path of the jail (more on the jail's page)
const vol = reactive({ name: '', mount: '', readOnly: false })
const volumes = ref<Volume[]>([])
const busy = ref(false)
const error = ref<ApiError | null>(null)

/** The images a jail may start from, by plain name (the newest generation): the one an app would get first, then
 *  the FreeBSD images by release, then the others by name. */
const imageChoices = computed(() => {
  const first = defaultImage(props.images, hostRelease(session.info))
  const rest = [...freebsdImages(props.images), ...props.images.filter((i) => i.spec.os !== 'freebsd').sort((a, b) => (a.metadata.name < b.metadata.name ? -1 : 1))]
  return [...rest.filter((i) => i.metadata.name === first), ...rest.filter((i) => i.metadata.name !== first)]
})
const imageRefs = computed(() => imageChoices.value.map((i) => i.metadata.name))
/** The project's grants narrow the choices; a "*" grant or no project data allows everything. */
const stoNames = computed(() => {
  const g = props.project?.spec.storage ?? []
  const all = props.storage.map((x) => x.metadata.name)
  return !g.length || g.some((x) => x.storage === '*') ? all : all.filter((n) => g.some((x) => x.storage === n))
})
const netNames = computed(() => {
  const g = props.project?.spec.networks ?? []
  const all = props.networks.map((x) => x.metadata.name)
  return g.length ? all.filter((n) => g.some((x) => x.network === n)) : all
})
const volUsed = computed(() => !!vol.name)
/** The shell is a FreeBSD choice: a Linux jail keeps the shell of its distribution. Empty: the host's default
 *  (jails.shell of jailopsd.yaml, bash unless the host says sh). */
const freebsd = computed(() => (props.images.find((i) => i.metadata.name === f.image)?.spec.os ?? 'freebsd') === 'freebsd')

// Field id -> problem, in the order of the form: the first one is named next to Create and focused on submit.
const check = useFormCheck(() => ({
  'jc-name': nameProblem(f.name, 'jail'),
  'jc-labels': labelField.value.problem ? s.labels.problems[labelField.value.problem] : '',
  'jc-image': f.image ? '' : s.jails.needImageField,
  'jc-sto': f.storage ? '' : s.jails.needStorageField,
  'jc-mount': !volUsed.value ? '' : !vol.mount ? s.jails.mountNeeded : /^\/[^\s"\\]*[^/\s]$/.test(vol.mount) && !vol.mount.includes('..') ? '' : s.jails.mountInvalid,
}))
const labels: Record<string, string> = { 'jc-name': s.jails.name, 'jc-labels': s.labels.createField, 'jc-image': s.jails.image, 'jc-sto': s.nav.storage, 'jc-mount': s.jails.volumeMount }
const why = computed(() => (check.firstId.value ? s.form.fixFirst(`${labels[check.firstId.value]}: ${check.reason.value}`) : ''))
const describe = (id: string, hint?: string) => [check.err(id) ? `${id}-err` : '', hint && check.err(id) !== nameHint('jail') ? hint : ''].filter(Boolean).join(' ') || undefined

function clearVolume(): void {
  Object.assign(vol, { name: '', mount: '', readOnly: false })
}
const noImage = computed(() => !imageRefs.value.length)
const missing = computed(() => (noImage.value ? (isGlobalAdmin() ? s.jails.needImage : s.jails.needImageAsk) : !stoNames.value.length ? s.jails.needStorage : ''))
// without an image the form offers to create the base image; the list reloads when it is made
const makingImage = ref(false)
watch(imageRefs, (r) => { if (!f.image && r.length) f.image = r[0] })

watch(() => props.open, (o) => {
  if (!o) {
    clearVolume()
    return
  }
  error.value = null
  check.reset()
  void api.volumes.list().then((v) => { volumes.value = v }).catch(() => { volumes.value = [] })
  Object.assign(f, { name: '', image: imageRefs.value[0] ?? '', storage: stoNames.value[0] ?? '', network: netNames.value[0] ?? '', shell: '', labels: '' })
})

async function save(): Promise<void> {
  busy.value = true
  error.value = null
  const attach = volUsed.value ? [{ volume: vol.name, mount: vol.mount, ...(vol.readOnly ? { read_only: true } : {}) }] : []
  check.reset()
  try {
    await runOp(s.jails.createTitle + ': ' + f.name, () =>
      api.jails.create({ metadata: { name: f.name, ...(Object.keys(labelField.value.labels).length ? { labels: labelField.value.labels } : {}) }, spec: { image: f.image, storage: f.storage, ...(f.network ? { network: [{ network: f.network, ipv4: 'auto' }] } : {}), ...(attach.length ? { volumes: attach } : {}), ...(f.shell && freebsd.value ? { shell: f.shell } : {}) } }),
    )
    clearVolume()
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
  <Modal :open="open" :title="s.jails.createTitle" @close="emit('close')">
    <div v-if="missing" class="stack" data-test="jail-missing">
      <p class="muted jc-missing">{{ missing }}</p>
      <div v-if="noImage && isGlobalAdmin()" class="row"><button class="btn btn-primary" type="button" data-test="jail-make-image" @click="makingImage = true"><Icon name="plus" />{{ s.imageCreate.openBase }}</button></div>
    </div>
    <form v-else id="jc" novalidate @submit.prevent="check.submit(save)">
      <p class="hint faint jc-note">{{ s.form.requiredNote }}</p>
      <div class="field">
        <label for="jc-name">{{ s.jails.name }} <span class="req" aria-hidden="true">*</span></label>
        <input id="jc-name" v-model.trim="f.name" class="mono" type="text" required autocomplete="off" spellcheck="false" :aria-invalid="!!check.err('jc-name')" :aria-describedby="describe('jc-name', 'jc-name-hint')" @blur="f.name && check.touch('jc-name')" />
        <span v-if="check.err('jc-name')" id="jc-name-err" class="field-error" role="alert">{{ check.err('jc-name') }}</span>
        <span v-if="check.err('jc-name') !== nameHint('jail')" id="jc-name-hint" class="hint">{{ nameHint('jail') }}</span>
      </div>
      <div class="field">
        <label for="jc-image">{{ s.jails.image }} <span class="req" aria-hidden="true">*</span></label>
        <select id="jc-image" v-model="f.image" required :aria-invalid="!!check.err('jc-image')" :aria-describedby="describe('jc-image')"><option v-for="i in imageChoices" :key="i.metadata.name" :value="i.metadata.name">{{ imageLabel(i) }}</option></select>
        <span v-if="check.err('jc-image')" id="jc-image-err" class="field-error" role="alert">{{ check.err('jc-image') }}</span>
      </div>
      <div class="field">
        <label for="jc-sto">{{ s.nav.storage }} <span class="req" aria-hidden="true">*</span></label>
        <select id="jc-sto" v-model="f.storage" required :aria-invalid="!!check.err('jc-sto')" :aria-describedby="describe('jc-sto')"><option v-for="x in stoNames" :key="x" :value="x">{{ x }}</option></select>
        <span v-if="check.err('jc-sto')" id="jc-sto-err" class="field-error" role="alert">{{ check.err('jc-sto') }}</span>
      </div>
      <div class="field">
        <label for="jc-net">{{ s.install.network }}</label>
        <select id="jc-net" v-model="f.network" aria-describedby="jc-net-hint"><option value="">{{ s.jails.noNetwork }}</option><option v-for="x in netNames" :key="x" :value="x">{{ x }}</option></select>
        <span id="jc-net-hint" class="hint">{{ s.jails.networkHint }}</span>
      </div>
      <div v-if="freebsd" class="field">
        <label for="jc-shell">{{ s.jails.shell }}</label>
        <select id="jc-shell" v-model="f.shell" aria-describedby="jc-shell-hint" data-test="jc-shell"><option value="">{{ s.jails.shellDefault }}</option><option value="bash">{{ s.jails.shellBash }}</option><option value="sh">{{ s.jails.shellSh }}</option></select>
        <span id="jc-shell-hint" class="hint">{{ s.jails.shellHint }}</span>
      </div>
      <div class="field">
        <label for="jc-labels">{{ s.labels.createField }}</label>
        <input id="jc-labels" v-model="f.labels" class="mono" type="text" autocomplete="off" spellcheck="false" autocapitalize="off" placeholder="env=prod team=web" :aria-invalid="!!check.err('jc-labels')" :aria-describedby="describe('jc-labels', 'jc-labels-hint')" data-test="jc-labels" @blur="f.labels && check.touch('jc-labels')" />
        <span v-if="check.err('jc-labels')" id="jc-labels-err" class="field-error" role="alert">{{ check.err('jc-labels') }}</span>
        <span id="jc-labels-hint" class="hint">{{ s.labels.createHint }}</span>
      </div>
      <fieldset v-if="volumes.length" class="vol-set">
        <legend>{{ s.jails.volume }}</legend>
        <div class="field">
          <label for="jc-vol">{{ s.jails.volumeName }}</label>
          <select id="jc-vol" v-model="vol.name" class="mono" data-test="jc-volume" aria-describedby="jc-vol-hint">
            <option value="">{{ s.jails.volumeNone }}</option>
            <option v-for="v in volumes" :key="v.metadata.name" :value="v.metadata.name" :disabled="v.spec.encrypted && (v.status?.attached_to?.length ?? 0) > 0">{{ v.metadata.name }}</option>
          </select>
          <span id="jc-vol-hint" class="hint">{{ s.jails.volumeHint }}</span>
        </div>
        <template v-if="vol.name">
          <div class="field">
            <label for="jc-mount">{{ s.jails.volumeMount }} <span class="req" aria-hidden="true">*</span></label>
            <input id="jc-mount" v-model.trim="vol.mount" class="mono" type="text" autocomplete="off" spellcheck="false" placeholder="/var/db/app" :aria-invalid="!!check.err('jc-mount')" :aria-describedby="describe('jc-mount')" @blur="vol.mount && check.touch('jc-mount')" />
            <span v-if="check.err('jc-mount')" id="jc-mount-err" class="field-error" role="alert" data-test="jc-vol-error">{{ check.err('jc-mount') }}</span>
          </div>
          <label class="check"><input v-model="vol.readOnly" type="checkbox" data-test="jc-ro" /> {{ s.jails.volumeReadOnly }}</label>
        </template>
      </fieldset>
      <ErrorPanel v-if="error" :error="error" />
    </form>
    <template #footer>
      <span v-if="!missing && why" class="why-disabled" data-test="jail-create-why">{{ why }}</span>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button v-if="!missing" class="btn btn-primary" type="submit" form="jc" :disabled="busy" :aria-disabled="!check.ok.value" data-test="jail-create-go">{{ s.jails.create }}</button>
    </template>
  </Modal>
  <ImageCreateDialog :open="makingImage" @close="makingImage = false" />
</template>

<style>
.vol-set { border: 1px solid var(--border); border-radius: var(--radius); padding: 8px 12px; margin: 0 0 12px; }
.vol-set legend { padding: 0 4px; font-size: 13px; color: var(--text-2); }
.vol-set .check { display: flex; gap: 8px; align-items: center; }
.vol-set > .hint { display: block; margin-top: 2px; color: var(--text-3); font-size: 12px; }
.jc-pass-field { margin-top: 10px; }
.jc-note { margin: 0 0 8px; font-size: 12px; }
.jc-missing { margin: 0; }
</style>
