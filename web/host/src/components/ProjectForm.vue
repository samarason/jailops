<script setup lang="ts">
import { clone } from '@/lib/clone'
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import { session, isHub } from '@jailops/shared/composables/session'
import Modal from '@jailops/shared/components/Modal.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import { useFormCheck } from '@jailops/shared/composables/form'
import { nameHint } from '@jailops/shared/lib/names'
import { nameError } from '@/lib/nameField'
import type { Project, ProjectNetwork, ProjectStorage, Network, Storage } from '@jailops/shared/api/types'

const props = defineProps<{ open: boolean; project: Project | null; etag?: string; networks: Network[]; storage: Storage[] }>()
const emit = defineEmits<{ close: []; done: [] }>()

interface Form {
  name: string; comment: string; hosts: string; firewall: string; images: string; newNetwork: boolean
  jails: number | undefined; cpu: number | undefined; memory: string; pids: number | undefined; addresses: number | undefined
  networks: ProjectNetwork[]; storage: ProjectStorage[]
}
const blank = (): Form => ({ name: '', comment: '', hosts: '', firewall: '', images: '', newNetwork: false, jails: undefined, cpu: undefined, memory: '', pids: undefined, addresses: undefined, networks: [], storage: [] })
const f = reactive<Form>(blank())
const busy = ref(false)
const error = ref<ApiError | null>(null)
const editing = computed(() => !!props.project)
// the project rule of the server: the object rule, and "all" and "host" are reserved
const check = useFormCheck(() => ({ 'pf-name': editing.value ? '' : nameError(f.name, 'project') }))
const split = (v: string) => v.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

watch(() => props.open, (o) => {
  if (!o) return
  error.value = null
  check.reset()
  Object.assign(f, blank())
  const p = props.project
  if (p) {
    const q = p.spec.quotas ?? {}
    Object.assign(f, { name: p.metadata.name, comment: p.spec.comment ?? '', hosts: (p.spec.hosts ?? []).join(', '), firewall: (p.spec.firewall_policies ?? []).join(', '), images: (p.spec.images ?? []).join(', '), jails: q.jails, cpu: q.cpu, memory: q.memory ?? '', pids: q.pids, addresses: q.addresses, networks: clone(p.spec.networks ?? []), storage: clone(p.spec.storage ?? []) })
  }
})

function body(): Pick<Project, 'metadata' | 'spec'> {
  const quotas: Record<string, unknown> = {}
  if (f.jails) quotas.jails = f.jails
  if (f.cpu) quotas.cpu = f.cpu
  if (f.memory.trim()) quotas.memory = f.memory.trim()
  if (f.pids) quotas.pids = f.pids
  if (f.addresses) quotas.addresses = f.addresses
  const clean = <T extends object>(rows: T[]) => rows.map((r) => Object.fromEntries(Object.entries(r).filter(([, v]) => v !== '' && v !== false && v !== undefined))) as T[]
  return {
    metadata: { ...(props.project?.metadata ?? {}), name: f.name },
    spec: {
      ...(f.comment ? { comment: f.comment } : {}),
      ...(split(f.hosts).length ? { hosts: split(f.hosts) } : {}),
      networks: clean(f.networks),
      storage: clean(f.storage),
      quotas,
      ...(split(f.firewall).length ? { firewall_policies: split(f.firewall) } : {}),
      ...(split(f.images).length ? { images: split(f.images) } : {}),
      ...(!editing.value && f.newNetwork ? { new_network: true } : {}),
    },
  }
}

const save = () => check.submit(async () => {
  busy.value = true
  error.value = null
  try {
    const b = body()
    if (editing.value) await runOp(s.projects.editTitle(f.name), () => api.projects.put({ ...props.project!, ...b } as Project, props.etag))
    else await runOp(s.projects.createTitle + ': ' + f.name, () => api.projects.create(b))
    emit('done')
    emit('close')
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
})
const addNet = () => f.networks.push({ network: props.networks[0]?.metadata.name ?? '' })
const addSto = () => f.storage.push({ storage: props.storage[0]?.metadata.name ?? '*' })
const netNames = computed(() => props.networks.map((n) => n.metadata.name))
const stoNames = computed(() => ['*', ...props.storage.map((x) => x.metadata.name)])
void session
</script>

<template>
  <Modal :open="open" :title="editing ? s.projects.editTitle(f.name) : s.projects.createTitle" wide @close="emit('close')">
    <form id="pf" novalidate @submit.prevent="save">
      <div class="form-2">
        <div class="field"><label for="pf-name">{{ s.projects.name }} <span v-if="!editing" class="req" aria-hidden="true">*</span></label>
          <input id="pf-name" v-model="f.name" class="mono" type="text" autocomplete="off" :readonly="editing" :aria-invalid="!!check.err('pf-name')" aria-describedby="pf-name-h pf-name-e" @input="check.touch('pf-name')" />
          <span id="pf-name-h" class="hint">{{ editing ? s.projects.nameFixed : nameHint('project') }}</span>
          <span id="pf-name-e" class="field-error" role="alert">{{ check.err('pf-name') }}</span></div>
        <div class="field"><label for="pf-desc">{{ s.projects.comment }}</label><input id="pf-desc" v-model="f.comment" type="text" /></div>
      </div>
      <label v-if="!editing" class="check" style="margin-bottom: 4px"><input v-model="f.newNetwork" type="checkbox" data-test="new-network" />{{ s.projects.newNetwork }}</label>
      <p v-if="!editing" class="hint muted">{{ s.projects.newNetworkHint }}</p>

      <h3 style="margin: 12px 0 6px">{{ s.projects.grantNetworks }}</h3>
      <div v-for="(n, i) in f.networks" :key="'n' + i" class="grant-row">
        <select v-model="n.network" :aria-label="s.projects.network"><option v-for="x in netNames" :key="x" :value="x">{{ x }}</option></select>
        <button class="btn btn-sm btn-icon btn-danger" type="button" :aria-label="s.projects.removeGrant" @click="f.networks.splice(i, 1)"><Icon name="trash" /></button>
      </div>
      <button class="btn btn-sm" type="button" @click="addNet"><Icon name="plus" />{{ s.projects.addNetwork }}</button>

      <h3 style="margin: 12px 0 6px">{{ s.projects.grantStorage }}</h3>
      <div v-for="(x, i) in f.storage" :key="'s' + i" class="grant-row grant-sto">
        <select v-model="x.storage" :aria-label="s.projects.storage"><option v-for="n in stoNames" :key="n" :value="n">{{ n === '*' ? s.projects.wildcard : n }}</option></select>
        <input v-model="x.quota" class="mono" type="text" :placeholder="s.projects.quotaField + ' (500G)'" :aria-label="s.projects.quotaField" />
        <button class="btn btn-sm btn-icon btn-danger" type="button" :aria-label="s.projects.removeGrant" @click="f.storage.splice(i, 1)"><Icon name="trash" /></button>
      </div>
      <button class="btn btn-sm" type="button" @click="addSto"><Icon name="plus" />{{ s.projects.addStorage }}</button>

      <h3 style="margin: 12px 0 6px">{{ s.projects.quotas }}</h3>
      <div class="grid-2" style="grid-template-columns: repeat(auto-fit, minmax(130px, 1fr))">
        <div class="field"><label for="pf-j">{{ s.projects.jailsQuota }}</label><input id="pf-j" v-model.number="f.jails" type="number" min="0" /></div>
        <div class="field"><label for="pf-c">{{ s.projects.cpuQuota }}</label><input id="pf-c" v-model.number="f.cpu" type="number" min="0" /></div>
        <div class="field"><label for="pf-m">{{ s.projects.memoryQuota }}</label><input id="pf-m" v-model="f.memory" class="mono" type="text" placeholder="8G" /></div>
        <div class="field"><label for="pf-p">{{ s.projects.pidsQuota }}</label><input id="pf-p" v-model.number="f.pids" type="number" min="0" /></div>
        <div class="field"><label for="pf-a">{{ s.projects.addressesQuota }}</label><input id="pf-a" v-model.number="f.addresses" type="number" min="0" /></div>
      </div>
      <p class="hint muted">{{ s.projects.sums }}</p>

      <div class="field"><label for="pf-fw">{{ s.projects.firewall }}</label><input id="pf-fw" v-model="f.firewall" class="mono" type="text" /><span class="hint">{{ s.projects.firewallHint }}</span></div>
      <div class="field"><label for="pf-img">{{ s.projects.images }}</label><input id="pf-img" v-model="f.images" class="mono" type="text" /><span class="hint">{{ s.projects.imagesHint }}</span></div>
      <div v-if="isHub" class="field"><label for="pf-hosts">{{ s.projects.hosts }}</label><input id="pf-hosts" v-model="f.hosts" class="mono" type="text" /><span class="hint">{{ s.projects.hostsHint }}</span></div>
      <ErrorPanel v-if="error" :error="error" />
    </form>
    <template #footer>
      <span v-if="check.reason.value" class="why-disabled">{{ s.projects.name }}: {{ check.reason.value }}</span>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button class="btn btn-primary" type="submit" form="pf" :disabled="busy" :aria-disabled="!check.ok.value" data-test="project-save">{{ s.projects.save }}</button>
    </template>
  </Modal>
</template>

<style>
.grant-row { display: grid; grid-template-columns: minmax(120px, 1fr) minmax(120px, 1fr) minmax(120px, 1fr) auto auto; gap: 8px; align-items: center; margin-bottom: 6px; }
.grant-sto { grid-template-columns: minmax(120px, 1fr) minmax(120px, 1fr) auto auto; }
@media (max-width: 800px) { .grant-row, .grant-sto { grid-template-columns: 1fr 1fr; } }
</style>
