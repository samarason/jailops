<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { confirmAction } from '@jailops/shared/composables/confirm'
import { bytes } from '@jailops/shared/lib/format'
import { nameProblem } from '@jailops/shared/lib/names'
import Icon from '@jailops/shared/components/Icon.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import ConfirmDialog from '@jailops/shared/components/ConfirmDialog.vue'
import Modal from '@jailops/shared/components/Modal.vue'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import UnlockDialog from '@/components/UnlockDialog.vue'
import PassphraseDialog from '@/components/PassphraseDialog.vue'
import { isHostDir, isLost, volumeLoss } from '@/lib/volumes'
import type { Volume, VolumeSnapshot } from '@jailops/shared/api/types'

const route = useRoute()
const router = useRouter()
const name = computed(() => String(route.params.name))

const l = useLoad(async () => {
  const v = await api.volumes.get(name.value)
  const snaps = await api.volumes.snapshots(name.value).catch(() => [] as VolumeSnapshot[])
  return { v, snaps }
})
const vol = computed<Volume | undefined>(() => l.data.value?.v)
const snaps = computed(() => [...(l.data.value?.snaps ?? [])].sort((a, b) => (b.metadata.created_at ?? '').localeCompare(a.metadata.created_at ?? '')))
const locked = computed(() => !!vol.value?.status?.locked)
const attached = computed(() => vol.value?.status?.attached_to ?? [])
const hostDir = computed(() => !!vol.value && isHostDir(vol.value))
const lost = computed(() => !!vol.value && isLost(vol.value))

const unlockOpen = ref(false)
const passOpen = ref(false)
const lockOpen = ref(false)
const lock = () => runOp(s.keys.lockTitle(name.value), () => api.volumes.lock(name.value))

// edit: the comment and the size; the owner, the mode and the storage are fixed when the volume is made
const editing = ref(false)
const ef = reactive({ comment: '', size: '', watch: false, probe: 'mounted', onLoss: 'none' })
const editBusy = ref(false)
const editError = ref<ApiError | null>(null)
function openEdit(): void {
  Object.assign(ef, { comment: vol.value?.spec.comment ?? '', size: vol.value?.spec.size ?? '', watch: !!vol.value?.spec.watch, probe: vol.value?.spec.probe || 'mounted', onLoss: vol.value?.spec.on_loss || 'none' })
  editError.value = null
  editing.value = true
}
async function saveEdit(): Promise<void> {
  const v = vol.value
  if (!v) return
  editBusy.value = true
  editError.value = null
  const next: Volume = hostDir.value
    ? { ...v, spec: { ...v.spec, comment: ef.comment || undefined, watch: ef.watch || undefined, probe: ef.watch ? ef.probe : undefined, on_loss: ef.watch ? ef.onLoss : undefined } }
    : { ...v, spec: { ...v.spec, comment: ef.comment || undefined, size: ef.size || undefined } }
  delete next.status
  try {
    await runOp(s.volumes.editTitle(v.metadata.name), () => api.volumes.put(next))
    editing.value = false
    await l.reload()
  } catch (e) {
    editError.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    editBusy.value = false
  }
}

function remove(): void {
  const v = vol.value
  if (!v) return
  const n = v.metadata.name
  if (isHostDir(v)) {
    confirmAction({
      title: s.volumes.deleteHostDirTitle(n), confirmLabel: s.volumes.forget, text: s.volumes.deleteHostDirText,
      run: () => runOp(s.volumes.deleteHostDirTitle(n), () => api.volumes.remove(n)),
      done: () => void router.push('/volumes'),
    })
    return
  }
  confirmAction({
    title: s.volumes.deleteTitle(n), confirmLabel: s.volumes.deleteVolume, text: s.volumes.deleteText, items: volumeLoss(v, snaps.value.length), itemsLabel: s.volumes.destroyed,
    typeName: n, typeLabel: s.volumes.typeName(n), danger: true,
    run: () => runOp(s.volumes.deleteTitle(n), () => api.volumes.remove(n)),
    done: () => void router.push('/volumes'),
  })
}

// snapshots
const snapOpen = ref(false)
const snapName = ref('')
const snapComment = ref('')
const snapProblem = computed(() => (snapName.value ? nameProblem(snapName.value, 'snapshot') : ''))
const snapBusy = ref(false)
const snapError = ref<ApiError | null>(null)
function openSnap(): void {
  snapName.value = ''
  snapComment.value = ''
  snapError.value = null
  snapOpen.value = true
}
async function takeSnap(): Promise<void> {
  if (snapProblem.value) return
  snapBusy.value = true
  snapError.value = null
  try {
    await runOp(s.volumes.snapshotTitle(name.value), () => api.volumes.snapshot(name.value, { metadata: snapName.value ? { name: snapName.value } : {}, spec: { volume: name.value, ...(snapComment.value ? { comment: snapComment.value } : {}) } }))
    snapOpen.value = false
    await l.reload()
  } catch (e) {
    snapError.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    snapBusy.value = false
  }
}
function rollback(sn: VolumeSnapshot): void {
  const n = sn.metadata.name
  confirmAction({
    title: s.volumes.rollbackTitle(name.value, n), confirmLabel: s.volumes.rollback, text: s.volumes.rollbackText(bytes(sn.status.written ?? 0)),
    typeName: name.value, typeLabel: s.volumes.typeName(name.value), danger: true,
    run: () => runOp(s.volumes.rollbackTitle(name.value, n), () => api.volumes.rollback(name.value, { snapshot: n, confirm_data_loss: true })),
    done: () => void l.reload(),
  })
}
function removeSnap(sn: VolumeSnapshot): void {
  const n = sn.metadata.name
  confirmAction({
    title: s.volumes.deleteSnapshotTitle(n), confirmLabel: s.volumes.deleteSnapshot, text: s.volumes.deleteSnapshotText, danger: true,
    run: () => runOp(s.volumes.deleteSnapshotTitle(n), () => api.volumes.removeSnapshot(name.value, n)),
    done: () => void l.reload(),
  })
}
</script>

<template>
  <div>
    <router-link class="back" to="/volumes"><Icon name="chevronLeft" />{{ s.volumes.back }}</router-link>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!vol" @retry="l.reload">
      <div v-if="vol">
        <div class="page-head">
          <div class="row">
            <h1 class="mono">{{ vol.metadata.name }}</h1>
            <span v-if="vol.spec.encrypted" class="badge" :class="locked ? 'warn' : 'info'" data-test="volume-state">{{ locked ? s.volumes.locked : s.volumes.encrypted }}</span>
            <span v-if="hostDir" class="badge" :class="lost ? 'warn' : 'info'" data-test="volume-state">{{ lost ? s.volumes.stateLost : s.volumes.stateOk }}</span>
          </div>
          <div class="row-actions">
            <button v-if="locked" class="btn btn-primary" type="button" data-test="unlock" @click="unlockOpen = true"><Icon name="lockOpen" />{{ s.keys.unlock }}</button>
            <template v-else-if="vol.spec.encrypted">
              <button class="btn" type="button" data-test="lock" @click="lockOpen = true"><Icon name="lock" />{{ s.keys.lock }}</button>
              <button class="btn" type="button" data-test="change-pass" @click="passOpen = true"><Icon name="keyRound" />{{ s.volumes.changePassphrase }}</button>
            </template>
            <button class="btn" type="button" data-test="volume-edit" @click="openEdit">{{ s.volumes.edit }}</button>
            <button class="btn btn-danger" type="button" data-test="volume-delete" @click="remove"><Icon name="trash" />{{ hostDir ? s.volumes.forget : s.volumes.deleteVolume }}</button>
          </div>
        </div>
        <Callout v-if="locked" tone="warn" data-test="locked-callout">{{ s.keys.lockedHint }}</Callout>
        <Callout v-if="lost" tone="warn" data-test="lost-callout">{{ s.volumes.lostCallout(vol.spec.path ?? '', vol.status?.detail ?? '') }}</Callout>
        <Callout v-for="w in vol.status?.warnings ?? []" :key="w" tone="warn" data-test="volume-warning">{{ w }}</Callout>
        <p v-if="vol.spec.comment" class="muted">{{ vol.spec.comment }}</p>

        <div class="grid-2">
          <section class="panel">
            <header><h2>{{ s.volumes.overview }}</h2></header>
            <dl v-if="hostDir" class="kv" data-test="hostdir-overview">
              <dt>{{ s.volumes.directory }}</dt><dd class="mono">{{ vol.spec.path }}</dd>
              <dt>{{ s.volumes.state }}</dt><dd>{{ lost ? s.volumes.stateLost : s.volumes.stateOk }}<span v-if="vol.status?.detail" class="faint"> ({{ vol.status.detail }})</span></dd>
              <dt>{{ s.volumes.watch }}</dt><dd>{{ vol.spec.watch ? s.volumes.watchOn(vol.spec.probe === 'write' ? s.volumes.probeWrite : s.volumes.probeMounted, vol.spec.on_loss === 'stop' ? s.volumes.onLossStop : s.volumes.onLossNone) : s.volumes.watchOff }}</dd>
            </dl>
            <dl v-else class="kv">
              <dt>{{ s.volumes.storage }}</dt><dd class="mono">{{ vol.spec.storage || '-' }}</dd>
              <dt>{{ s.volumes.dataset }}</dt><dd class="mono">{{ vol.status?.dataset || '-' }}</dd>
              <dt>{{ s.volumes.mountpoint }}</dt><dd class="mono">{{ vol.status?.mountpoint || '-' }}</dd>
              <dt>{{ s.volumes.used }}</dt><dd class="mono">{{ bytes(vol.status?.used ?? 0) }}<span v-if="vol.spec.size" class="faint"> / {{ vol.spec.size }}</span></dd>
              <dt>{{ s.volumes.owner }}</dt><dd class="mono" :title="s.volumes.fixed">{{ vol.spec.uid }}:{{ vol.spec.gid }}</dd>
              <dt>{{ s.volumes.mode }}</dt><dd class="mono" :title="s.volumes.fixed">{{ vol.spec.mode || '-' }}</dd>
            </dl>
          </section>
          <section class="panel">
            <header><h2>{{ s.volumes.attachedTo }}</h2></header>
            <p v-if="!attached.length" class="empty">{{ s.volumes.none }}</p>
            <div v-else class="table-wrap"><table data-test="volume-uses">
              <thead><tr><th>{{ s.jails.name }}</th><th>{{ s.jail.mount }}</th></tr></thead>
              <tbody><tr v-for="u in attached" :key="u.jail" :data-use="u.jail"><td><router-link class="mono" :to="`/jails/${encodeURIComponent(u.jail)}`">{{ u.jail }}</router-link></td>
                <td class="mono">{{ u.mount }}<span v-if="u.read_only" class="badge info" style="margin-left: 6px">{{ s.volumes.readOnly }}</span></td></tr></tbody>
            </table></div>
          </section>
        </div>

        <section v-if="!hostDir" class="panel">
          <header><h2>{{ s.volumes.snapshots }}</h2><button class="btn btn-sm" type="button" data-test="volume-snapshot" @click="openSnap"><Icon name="camera" />{{ s.volumes.snapshotTake }}</button></header>
          <p v-if="!snaps.length" class="empty">{{ s.volumes.noSnapshots }}</p>
          <div v-else class="table-wrap"><table data-test="volume-snapshots" class="rtable">
            <thead><tr><th>{{ s.jails.name }}</th><th>{{ s.volumes.snapshotCreated }}</th><th :title="s.volumes.writtenHint">{{ s.volumes.written }}</th><th><span class="sr-only">{{ s.app.actions }}</span></th></tr></thead>
            <tbody><tr v-for="sn in snaps" :key="sn.metadata.name" :data-snapshot="sn.metadata.name">
              <td class="mono" :data-label="s.jails.name">{{ sn.metadata.name }}<div v-if="sn.spec.comment" class="faint">{{ sn.spec.comment }}</div></td>
              <td :data-label="s.volumes.snapshotCreated"><TimeStamp :ts="sn.metadata.created_at" /></td>
              <td class="mono" :data-label="s.volumes.written">{{ bytes(sn.status.written ?? 0) }}</td>
              <td class="actions"><div class="row-actions"><button class="btn btn-sm" type="button" :data-rollback="sn.metadata.name" @click="rollback(sn)">{{ s.volumes.rollback }}</button><button class="btn btn-sm btn-danger" type="button" :data-delete-snapshot="sn.metadata.name" @click="removeSnap(sn)">{{ s.volumes.deleteSnapshot }}</button></div></td>
            </tr></tbody></table></div>
        </section>

        <UnlockDialog :open="unlockOpen" :volume="vol.metadata.name" @close="unlockOpen = false" @done="l.reload" />
        <PassphraseDialog :open="passOpen" :volume="vol.metadata.name" @close="passOpen = false" @done="l.reload" />
        <ConfirmDialog :open="lockOpen" :title="s.keys.lockTitle(vol.metadata.name)" :confirm-label="s.keys.lock" danger :run="lock" @close="lockOpen = false" @done="l.reload"><Callout tone="warn">{{ s.keys.lockText }}</Callout></ConfirmDialog>

        <Modal :open="editing" :title="s.volumes.editTitle(vol.metadata.name)" @close="editing = false">
          <form id="ve" novalidate @submit.prevent="saveEdit">
            <div class="field"><label for="ve-comment">{{ s.volumes.comment }}</label><input id="ve-comment" v-model="ef.comment" type="text" data-test="ve-comment" /></div>
            <template v-if="hostDir">
              <label class="check"><input v-model="ef.watch" type="checkbox" data-test="ve-watch" /> {{ s.volumes.watch }}</label>
              <div v-if="ef.watch" class="form-2">
                <div class="field"><label for="ve-probe">{{ s.volumes.probe }}</label><select id="ve-probe" v-model="ef.probe" data-test="ve-probe"><option value="mounted">{{ s.volumes.probeMounted }}</option><option value="write">{{ s.volumes.probeWrite }}</option></select></div>
                <div class="field"><label for="ve-onloss">{{ s.volumes.onLoss }}</label><select id="ve-onloss" v-model="ef.onLoss" data-test="ve-onloss"><option value="none">{{ s.volumes.onLossNone }}</option><option value="stop">{{ s.volumes.onLossStop }}</option></select></div>
              </div>
              <p class="hint faint">{{ s.volumes.editWatchHint }}</p>
            </template>
            <template v-else>
              <div class="field"><label for="ve-size">{{ s.volumes.size }}</label><input id="ve-size" v-model.trim="ef.size" class="mono" type="text" placeholder="50G" data-test="ve-size" aria-describedby="ve-size-h" /><span id="ve-size-h" class="hint">{{ s.volumes.sizeHint }}</span></div>
              <p class="hint faint">{{ s.volumes.fixed }} ({{ s.volumes.owner }}, {{ s.volumes.mode }}, {{ s.volumes.storage }})</p>
            </template>
            <ErrorPanel v-if="editError" :error="editError" />
          </form>
          <template #footer><button class="btn" type="button" @click="editing = false">{{ s.app.cancel }}</button><button class="btn btn-primary" type="submit" form="ve" :disabled="editBusy" data-test="ve-save">{{ s.volumes.saveChanges }}</button></template>
        </Modal>
        <Modal :open="snapOpen" :title="s.volumes.snapshotTitle(vol.metadata.name)" @close="snapOpen = false">
          <form id="vs" novalidate @submit.prevent="takeSnap">
            <div class="field"><label for="vs-name">{{ s.volumes.snapshotName }}</label><input id="vs-name" v-model.trim="snapName" class="mono" type="text" autocomplete="off" data-test="vs-name" :aria-invalid="!!snapProblem" aria-describedby="vs-name-e" /><span id="vs-name-e" class="field-error" role="alert">{{ snapProblem }}</span></div>
            <div class="field"><label for="vs-comment">{{ s.volumes.comment }}</label><input id="vs-comment" v-model="snapComment" type="text" data-test="vs-comment" /></div>
            <ErrorPanel v-if="snapError" :error="snapError" />
          </form>
          <template #footer><button class="btn" type="button" @click="snapOpen = false">{{ s.app.cancel }}</button><button class="btn btn-primary" type="submit" form="vs" :disabled="snapBusy || !!snapProblem" data-test="vs-go">{{ s.volumes.snapshotTake }}</button></template>
        </Modal>
      </div>
    </LoadState>
  </div>
</template>
