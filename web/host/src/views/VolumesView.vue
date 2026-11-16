<script setup lang="ts">
import { ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { confirmAction } from '@jailops/shared/composables/confirm'
import { bytes } from '@jailops/shared/lib/format'
import Icon from '@jailops/shared/components/Icon.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import VolumeCreateDialog from '@/components/VolumeCreateDialog.vue'
import { isHostDir, isLost, volumeLoss } from '@/lib/volumes'
import type { Volume } from '@jailops/shared/api/types'

const l = useLoad(() => api.volumes.list())
const creating = ref(false)

// data loss: the name is typed, and the sizes are read from the server first
async function remove(v: Volume): Promise<void> {
  const n = v.metadata.name
  if (isHostDir(v)) {
    // nothing is destroyed: the volume is forgotten and the directory stays as it is
    confirmAction({
      title: s.volumes.deleteHostDirTitle(n), confirmLabel: s.volumes.forget, text: s.volumes.deleteHostDirText,
      run: () => runOp(s.volumes.deleteHostDirTitle(n), () => api.volumes.remove(n)),
      done: () => void l.reload(),
    })
    return
  }
  const snaps = await api.volumes.snapshots(n).catch(() => [])
  confirmAction({
    title: s.volumes.deleteTitle(n), confirmLabel: s.volumes.deleteVolume, text: s.volumes.deleteText, items: volumeLoss(v, snaps.length), itemsLabel: s.volumes.destroyed,
    typeName: n, typeLabel: s.volumes.typeName(n), danger: true,
    run: () => runOp(s.volumes.deleteTitle(n), () => api.volumes.remove(n)),
    done: () => void l.reload(),
  })
}
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.volumes.title }}</h1><button class="btn btn-primary" type="button" data-test="new-volume" @click="creating = true"><Icon name="plus" />{{ s.volumes.create }}</button></div>
    <p class="muted">{{ s.volumes.lead }}</p>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div class="panel">
        <p v-if="!l.data.value?.length" class="empty" data-test="volumes-empty">{{ s.volumes.empty }}</p>
        <div v-else class="table-wrap"><table data-test="volumes-table" class="rtable">
          <thead><tr><th>{{ s.volumes.name }}</th><th class="hide-sm">{{ s.volumes.storage }}</th><th>{{ s.volumes.used }}</th><th class="hide-sm">{{ s.volumes.owner }}</th><th class="hide-sm">{{ s.volumes.mode }}</th><th>{{ s.volumes.attachedTo }}</th><th><span class="sr-only">{{ s.app.actions }}</span></th></tr></thead>
          <tbody><tr v-for="v in l.data.value" :key="v.metadata.name" :data-volume="v.metadata.name">
            <td :data-label="s.volumes.name"><router-link class="mono" :to="`/volumes/${encodeURIComponent(v.metadata.name)}`" :aria-label="s.volumes.open(v.metadata.name)">{{ v.metadata.name }}</router-link>
              <span v-if="v.spec.encrypted" class="badge" :class="v.status?.locked ? 'warn' : 'info'" style="margin-left: 6px">{{ v.status?.locked ? s.volumes.locked : s.volumes.encrypted }}</span>
              <span v-if="isHostDir(v)" class="badge" :class="isLost(v) ? 'warn' : 'info'" style="margin-left: 6px" data-test="volume-state">{{ isLost(v) ? s.volumes.stateLost : s.volumes.hostDirBadge }}</span>
              <div v-if="v.spec.comment" class="faint">{{ v.spec.comment }}</div></td>
            <td class="mono hide-sm" :data-label="s.volumes.storage">{{ v.spec.path || v.spec.storage || '-' }}</td>
            <td class="mono" :data-label="s.volumes.used"><template v-if="isHostDir(v)">-</template><template v-else>{{ bytes(v.status?.used ?? 0) }}<span v-if="v.spec.size" class="faint"> / {{ v.spec.size }}</span></template></td>
            <td class="mono hide-sm" :data-label="s.volumes.owner">{{ isHostDir(v) ? '-' : `${v.spec.uid}:${v.spec.gid}` }}</td>
            <td class="mono hide-sm" :data-label="s.volumes.mode">{{ isHostDir(v) ? '-' : v.spec.mode || '-' }}</td>
            <td :data-label="s.volumes.attachedTo"><span v-if="!v.status?.attached_to?.length" class="faint">{{ s.volumes.none }}</span>
              <router-link v-for="u in v.status?.attached_to ?? []" :key="u.jail" class="mono chip" :to="`/jails/${encodeURIComponent(u.jail)}`">{{ u.jail }}<span v-if="u.read_only" class="faint"> ({{ s.volumes.readOnly }})</span></router-link>
              <div v-for="w in v.status?.warnings ?? []" :key="w" class="faint" data-test="volume-warning">{{ w }}</div></td>
            <td class="actions"><div class="row-actions"><button class="btn btn-sm btn-danger" type="button" :data-delete="v.metadata.name" @click="remove(v)">{{ isHostDir(v) ? s.volumes.forget : s.volumes.deleteVolume }}</button></div></td>
          </tr></tbody></table></div>
      </div>
    </LoadState>
    <VolumeCreateDialog :open="creating" @close="creating = false" @done="l.reload" />
  </div>
</template>
