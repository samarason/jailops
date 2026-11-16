<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { can } from '@jailops/shared/composables/session'
import { runOp } from '@jailops/shared/composables/ops'
import { confirmAction } from '@jailops/shared/composables/confirm'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import ConfirmDialog from '@jailops/shared/components/ConfirmDialog.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import ImageCreateDialog from '@/components/ImageCreateDialog.vue'
import ImageAutoUpgrade from '@/components/ImageAutoUpgrade.vue'
import NewReleaseNotice from '@/components/NewReleaseNotice.vue'
import { isGlobalAdmin } from '@/composables/project'
import RenameDialog from '@/components/RenameDialog.vue'
import { canRename } from '@/composables/rename'
import { ifMatch } from '@/lib/rename'
import type { Image } from '@jailops/shared/api/types'

const l = useLoad(() => api.images.list())
// Rename (extension rename, global admin): the jails and projects that name the image follow
const renaming = ref<Image | null>(null)

// Create image: the page head's button, the empty page's first action, and /images?create=1 (the wizard and the
// install dialog link here).
const route = useRoute()
const router = useRouter()
const mayCreate = () => can('images') && isGlobalAdmin()
const creating = ref(false)
watch(() => route.query.create, (c) => {
  if (c === undefined) return
  if (mayCreate()) creating.value = true
  void router.replace({ query: { ...route.query, create: undefined } })
}, { immediate: true })

function aliasesOf(img: Image, n: number): string[] {
  return Object.entries(img.status.aliases ?? {}).filter(([, g]) => g === n).map(([a]) => a)
}
/** Every jail on any generation of the image (the server's used-by data). */
function jailsOn(img: Image): string[] {
  return [...new Set((img.status.generations ?? []).flatMap((g) => g.refs ?? []))].sort()
}
// Building and upgrading are tier 2: they ask first and name the jails on the image.
function build(img: Image): void {
  const last = Math.max(0, ...(img.status.generations ?? []).map((g) => g.number))
  const n = img.metadata.name
  confirmAction({
    title: s.images.buildTitle(n), confirmLabel: s.images.build, text: s.images.buildText, items: jailsOn(img), itemsLabel: s.images.jailsOnImage,
    run: () => runOp(`${s.images.build}: ${n}`, () => api.images.build(n, { from_generation: last || undefined })),
  })
}
function upgrade(img: Image): void {
  const n = img.metadata.name
  const jails = jailsOn(img)
  confirmAction({
    title: s.images.upgradeTitle(n), confirmLabel: s.images.upgrade, text: jails.length ? s.images.upgradeText : s.images.noJails, items: jails, itemsLabel: s.images.jailsOnImage,
    run: () => runOp(`${s.images.upgrade}: ${n}`, () => api.images.upgrade(n, {})),
  })
}

// Aliases are an advanced feature of the CLI: the page shows the ones there are and removes them, and sets none.
const removingAlias = ref<{ image: string; alias: string } | null>(null)
const removeAlias = () => runOp(s.images.deleteAliasTitle(removingAlias.value!.alias), () => api.images.deleteAlias(removingAlias.value!.image, removingAlias.value!.alias))
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.images.title }}</h1><button v-if="mayCreate() && l.data.value?.length" class="btn btn-primary" type="button" data-test="image-new" @click="creating = true"><Icon name="plus" />{{ s.imageCreate.open }}</button></div>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <p v-if="l.data.value?.length" class="muted img-lead">{{ s.images.lead }}</p>
      <NewReleaseNotice :images="l.data.value ?? undefined" :may-create="mayCreate()" class="img-new" @create="creating = true" />
      <section v-if="!l.data.value?.length" class="panel img-empty" data-test="images-empty">
        <div class="body stack">
          <h2>{{ s.images.emptyTitle }}</h2>
          <p class="muted">{{ s.images.emptyText }}</p>
          <div v-if="mayCreate()" class="row"><button class="btn btn-primary" type="button" data-test="image-new-empty" @click="creating = true"><Icon name="plus" />{{ s.imageCreate.openBase }}</button></div>
          <p v-else class="faint">{{ s.imageCreate.noImageAsk }}</p>
        </div>
      </section>
      <div class="stack">
        <section v-for="img in l.data.value" :key="img.metadata.name" class="panel" :data-image="img.metadata.name">
          <header>
            <div class="row">
              <h2 class="mono">{{ img.metadata.name }}</h2>
              <span class="faint" data-test="image-release">{{ s.images.release(img.spec.release) }} <span class="mono">{{ img.spec.os }} {{ img.spec.arch }}</span> · {{ s.images.gens(img.status.generations?.length ?? 0) }}</span>
              <span v-for="(g, a) in img.status.aliases" :key="a" class="pill info">{{ a }} = g{{ g }}<button v-if="can('image_aliases')" class="btn btn-sm" type="button" :title="s.images.deleteAlias" :aria-label="s.images.deleteAlias" :data-test="`delete-alias-${a}`" style="margin-left: 4px" @click="removingAlias = { image: img.metadata.name, alias: String(a) }"><Icon name="x" /></button></span>
            </div>
            <div class="row-actions">
              <button v-if="can('generations')" class="btn btn-sm" type="button" :data-test="`build-${img.metadata.name}`" @click="build(img)"><Icon name="plus" />{{ s.images.build }}</button>
              <button v-if="can('image_upgrade')" class="btn btn-sm" type="button" :title="s.images.upgradeHint" :data-test="`upgrade-${img.metadata.name}`" @click="upgrade(img)"><Icon name="play" />{{ s.images.upgrade }}</button>
              <button v-if="canRename('image')" class="btn btn-sm" type="button" :data-test="`rename-image-${img.metadata.name}`" @click="renaming = img">{{ s.rename.open(s.rename.kinds.image) }}</button>
            </div>
          </header>
          <div class="body muted">
            {{ s.images.source }}: <span class="mono img-src">{{ img.spec.source.type }}<template v-if="img.spec.source.repo"> · {{ img.spec.source.repo }}</template></span>
            <span v-if="img.spec.retention?.keep_last || img.spec.retention?.keep_days"> · {{ s.images.retention }}: {{ s.images.keep(img.spec.retention.keep_last ?? 0, img.spec.retention.keep_days ?? 0) }}</span>
          </div>
          <p v-if="!img.status.generations?.length" class="body faint" data-test="image-no-generation">{{ s.images.noBuild }}</p>
          <div v-else class="table-wrap">
            <table class="rtable">
              <thead><tr><th>{{ s.images.generations }}</th><th>{{ s.images.created }}</th><th>{{ s.images.freebsd }}</th><th class="hide-sm">{{ s.images.manifest }}</th><th class="num">{{ s.images.packagesCol }}</th><th>{{ s.images.usedBy }}</th></tr></thead>
              <tbody>
                <tr v-for="g in [...(img.status.generations ?? [])].sort((a, b) => b.number - a.number)" :key="g.number">
                  <td class="nowrap" :data-label="s.images.generations"><span class="mono">g{{ g.number }}</span> <span v-if="g.parent" class="faint">{{ s.images.parent(g.parent) }}</span><span v-for="a in aliasesOf(img, g.number)" :key="a" class="pill info" style="margin-left: 6px">{{ a }}</span></td>
                  <td class="faint" :data-label="s.images.created"><TimeStamp :ts="g.created_at" /></td>
                  <td class="mono" :data-label="s.images.freebsd" :title="s.images.freebsdHint" data-test="generation-freebsd">{{ g.freebsd_version || '-' }}</td>
                  <td class="mono faint hide-sm" :data-label="s.images.manifest" :title="g.manifest">{{ g.manifest.slice(0, 12) }}</td>
                  <td class="num" :data-label="s.images.packagesCol">{{ g.packages ?? '-' }}</td>
                  <td :data-label="s.images.usedBy">
                    <span v-if="!g.refs?.length" class="faint">{{ s.images.unused }}</span>
                    <template v-else><router-link v-for="r in g.refs" :key="r" class="mono refl" :to="`/jails/${r}`">{{ r }}</router-link></template>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <ImageAutoUpgrade v-if="can('image_upgrade')" :image="img" :editable="mayCreate()" @saved="l.reload" />
        </section>
      </div>
    </LoadState>
    <RenameDialog :open="!!renaming" kind="image" :name="renaming?.metadata.name ?? ''" :etag="ifMatch(renaming?.metadata.generation)" @close="renaming = null" @done="l.reload" />
    <ImageCreateDialog :open="creating" @close="creating = false" @done="l.reload" />
    <ConfirmDialog :open="!!removingAlias" :title="s.images.deleteAliasTitle(removingAlias?.alias ?? '')" :confirm-label="s.images.deleteAlias" danger :run="removeAlias" @close="removingAlias = null" @done="l.reload"><Callout tone="warn">{{ s.images.deleteAliasText }}</Callout></ConfirmDialog>
  </div>
</template>

<style>
.refl { margin-right: 10px; }
.img-src { overflow-wrap: anywhere; }
.img-lead { margin: 0 0 12px; max-width: 80ch; }
.img-new { margin-bottom: 12px; }
.img-empty h2 { font-size: 16px; margin: 0; }
.img-empty p { margin: 0; max-width: 70ch; }
</style>
