<script setup lang="ts">
// The fields of a new image, shared by the Create image dialog and the wizard's base image step. The form object
// belongs to the caller (its checks too); this only edits it. The name follows the release (one image is one
// release) until it is edited by hand.
import { computed, ref, watch } from 'vue'
import { s } from '@/i18n'
import { session } from '@jailops/shared/composables/session'
import { nameHint } from '@jailops/shared/lib/names'
import { IMAGE_KINDS, ARCHES, DEFAULT_RELEASE, hostArch, hostRelease, imageNameFor, type ImageForm, type ImageKind } from '@/lib/images'
import Callout from '@jailops/shared/components/Callout.vue'

const props = defineProps<{ f: ImageForm; err: (id: string) => string; touch: (id: string) => void; kinds?: boolean; buildBox?: boolean; disabled?: boolean }>()

const host = computed(() => hostRelease(session.info))
const knownArch = computed(() => hostArch(session.info))
// the host's release is the first choice; another one is typed
const other = ref(false)
const offerHost = computed(() => props.f.kind === 'freebsd' && !!host.value)
const choice = computed({
  get: () => (offerHost.value && !other.value ? 'host' : 'other'),
  set: (v: string) => {
    other.value = v === 'other'
    props.f.release = other.value ? '' : host.value
  },
})
// another system: a release of its own; the nightly upgrade is proposed for FreeBSD
function setKind(e: Event): void {
  const k = (e.target as HTMLSelectElement).value as ImageKind
  const f = props.f
  if (k === f.kind) return
  other.value = false
  f.kind = k
  f.release = (k === 'freebsd' && host.value) || DEFAULT_RELEASE[k]
  f.auto = k === 'freebsd'
  if (k !== 'debian') f.keys = ''
}
// the proposed name follows the system and the release, unless the name was changed by hand
watch(() => [props.f.kind, props.f.release] as const, ([k, r], [wasK, wasR]) => {
  const f = props.f
  if (!f.name || f.name === imageNameFor(wasK, wasR)) f.name = imageNameFor(k, r)
})
const said = (id: string, hint: string) => (props.err(id) ? `${id}-err` : hint)
</script>

<template>
  <fieldset class="img-fields" :disabled="disabled" data-test="image-fields">
    <div v-if="kinds" class="field">
      <label for="img-kind">{{ s.imageCreate.kind }}</label>
      <select id="img-kind" :value="f.kind" data-test="image-kind" @change="setKind">
        <option v-for="k in IMAGE_KINDS" :key="k" :value="k">{{ s.imageCreate.kinds[k] }}</option>
      </select>
    </div>
    <Callout v-if="f.kind !== 'freebsd'" tone="info">{{ s.imageCreate.linuxHint }}</Callout>
    <div class="field">
      <label for="img-name">{{ s.imageCreate.name }} <span class="req" aria-hidden="true">*</span></label>
      <input id="img-name" v-model.trim="f.name" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!err('img-name')" :aria-describedby="said('img-name', 'img-name-h')" data-test="image-name" @blur="touch('img-name')" />
      <span v-if="err('img-name')" id="img-name-err" class="field-error" role="alert">{{ err('img-name') }}</span>
      <span v-else id="img-name-h" class="hint">{{ nameHint('image') }}</span>
    </div>
    <div class="field">
      <label :for="offerHost ? 'img-rel-choice' : 'img-release'">{{ s.imageCreate.release }} <span class="req" aria-hidden="true">*</span></label>
      <select v-if="offerHost" id="img-rel-choice" v-model="choice" data-test="image-release-choice" aria-describedby="img-release-h">
        <option value="host">{{ s.imageCreate.thisHost(host) }}</option>
        <option value="other">{{ s.imageCreate.other }}</option>
      </select>
      <template v-if="!offerHost || other">
        <label v-if="offerHost" for="img-release" class="sr-only">{{ s.imageCreate.otherRelease }}</label>
        <input id="img-release" v-model="f.release" class="mono img-release" type="text" autocomplete="off" spellcheck="false" :placeholder="DEFAULT_RELEASE[f.kind]" :aria-invalid="!!err('img-release')" :aria-describedby="said('img-release', 'img-release-h')" data-test="image-release" @blur="touch('img-release')" />
      </template>
      <span v-if="err('img-release')" id="img-release-err" class="field-error" role="alert">{{ err('img-release') }}</span>
      <span v-else id="img-release-h" class="hint">{{ s.imageCreate.releaseHint[f.kind] }}</span>
    </div>
    <div class="field">
      <label :for="knownArch ? 'img-arch-ro' : 'img-arch'">{{ s.imageCreate.arch }}</label>
      <input v-if="knownArch" id="img-arch-ro" :value="f.arch" class="mono" type="text" readonly aria-describedby="img-arch-h" data-test="image-arch" />
      <select v-else id="img-arch" v-model="f.arch" :aria-invalid="!!err('img-arch')" :aria-describedby="said('img-arch', 'img-arch-h')" data-test="image-arch">
        <option value="" disabled>{{ s.install.choose }}</option>
        <option v-for="a in ARCHES" :key="a" :value="a">{{ a }}</option>
      </select>
      <span v-if="err('img-arch')" id="img-arch-err" class="field-error" role="alert">{{ err('img-arch') }}</span>
      <span v-else id="img-arch-h" class="hint">{{ knownArch ? s.imageCreate.archHint : s.imageCreate.archChoose }}</span>
    </div>
    <div v-if="f.kind === 'debian'" class="field">
      <label for="img-keys">{{ s.imageCreate.keys }} <span class="req" aria-hidden="true">*</span></label>
      <input id="img-keys" v-model.trim="f.keys" class="mono" type="text" autocomplete="off" spellcheck="false" placeholder="/usr/local/share/keyrings/debian-archive-keyring.gpg" :aria-invalid="!!err('img-keys')" :aria-describedby="said('img-keys', 'img-keys-h')" data-test="image-keys" @blur="touch('img-keys')" />
      <span v-if="err('img-keys')" id="img-keys-err" class="field-error" role="alert">{{ err('img-keys') }}</span>
      <span v-else id="img-keys-h" class="hint">{{ s.imageCreate.keysHint }}</span>
    </div>
    <fieldset class="img-auto" data-test="image-auto-fields">
      <legend class="sr-only">{{ s.autoUpgrade.legend }}</legend>
      <label class="check"><input v-model="f.auto" type="checkbox" aria-describedby="img-auto-h" data-test="image-auto" />{{ s.autoUpgrade.enable }}</label>
      <span id="img-auto-h" class="hint img-build-h">{{ s.autoUpgrade.explain }}</span>
      <template v-if="f.auto">
        <div class="field img-at">
          <label for="img-at">{{ s.autoUpgrade.at }} <span class="req" aria-hidden="true">*</span></label>
          <input id="img-at" v-model="f.at" class="mono" type="time" required :aria-invalid="!!err('img-at')" :aria-describedby="said('img-at', 'img-at-h')" data-test="image-at" @blur="touch('img-at')" />
          <span v-if="err('img-at')" id="img-at-err" class="field-error" role="alert">{{ err('img-at') }}</span>
          <span v-else id="img-at-h" class="hint">{{ s.autoUpgrade.atHint }}</span>
        </div>
        <label class="check"><input v-model="f.packages" type="checkbox" data-test="image-packages" />{{ s.autoUpgrade.packages }}</label>
      </template>
    </fieldset>
    <template v-if="buildBox">
      <label class="check"><input v-model="f.build" type="checkbox" aria-describedby="img-build-h" data-test="image-build" />{{ s.imageCreate.build }}</label>
      <span id="img-build-h" class="hint img-build-h">{{ s.imageCreate.buildHint }}</span>
    </template>
  </fieldset>
</template>

<style>
.img-fields { border: 0; margin: 0; padding: 0; min-width: 0; }
.img-fields .img-release { margin-top: 6px; }
.img-fields select + .img-release { margin-top: 6px; }
.img-auto { border: 0; margin: 12px 0; padding: 0; min-width: 0; }
.img-auto .img-at { margin: 8px 0 4px; }
.img-auto .img-at input { max-width: 9em; }
.img-build-h { display: block; margin: 2px 0 0; color: var(--text-3); font-size: 12px; }
</style>
