<script setup lang="ts">
// The host runs a newer FreeBSD release than every image: a quiet notice that offers the image of that release. A
// new release is a new image; the jails that exist stay on theirs. Nothing shows while the images are not known.
import { computed } from 'vue'
import { s } from '@/i18n'
import { session } from '@jailops/shared/composables/session'
import { newHostRelease } from '@/lib/images'
import Callout from '@jailops/shared/components/Callout.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import type { Image } from '@jailops/shared/api/types'

const props = defineProps<{ images: Image[] | undefined; mayCreate: boolean }>()
const emit = defineEmits<{ create: [] }>()
const release = computed(() => (props.images ? newHostRelease(props.images, session.info) : ''))
</script>

<template>
  <Callout v-if="release" tone="info" data-test="new-release">
    <p class="nr-text">{{ s.images.newRelease(release) }} {{ s.images.newReleaseWhy }}</p>
    <div v-if="mayCreate" class="row nr-row"><button class="btn btn-sm" type="button" data-test="new-release-go" @click="emit('create')"><Icon name="plus" />{{ s.images.newReleaseGo(release) }}</button></div>
    <p v-else class="faint nr-text">{{ s.images.newReleaseAsk }}</p>
  </Callout>
</template>

<style>
.nr-text { margin: 0; }
.nr-row { margin-top: 8px; }
</style>
