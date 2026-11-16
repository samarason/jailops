<script setup lang="ts">
import { computed } from 'vue'
import { ago, stamp } from '../lib/format'

// One time format: ISO date and time in UTC, the relative form in the tooltip.
const props = defineProps<{ ts: string | undefined | null; seconds?: boolean }>()
const text = computed(() => stamp(props.ts ?? undefined, props.seconds))
const rel = computed(() => ago(props.ts ?? undefined))
</script>

<template>
  <span v-if="text === '-'" class="faint">-</span>
  <time v-else class="ts" :datetime="ts ?? undefined" :title="rel">{{ text }}</time>
</template>

<style>
.ts { white-space: nowrap; }
</style>
