<script setup lang="ts">
import { computed } from 'vue'
import { noteBlocks } from '@/lib/apps'

// The notes of an app definition: prose, list items and commands kept apart.
const props = defineProps<{ text: string | undefined }>()
const blocks = computed(() => noteBlocks(props.text))
</script>

<template>
  <div class="notes-text">
    <template v-for="(b, i) in blocks" :key="i">
      <pre v-if="b.kind === 'pre'" class="notes-pre">{{ b.text }}</pre>
      <p v-else><template v-for="(p, k) in b.parts" :key="k"><code v-if="p.code" class="notes-code">{{ p.text }}</code><template v-else>{{ p.text }}</template></template></p>
    </template>
  </div>
</template>

<style>
.notes-text p { margin: 0 0 8px; }
.notes-text > :last-child { margin-bottom: 0; }
.notes-pre { margin: 0 0 8px; padding: 6px 10px; background: var(--surface-3); border-radius: var(--radius); font-family: var(--font-mono); font-size: 12.5px; white-space: pre; overflow-x: auto; }
.notes-code { padding: 0 4px; background: var(--surface-3); border-radius: 3px; overflow-wrap: anywhere; }
</style>
