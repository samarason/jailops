<script setup lang="ts">
import { s } from '@/i18n'

// Which encrypted volumes of a jail wait for their passphrase: a line under the one Locked state, not a second badge.
defineProps<{ volumes: string[]; jail: string }>()
</script>

<template>
  <span class="lock-vols" :data-locked="jail" :title="s.keys.lockedHint">{{ s.jails.lockedVolumes(volumes) }}</span>
</template>

<style>
.lock-vols { display: block; margin-top: 2px; font-size: 12px; color: var(--text-2); }
</style>
