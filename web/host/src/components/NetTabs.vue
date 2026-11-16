<script setup lang="ts">
import { s } from '@/i18n'
import { hasExt } from '@jailops/shared/composables/session'
</script>

<template>
  <!-- The sections of the Networks area: links, so each one has its own address. -->
  <nav v-if="hasExt('wireguard')" class="tabs" :aria-label="s.networks.sections" data-test="net-tabs">
    <router-link to="/networks" data-tab="networks">{{ s.networks.tabNetworks }}</router-link>
    <router-link to="/networks/wireguard" data-tab="wireguard">{{ s.networks.tabWireGuard }}</router-link>
  </nav>
</template>
