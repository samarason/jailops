<script setup lang="ts">
import { computed } from 'vue'
import { s } from '@/i18n'
import { hasExt } from '@jailops/shared/composables/session'
import { useTabQuery } from '@jailops/shared/composables/tabs'
import { isGlobalAdmin } from '@/composables/project'
import TabBar from '@jailops/shared/components/TabBar.vue'
import UnifiedLogs from '@/components/UnifiedLogs.vue'
import LogForwardPanel from '@/components/LogForwardPanel.vue'

// Two sections: the merged lines of many jails, and (for a global admin) where the host forwards them. The section
// is kept in ?tab= (the shared tab pattern); the filters of the lines keep their own query keys.
type Tab = 'lines' | 'forwarding'
const canForward = computed(() => hasExt('log_forward') && isGlobalAdmin())
const { tab } = useTabQuery<Tab>(() => (canForward.value ? ['lines', 'forwarding'] : ['lines']), 'lines')
const tabs = computed(() => [{ key: 'lines' as Tab, label: s.ulogs.viewTab }, { key: 'forwarding' as Tab, label: s.ulogs.forwardTab }])
</script>

<template>
  <div>
    <div class="page-head">
      <div><h1>{{ s.ulogs.title }}</h1><p class="muted">{{ s.ulogs.lead }}</p></div>
    </div>
    <TabBar v-if="canForward" v-model="tab" :tabs="tabs" :label="s.ulogs.sections" id="logs" />
    <div id="logs-panel" :role="canForward ? 'tabpanel' : undefined" :aria-labelledby="canForward ? `logs-tab-${tab}` : undefined">
      <LogForwardPanel v-if="tab === 'forwarding'" />
      <UnifiedLogs v-else />
    </div>
  </div>
</template>
