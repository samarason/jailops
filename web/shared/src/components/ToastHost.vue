<script setup lang="ts">
import { ref } from 'vue'
import { common as s } from '@jailops/shared/i18n/common'
import { toasts, dismiss, cancelToast, holdToast, releaseToast } from '@jailops/shared/composables/ops'
import Icon from './Icon.vue'
import ErrorPanel from './ErrorPanel.vue'

const open = ref<Record<number, boolean>>({})
// Escape on a focused toast closes it; focus goes back to the page.
function onKey(e: KeyboardEvent, id: number): void {
  if (e.key !== 'Escape') return
  e.stopPropagation()
  dismiss(id)
  ;(document.getElementById('main') as HTMLElement | null)?.focus()
}
</script>

<template>
  <section class="toasts" :aria-label="s.toast.region" aria-live="polite">
    <article v-for="t in toasts" :key="t.id" class="toast" :class="t.status" :data-status="t.status" @mouseenter="holdToast(t.id)" @mouseleave="releaseToast(t.id)" @focusin="holdToast(t.id)" @focusout="releaseToast(t.id)" @keydown="onKey($event, t.id)">
      <div class="row">
        <Icon :name="t.status === 'failure' ? 'alertCircle' : t.status === 'success' ? 'checkCircle' : 'info'" />
        <strong class="grow toast-title">{{ t.title }}</strong>
        <span class="muted">{{ s.toast[t.status] }}</span>
        <button v-if="t.mayCancel" class="btn btn-sm" type="button" @click="cancelToast(t)">{{ s.toast.cancel }}</button>
        <button class="btn btn-ghost btn-icon btn-sm" type="button" :aria-label="s.error.dismiss" @click="dismiss(t.id)"><Icon name="x" /></button>
      </div>
      <div v-if="t.status === 'running'" class="meter" role="progressbar" :aria-valuenow="t.progress" aria-valuemin="0" aria-valuemax="100" :aria-label="t.title">
        <span :style="{ width: Math.max(4, t.progress) + '%' }"></span>
      </div>
      <template v-if="t.error">
        <p class="muted" style="margin: 6px 0 0; overflow-wrap: anywhere">{{ t.error.message }}</p>
        <button class="btn btn-sm" type="button" :aria-expanded="!!open[t.id]" @click="open[t.id] = !open[t.id]">{{ s.error.details }}</button>
        <div v-if="open[t.id]" style="margin-top: 6px"><ErrorPanel :error="t.error" /></div>
      </template>
    </article>
  </section>
</template>

<style>
.toasts { position: fixed; right: var(--gutter); bottom: var(--gutter); z-index: 60; display: grid; gap: 8px; width: min(380px, calc(100vw - 2 * var(--gutter))); }
.toast-title { overflow-wrap: anywhere; }
.toast .row { flex-wrap: nowrap; align-items: flex-start; }
.toast { max-height: 50vh; overflow-y: auto; background: var(--surface); border: 1px solid var(--border-strong); border-left-width: 4px; border-radius: var(--radius); box-shadow: var(--shadow); padding: 8px 10px; }
.toast.running { border-left-color: var(--info); }
.toast.success { border-left-color: var(--ok); }
.toast.failure { border-left-color: var(--danger); }
.toast .meter { margin-top: 6px; }
</style>
