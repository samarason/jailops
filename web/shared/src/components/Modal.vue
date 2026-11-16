<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { common as s } from '@jailops/shared/i18n/common'
import Icon from './Icon.vue'

const props = defineProps<{ open: boolean; title: string; wide?: boolean }>()
const emit = defineEmits<{ close: [] }>()
const box = ref<HTMLElement | null>(null)
let opener: HTMLElement | null = null
const uid = `m${Math.random().toString(36).slice(2, 8)}`

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

function onKey(e: KeyboardEvent): void {
  if (e.key === 'Escape') {
    e.stopPropagation()
    emit('close')
    return
  }
  if (e.key !== 'Tab' || !box.value) return
  const items = [...box.value.querySelectorAll<HTMLElement>(FOCUSABLE)]
  if (!items.length) return
  const first = items[0]
  const last = items[items.length - 1]
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault()
    last.focus()
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault()
    first.focus()
  }
}

watch(
  () => props.open,
  async (o) => {
    if (o) {
      opener = document.activeElement as HTMLElement | null
      await nextTick()
      const el = box.value?.querySelector<HTMLElement>('[autofocus], input, select, textarea') ?? box.value?.querySelector<HTMLElement>('.modal-close')
      el?.focus()
    } else {
      opener?.focus?.()
    }
  },
  { immediate: true },
)
onBeforeUnmount(() => opener?.focus?.())
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="modal-backdrop" @mousedown.self="emit('close')">
      <div ref="box" class="modal" :class="{ wide }" role="dialog" aria-modal="true" :aria-labelledby="uid" @keydown="onKey">
        <header>
          <h2 :id="uid">{{ title }}</h2>
          <button class="btn btn-ghost btn-icon modal-close" type="button" :aria-label="s.app.close" @click="emit('close')"><Icon name="x" /></button>
        </header>
        <div class="modal-body"><slot /></div>
        <footer v-if="$slots.footer"><slot name="footer" /></footer>
      </div>
    </div>
  </Teleport>
</template>

<style>
.modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.5); display: flex; align-items: flex-start; justify-content: center; padding: 6vh var(--gutter) var(--gutter); overflow-y: auto; z-index: 50; }
/* a long dialog scrolls its body: the header and the footer with the buttons stay in view */
.modal { background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--radius-lg); box-shadow: var(--shadow); width: min(520px, 100%); display: flex; flex-direction: column; max-height: calc(100dvh - 6vh - var(--gutter)); --tabbar-bg: var(--surface); }
.modal > header, .modal > footer { flex: none; }
.modal.wide { width: min(760px, 100%); }
.modal > header { display: flex; justify-content: space-between; align-items: center; padding: 8px 8px 8px 16px; border-bottom: 1px solid var(--border); gap: 8px; }
.modal-body { padding: 16px; overflow-y: auto; min-height: 0; flex: 1 1 auto; }
.modal > footer { display: flex; justify-content: flex-end; gap: 8px; flex-wrap: wrap; padding: 12px 16px; border-top: 1px solid var(--border); background: var(--surface-2); border-radius: 0 0 var(--radius-lg) var(--radius-lg); }
@media (max-width: 600px) { .modal-backdrop { padding-top: 12px; } .modal { max-height: calc(100dvh - 12px - var(--gutter)); } }
</style>
