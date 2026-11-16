<script setup lang="ts" generic="T extends string">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { nextTab, focusTab } from '../composables/tabs'

// A tab list with a roving tabindex: one Tab stop, arrows, Home and End move between tabs. On a narrow screen the
// bar scrolls sideways; a fade with an arrow shows that more tabs are there, and the selected tab is kept in view.
export interface TabItem<K extends string = string> { key: K; label: string; count?: number }
const props = defineProps<{ tabs: TabItem<T>[]; modelValue: T; label: string; id: string }>()
const emit = defineEmits<{ 'update:modelValue': [T] }>()
const root = ref<HTMLElement | null>(null)
const more = ref({ left: false, right: false })
const keys = computed(() => props.tabs.map((t) => t.key))

function measure(): void {
  const el = root.value
  if (!el) return
  more.value = { left: el.scrollLeft > 2, right: el.scrollLeft + el.clientWidth < el.scrollWidth - 2 }
}
function onKey(e: KeyboardEvent): void {
  const n = nextTab(keys.value, props.modelValue, e.key)
  if (!n) return
  e.preventDefault()
  emit('update:modelValue', n)
  void focusTab(root.value, n)
}
function scrollBy(dir: number): void {
  root.value?.scrollBy({ left: dir * Math.max(120, (root.value?.clientWidth ?? 0) * 0.6), behavior: 'smooth' })
}
watch(() => props.modelValue, async (k) => {
  await nextTick()
  root.value?.querySelector<HTMLElement>(`[data-tab="${k}"]`)?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' })
  measure()
}, { immediate: true })
watch(() => props.tabs.length, () => void nextTick(measure))
let ro: ResizeObserver | undefined
onMounted(() => {
  measure()
  if (typeof ResizeObserver !== 'undefined' && root.value) {
    ro = new ResizeObserver(measure)
    ro.observe(root.value)
  }
})
onBeforeUnmount(() => ro?.disconnect())
</script>

<template>
  <div class="tabbar" :class="{ 'more-left': more.left, 'more-right': more.right }">
    <button v-if="more.left" class="tab-more tab-more-left" type="button" tabindex="-1" aria-hidden="true" @click="scrollBy(-1)">‹</button>
    <div ref="root" class="tabs" role="tablist" :aria-label="label" @keydown="onKey" @scroll.passive="measure">
      <button v-for="t in tabs" :id="`${id}-tab-${t.key}`" :key="t.key" type="button" role="tab" :aria-controls="`${id}-panel`" :aria-selected="modelValue === t.key" :tabindex="modelValue === t.key ? 0 : -1" :data-tab="t.key" @click="emit('update:modelValue', t.key)">{{ t.label }}<span v-if="t.count" class="tab-n">{{ t.count }}</span></button>
    </div>
    <button v-if="more.right" class="tab-more tab-more-right" type="button" tabindex="-1" aria-hidden="true" @click="scrollBy(1)">›</button>
  </div>
</template>

<style>
.tabbar { position: relative; margin-bottom: 12px; }
.tabbar > .tabs { margin-bottom: 0; scrollbar-width: none; scroll-behavior: smooth; }
.tabbar > .tabs::-webkit-scrollbar { display: none; }
.tab-n { margin-left: 6px; padding: 0 6px; border-radius: 999px; background: var(--surface-3); color: var(--text-2); font-size: 12px; font-weight: 500; }
.tab-more { position: absolute; top: 0; bottom: 1px; width: 36px; border: 0; padding: 0; cursor: pointer; font-size: 20px; line-height: 1; color: var(--text); z-index: 1; }
.tab-more-left { left: 0; text-align: left; padding-left: 4px; background: linear-gradient(to right, var(--tabbar-bg, var(--bg)) 55%, transparent); }
.tab-more-right { right: 0; text-align: right; padding-right: 4px; background: linear-gradient(to left, var(--tabbar-bg, var(--bg)) 55%, transparent); }
</style>
