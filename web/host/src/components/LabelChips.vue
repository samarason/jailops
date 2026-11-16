<script setup lang="ts">
import { computed, ref } from 'vue'
import { s } from '@/i18n'
import { chipOrder, labelText, type Labels } from '@/lib/labels'

// A jail's labels as chips: the first `max`, then a +N that shows the rest. With `pick` every chip is a button that
// filters by its label; without it the chips are plain text (the quick switcher's rows, where the row is the button).
const props = withDefaults(defineProps<{ labels?: Labels; max?: number; pick?: boolean }>(), { labels: () => ({}), max: 3, pick: false })
const emit = defineEmits<{ pick: [key: string, value: string] }>()
const all = ref(false)
const list = computed(() => chipOrder(props.labels))
const shown = computed(() => (all.value ? list.value : list.value.slice(0, props.max)))
const rest = computed(() => list.value.length - shown.value.length)
</script>

<template>
  <span v-if="list.length" class="lchips" data-test="label-chips">
    <template v-for="[k, v] in shown" :key="k">
      <button v-if="pick" class="lchip" type="button" :title="labelText(k, v)" :aria-label="s.labels.filterBy(labelText(k, v))" :data-label="labelText(k, v)" @click="emit('pick', k, v)"><span class="lk">{{ k }}</span><span class="lv">{{ v }}</span></button>
      <span v-else class="lchip" :title="labelText(k, v)" :data-label="labelText(k, v)"><span class="lk">{{ k }}</span><span class="lv">{{ v }}</span></span>
    </template>
    <button v-if="rest > 0 && pick" class="lchip lmore" type="button" :aria-label="s.labels.moreTitle(rest)" :title="s.labels.moreTitle(rest)" data-test="labels-more" @click="all = true">{{ s.labels.more(rest) }}</button>
    <span v-else-if="rest > 0" class="lchip lmore" :title="s.labels.moreTitle(rest)">{{ s.labels.more(rest) }}</span>
    <button v-if="all && pick && list.length > max" class="lchip lmore" type="button" @click="all = false">{{ s.labels.less }}</button>
  </span>
</template>

<style>
.lchips { display: inline-flex; flex-wrap: wrap; gap: 4px; min-width: 0; max-width: 100%; vertical-align: middle; }
.lchip { display: inline-flex; align-items: stretch; max-width: 220px; min-height: 24px; padding: 0; border: 1px solid var(--border-strong); border-radius: 999px; background: var(--surface-2); color: var(--text-2); font: 12px/22px var(--font-mono); overflow: hidden; white-space: nowrap; }
.lchip .lk { padding: 0 4px 0 8px; color: var(--text-2); }
.lchip .lv { padding: 0 8px 0 4px; background: var(--surface); color: var(--text); overflow: hidden; text-overflow: ellipsis; border-left: 1px solid var(--border); }
.lchip.lmore { padding: 0 8px; color: var(--text-2); font-family: var(--font-sans); }
button.lchip { cursor: pointer; }
button.lchip:hover { border-color: var(--accent); }
button.lchip:hover .lv { color: var(--accent); }
button.lchip:focus-visible { outline: 2px solid var(--focus); outline-offset: 1px; }
</style>
