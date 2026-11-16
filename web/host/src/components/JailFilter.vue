<script setup lang="ts">
import { computed, nextTick, ref } from 'vue'
import { s } from '@/i18n'
import { parseQuery, suggest, termText, withoutTerm, type Suggestion } from '@/lib/labels'
import Icon from '@jailops/shared/components/Icon.vue'

// The filter box of the jail list: words and label terms (lib/labels.ts), with suggestions of the keys and values the
// jails carry. Typing updates the model; a finished change (a suggestion taken, Enter, a filter removed) is a commit,
// which the list records as a step of the browser history.
const props = defineProps<{ modelValue: string; known: Map<string, Map<string, number>> }>()
const emit = defineEmits<{ 'update:modelValue': [v: string]; commit: [v: string] }>()

const el = ref<HTMLInputElement | null>(null)
const caret = ref(0)
const open = ref(false)
const active = ref(-1)
const sugg = computed<Suggestion[]>(() => (open.value ? suggest(props.modelValue, caret.value, props.known) : []))
const terms = computed(() => parseQuery(props.modelValue))
const shown = computed(() => terms.value.map((t, i) => ({ t, i })).filter((x) => x.t.kind !== 'word'))

function sync(): void {
  caret.value = el.value?.selectionStart ?? props.modelValue.length
}
function onInput(e: Event): void {
  const v = (e.target as HTMLInputElement).value
  emit('update:modelValue', v)
  open.value = true
  active.value = -1
  void nextTick(sync)
}
async function take(x: Suggestion): Promise<void> {
  emit('update:modelValue', x.value)
  // a key goes on with its value; a value finishes the term
  if (!x.value.slice(0, x.caret).endsWith('=')) emit('commit', x.value)
  active.value = -1
  await nextTick()
  el.value?.focus()
  el.value?.setSelectionRange(x.caret, x.caret)
  caret.value = x.caret
  open.value = x.value.slice(0, x.caret).endsWith('=')
}
function onKey(e: KeyboardEvent): void {
  const n = sugg.value.length
  if (e.key === 'ArrowDown' && n) {
    e.preventDefault()
    active.value = (active.value + 1) % n
  } else if (e.key === 'ArrowUp' && n) {
    e.preventDefault()
    active.value = active.value <= 0 ? n - 1 : active.value - 1
  } else if ((e.key === 'Enter' || e.key === 'Tab') && n && active.value >= 0) {
    e.preventDefault()
    void take(sugg.value[active.value])
  } else if (e.key === 'Enter') {
    open.value = false
    emit('commit', props.modelValue)
  } else if (e.key === 'Escape' && n) {
    e.preventDefault()
    e.stopPropagation()
    open.value = false
  }
}
function drop(i: number): void {
  emit('commit', withoutTerm(props.modelValue, i))
}
function blur(): void {
  // a click on a suggestion is a mousedown that keeps the focus: closing here only follows a real blur
  open.value = false
  active.value = -1
}
defineExpose({ focus: () => el.value?.focus() })
</script>

<template>
  <div class="jfilter" data-test="jail-filter">
    <div class="jf-box">
      <Icon name="search" />
      <input
        id="jails-filter" ref="el" :value="modelValue" class="jf-input mono" type="search" role="combobox" autocomplete="off" spellcheck="false" autocapitalize="off"
        :placeholder="s.jails.filter" :aria-label="s.jails.filter" aria-autocomplete="list" :aria-expanded="sugg.length > 0" aria-controls="jf-sugg"
        :aria-activedescendant="active >= 0 && sugg.length ? `jf-s-${active}` : undefined" aria-describedby="jf-hint" data-test="jails-filter"
        @input="onInput" @keydown="onKey" @click="sync(); open = true" @keyup="sync" @focus="sync(); open = true" @blur="blur"
      />
    </div>
    <ul v-if="sugg.length" id="jf-sugg" class="jf-sugg" role="listbox" :aria-label="s.filter.suggestions" data-test="filter-suggestions">
      <li v-for="(x, i) in sugg" :id="`jf-s-${i}`" :key="x.text" role="option" :aria-selected="i === active" class="jf-opt" :data-sugg="x.text" @mousedown.prevent="take(x)">
        <span class="mono">{{ x.text }}</span><span class="faint jf-count">{{ s.filter.jailsCount(x.count) }}</span>
      </li>
    </ul>
    <p id="jf-hint" class="jf-hint faint">{{ s.filter.hint }}</p>
    <div v-if="shown.length" class="jf-terms" role="group" :aria-label="s.filter.active" data-test="filter-terms">
      <span v-for="x in shown" :key="x.i" class="lchip jf-term" :class="{ neg: x.t.not }" :data-term="termText(x.t)">
        <span class="lv">{{ termText(x.t) }}</span>
        <button class="lx" type="button" :aria-label="s.filter.removeTerm(termText(x.t))" @click="drop(x.i)"><Icon name="x" /></button>
      </span>
    </div>
  </div>
</template>

<style>
.jfilter { position: relative; flex: 1 1 320px; max-width: 520px; min-width: 0; }
.jf-box { display: flex; align-items: center; gap: 8px; padding: 0 10px; border: 1px solid var(--border-strong); border-radius: var(--radius); background: var(--surface); color: var(--text-3); }
.jf-box:focus-within { outline: 2px solid var(--focus); outline-offset: 1px; }
.jf-box .jf-input { flex: 1; min-width: 0; border: 0; background: transparent; padding: 6px 0; font-size: 13px; color: var(--text); box-shadow: none; }
.jf-box .jf-input:focus { outline: none; box-shadow: none; }
.jf-sugg { position: absolute; z-index: 15; left: 0; right: 0; top: 36px; margin: 0; padding: 4px; list-style: none; background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--radius); box-shadow: var(--shadow); max-height: 260px; overflow-y: auto; }
.jf-opt { display: flex; justify-content: space-between; gap: 12px; padding: 6px 8px; border-radius: var(--radius); cursor: pointer; font-size: 13px; min-height: 32px; align-items: center; }
.jf-opt[aria-selected='true'], .jf-opt:hover { background: var(--accent-soft); }
.jf-count { font-size: 12px; }
.jf-hint { margin: 4px 0 0; font-size: 12px; line-height: 1.4; }
.jf-terms { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
.jf-term .lv { border-left: 0; background: var(--accent-soft); color: var(--text); padding-left: 8px; }
.jf-term.neg .lv { background: var(--danger-bg); }
</style>
