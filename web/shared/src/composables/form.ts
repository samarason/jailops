import { computed, nextTick, ref } from 'vue'

/**
 * Field checks of a form, the same way in every dialog: each field id maps to its problem (empty when fine). A field
 * shows its message once it was touched or a submit was tried; the primary button is never silently disabled: it
 * stays clickable (aria-disabled while something is missing), `reason` says what is missing next to it, and a
 * submit focuses the first field with a problem.
 */
export function useFormCheck(problems: () => Record<string, string>) {
  const tried = ref(false)
  const touched = ref<Record<string, boolean>>({})
  const all = computed(problems)
  const firstId = computed(() => Object.keys(all.value).find((k) => !!all.value[k]) ?? '')
  const ok = computed(() => !firstId.value)
  /** The message under a field: shown after a submit attempt or once the field was left. */
  function err(id: string): string {
    return tried.value || touched.value[id] ? all.value[id] ?? '' : ''
  }
  function touch(id: string): void {
    touched.value = { ...touched.value, [id]: true }
  }
  /** The first missing item, for the text next to the button. */
  const reason = computed(() => (firstId.value ? all.value[firstId.value] : ''))
  /** Run fn when the form is complete; else show every message and focus the first field with a problem. */
  async function submit(fn: () => unknown): Promise<void> {
    tried.value = true
    if (!ok.value) {
      await nextTick()
      const el = document.getElementById(firstId.value)
      el?.focus()
      return
    }
    await fn()
  }
  function reset(): void {
    tried.value = false
    touched.value = {}
  }
  return { tried, ok, err, touch, reason, submit, reset, firstId }
}
