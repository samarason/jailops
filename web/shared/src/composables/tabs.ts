import { computed, nextTick, ref, watch, type ComputedRef, type Ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

/**
 * The selected tab of a page, kept in ?tab= so a link, a reload and the back button land on it. The default tab is
 * left out of the address. A tab that is not offered (yet) falls back to the default; when it appears later (the jail
 * turns out to be an app) a ?tab= that names it is honoured then.
 */
export function useTabQuery<T extends string>(tabs: Ref<readonly T[]> | ComputedRef<readonly T[]> | (() => readonly T[]), fallback: T | (() => T), key = 'tab') {
  const route = useRoute()
  const router = useRouter()
  const list = computed(() => (typeof tabs === 'function' ? tabs() : tabs.value))
  const def = () => (typeof fallback === 'function' ? fallback() : fallback)
  const wanted = () => (typeof route.query[key] === 'string' ? (route.query[key] as T) : undefined)
  const pick = (): T => {
    const w = wanted()
    return w && list.value.includes(w) ? w : def()
  }
  const tab = ref(pick()) as Ref<T>
  // a tab that arrives later, or a ?tab= changed by a link on the same page
  watch([list, () => route.query[key]], () => {
    const w = wanted()
    if (w && w !== tab.value && list.value.includes(w)) tab.value = w
    else if (!list.value.includes(tab.value)) tab.value = def()
  })
  watch(tab, (t) => {
    if ((wanted() ?? def()) === t) return
    const { [key]: _drop, ...rest } = route.query
    void router.replace({ query: t === def() ? rest : { ...rest, [key]: t } })
  })
  function select(t: T): void {
    tab.value = t
  }
  return { tab, select, tabs: list }
}

/** Arrow keys, Home and End over a tab list (the roving tabindex of the ARIA tabs pattern). Returns the new tab. */
export function nextTab<T extends string>(tabs: readonly T[], current: T, key: string): T | undefined {
  const i = tabs.indexOf(current)
  if (i < 0 || !tabs.length) return undefined
  switch (key) {
    case 'ArrowRight': return tabs[(i + 1) % tabs.length]
    case 'ArrowLeft': return tabs[(i - 1 + tabs.length) % tabs.length]
    case 'Home': return tabs[0]
    case 'End': return tabs[tabs.length - 1]
  }
  return undefined
}

export async function focusTab(root: HTMLElement | null, key: string): Promise<void> {
  await nextTick()
  const el = root?.querySelector<HTMLElement>(`[data-tab="${key}"]`)
  el?.focus()
  el?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' })
}
