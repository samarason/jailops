import { describe, expect, it, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import ConfirmDialog from './ConfirmDialog.vue'
import TabBar from './TabBar.vue'
import { useTabQuery } from '../composables/tabs'

describe('ConfirmDialog', () => {
  it('tier 3: the action runs only after the name is typed, and says why not', async () => {
    const run = vi.fn(() => Promise.resolve())
    const w = mount(ConfirmDialog, { props: { open: true, title: 'Delete jail web', confirmLabel: 'Delete', run, typeName: 'web', items: ['volume content (10 GiB)'] }, attachTo: document.body })
    await flushPromises()
    const body = document.body
    expect(body.querySelector('[data-test="confirm-items"]')?.textContent).toContain('volume content')
    expect(body.querySelector('[data-test="confirm-why"]')?.textContent).toContain('Type web')
    ;(body.querySelector('[data-test="confirm"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(run).not.toHaveBeenCalled()
    expect(body.querySelector('[role="alert"]')?.textContent).toContain('does not match')
    const input = body.querySelector('[data-test="confirm-type"]') as HTMLInputElement
    input.value = 'web'
    input.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(body.querySelector('[data-test="confirm-why"]')).toBeNull()
    ;(body.querySelector('[data-test="confirm"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(run).toHaveBeenCalledOnce()
    expect(w.emitted('done')).toBeTruthy()
    w.unmount()
  })
  it('tier 2: one click, no typing', async () => {
    const run = vi.fn(() => Promise.resolve())
    const w = mount(ConfirmDialog, { props: { open: true, title: 'Stop web', confirmLabel: 'Stop', run }, attachTo: document.body })
    await flushPromises()
    expect(document.body.querySelector('[data-test="confirm-type"]')).toBeNull()
    ;(document.body.querySelector('[data-test="confirm"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(run).toHaveBeenCalledOnce()
    w.unmount()
  })
})

describe('TabBar and useTabQuery', () => {
  it('keeps the tab in ?tab=, leaves the default out, and moves with the arrow keys', async () => {
    const Page = defineComponent({
      setup() {
        const { tab } = useTabQuery(() => ['users', 'tokens', 'trust'] as const, 'users')
        return () => h(TabBar, { tabs: [{ key: 'users', label: 'Users' }, { key: 'tokens', label: 'Tokens' }, { key: 'trust', label: 'Trust' }], modelValue: tab.value, label: 'Sections', id: 't', 'onUpdate:modelValue': (v: string) => (tab.value = v as 'users' | 'tokens' | 'trust') })
      },
    })
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/access', component: Page }] })
    await router.push('/access?tab=tokens')
    const w = mount({ render: () => h('div', [h(defineComponent({ setup: () => () => h(Page) }))]) }, { global: { plugins: [router] }, attachTo: document.body })
    await flushPromises()
    const selected = () => w.find('[aria-selected="true"]').attributes('data-tab')
    expect(selected()).toBe('tokens')
    expect(w.find('[data-tab="tokens"]').attributes('tabindex')).toBe('0')
    expect(w.find('[data-tab="users"]').attributes('tabindex')).toBe('-1')
    await w.find('[role="tablist"]').trigger('keydown', { key: 'ArrowRight' })
    await flushPromises()
    expect(selected()).toBe('trust')
    expect(router.currentRoute.value.query.tab).toBe('trust')
    await w.find('[role="tablist"]').trigger('keydown', { key: 'Home' })
    await flushPromises()
    expect(selected()).toBe('users')
    expect(router.currentRoute.value.query.tab).toBeUndefined()
    w.unmount()
  })
})
