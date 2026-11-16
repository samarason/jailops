<script setup lang="ts">
// The change that reverts itself unless it is confirmed: shown on every page, read from the server (so it is back
// after a reload), with a countdown and the Confirm and Revert buttons.
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { isGlobalAdmin } from '@/composables/project'
import { pendingState, refreshPending, setPending } from '@/composables/pending'
import { secondsLeft, countdown } from '@/lib/hostfw'

const POLL = 5000
const RECENT = 10 * 60_000
const now = ref(Date.now())
const busy = ref(false)
const error = ref('')
const said = ref('')
let tick: ReturnType<typeof setInterval> | undefined
let poll: ReturnType<typeof setInterval> | undefined
let saidTimer: ReturnType<typeof setTimeout> | undefined

const seen = ref<string[]>(load())
function load(): string[] {
  try { return JSON.parse(localStorage.getItem('jailops.pending.seen') ?? '[]') as string[] } catch { return [] }
}
function remember(id: string): void {
  seen.value = [...seen.value.slice(-19), id]
  try { localStorage.setItem('jailops.pending.seen', JSON.stringify(seen.value)) } catch { /* only a convenience */ }
}

const p = computed(() => pendingState.data?.pending)
const left = computed(() => (p.value ? secondsLeft(p.value, pendingState.fetchedAt, now.value) : 0))
const admin = computed(() => isGlobalAdmin())
/** A revert the user did not cause (the deadline passed, a reboot, a failure), shown once while it is recent. */
const notice = computed(() => {
  const l = pendingState.data?.last
  if (!l || p.value || seen.value.includes(l.id) || !s.pending.outcomes[l.outcome]) return null
  return now.value - Date.parse(l.time) < RECENT ? l : null
})

onMounted(() => {
  void refreshPending()
  tick = setInterval(() => {
    now.value = Date.now()
    // at the deadline the helper reverts: ask again soon to show it
    if (p.value && left.value === 0 && now.value - pendingState.fetchedAt > 1500) void refreshPending()
  }, 1000)
  poll = setInterval(() => { void refreshPending() }, POLL)
})
onUnmounted(() => { clearInterval(tick); clearInterval(poll); clearTimeout(saidTimer) })

async function act(how: 'confirm' | 'revert'): Promise<void> {
  if (!p.value) return
  busy.value = true
  error.value = ''
  const id = p.value.id
  try {
    const r = how === 'confirm' ? await api.host.confirm(id) : await api.host.revert(id)
    if (r.kind === 'sync' && r.data) setPending(r.data)
    remember(id)
    said.value = how === 'confirm' ? s.pending.confirmed : s.pending.reverted
    clearTimeout(saidTimer)
    saidTimer = setTimeout(() => { said.value = '' }, 6000)
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : String(e)
    void refreshPending()
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="pending-wrap" role="status" aria-live="polite">
    <div v-if="p" class="pending-bar warn" data-test="pending-banner" :aria-label="s.pending.label">
      <p class="grow">
        <!-- the countdown is shown once, inside the sentence; screen readers hear it once a minute, not every second -->
        <template v-if="left > 0">
          <strong data-test="pending-countdown" aria-hidden="true">{{ s.pending.text(p.module, countdown(left)) }}</strong>
          <span class="sr-only">{{ s.pending.textMinutes(p.module, Math.ceil(left / 60)) }}</span>
        </template>
        <strong v-else>{{ s.pending.expired(p.module) }}</strong>
        <span v-if="error" class="pending-err">{{ error }}</span>
        <span v-if="!admin" class="pending-note">{{ s.pending.adminOnly }}</span>
      </p>
      <div v-if="admin" class="row pending-actions">
        <button class="btn btn-primary" type="button" :disabled="busy || left === 0" data-test="pending-confirm" @click="act('confirm')">{{ s.pending.confirm }}</button>
        <button class="btn" type="button" :disabled="busy" data-test="pending-revert" @click="act('revert')">{{ s.pending.revert }}</button>
      </div>
    </div>
    <div v-else-if="said" class="pending-bar ok" data-test="pending-said"><p class="grow">{{ said }}</p></div>
    <div v-else-if="notice" class="pending-bar danger" data-test="pending-notice">
      <p class="grow">{{ s.pending.outcomes[notice.outcome] }} <span v-if="notice.detail" class="pending-note">{{ notice.detail }}</span></p>
      <button class="btn btn-ghost" type="button" data-test="pending-dismiss" @click="remember(notice.id)">{{ s.pending.dismiss }}</button>
    </div>
  </div>
</template>

<style scoped>
.pending-wrap:empty { display: none; }
.pending-bar { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; padding: 10px 14px; margin-bottom: 12px; border: 1px solid var(--border-strong); border-radius: var(--radius); }
.pending-bar p { margin: 0; min-width: 0; overflow-wrap: anywhere; }
.pending-bar.warn { background: var(--warn-bg); color: var(--text); border-color: var(--warn); }
.pending-bar.ok { background: var(--ok-bg); color: var(--text); border-color: var(--ok); }
.pending-bar.danger { background: var(--danger-bg); color: var(--text); border-color: var(--danger); }
.pending-note, .pending-err { display: block; font-size: 12px; }
.pending-actions { flex-wrap: wrap; }
</style>
