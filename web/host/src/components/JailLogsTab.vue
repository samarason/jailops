<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { hasExt } from '@jailops/shared/composables/session'
import { ago, bytes, stamp } from '@jailops/shared/lib/format'
import { applyFollow, emptyFollow, pickFile, plainText, sortFiles, startFrom, FOLLOW_MS, MAX_TAIL, SINCE, TAILS, type FollowState } from '@/lib/logs'
import Icon from '@jailops/shared/components/Icon.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import type { Jail, JailLogFile } from '@jailops/shared/api/types'
import { projectState } from '@/composables/project'

const props = defineProps<{ jail: Jail; file?: string }>()
const name = computed(() => props.jail.metadata.name)
const available = computed(() => hasExt('jail_logs'))
/** The Logs page with this jail chosen, where it can be read next to the others. */
const allLogs = computed(() => ({ path: '/logs', query: { jail: name.value, ...((props.jail.metadata.project ?? projectState.current) ? { project: props.jail.metadata.project ?? projectState.current } : {}) } }))

const files = ref<JailLogFile[]>([])
const filesError = ref<ApiError | null>(null)
const filesLoading = ref(true)
const selected = ref('')
const tail = ref(200)
const since = ref('')
const grep = ref('')
const grepApplied = ref('')
const st = ref<FollowState>(emptyFollow())
const readError = ref<ApiError | null>(null)
const reading = ref(false)
const follow = ref(false)
const stopped = ref(false)
const hidden = ref(typeof document !== 'undefined' && document.hidden)
const wrap = ref(false)
const atEnd = ref(true)
const copied = ref(false)
const box = ref<HTMLElement | null>(null)
let timer: ReturnType<typeof setInterval> | undefined
let inflight = false
let gen = 0

const sorted = computed(() => sortFiles(files.value))
const current = computed(() => files.value.find((f) => f.name === selected.value))
const count = computed(() => st.value.lines.filter((l) => !l.marker).length)
const errOf = (e: unknown) => (e instanceof ApiError ? e : new ApiError({ message: String(e) }))

async function loadFiles(): Promise<void> {
  filesLoading.value = true
  try {
    files.value = await api.logs.list(name.value)
    filesError.value = null
    if (!selected.value || !files.value.some((f) => f.name === selected.value)) selected.value = pickFile(files.value, props.file ?? '')
  } catch (e) {
    filesError.value = errOf(e)
  } finally {
    filesLoading.value = false
  }
}

/** A fresh read of the end of the file with the filters: replaces what is shown. */
async function read(): Promise<void> {
  if (!selected.value) return
  const mine = ++gen
  reading.value = true
  readError.value = null
  grepApplied.value = grep.value.trim()
  try {
    const r = await api.logs.read(name.value, selected.value, { tail: tail.value, since: since.value, grep: grepApplied.value })
    if (mine !== gen) return
    st.value = startFrom(r)
    atEnd.value = true
    await nextTick()
    toEnd()
  } catch (e) {
    if (mine !== gen) return
    readError.value = errOf(e)
    st.value = emptyFollow()
    follow.value = false
  } finally {
    if (mine === gen) reading.value = false
  }
}

/** One follow poll: what was written since next_offset. Hidden tabs do not poll. */
async function poll(): Promise<void> {
  if (inflight || hidden.value || reading.value || !selected.value) return
  inflight = true
  const mine = gen
  try {
    const r = await api.logs.read(name.value, selected.value, { offset: st.value.offset, tail: MAX_TAIL, since: since.value, grep: grepApplied.value })
    if (mine !== gen || !follow.value) return
    const end = atEnd.value
    st.value = applyFollow(st.value, r, end)
    if (end) {
      await nextTick()
      toEnd()
    }
  } catch (e) {
    readError.value = errOf(e)
    follow.value = false
    stopped.value = true
  } finally {
    inflight = false
  }
}

function toEnd(): void {
  const el = box.value
  if (el) el.scrollTop = el.scrollHeight
  atEnd.value = true
  st.value = { ...st.value, unseen: 0 }
}
function onScroll(): void {
  const el = box.value
  if (!el) return
  const end = el.scrollHeight - el.scrollTop - el.clientHeight < 24
  atEnd.value = end
  if (end && st.value.unseen) st.value = { ...st.value, unseen: 0 }
}
function onVisibility(): void {
  hidden.value = document.hidden
}

watch(follow, (on) => {
  clearInterval(timer)
  timer = undefined
  if (on) {
    stopped.value = false
    timer = setInterval(() => void poll(), FOLLOW_MS)
  }
})
watch(selected, () => void read())
watch([tail, since], () => void read())

async function copy(): Promise<void> {
  try {
    await navigator.clipboard.writeText(plainText(st.value.lines))
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  } catch {
    /* clipboard unavailable (insecure origin): download still works */
  }
}
function download(): void {
  const blob = new Blob([plainText(st.value.lines)], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${name.value}-${selected.value.replace(/\//g, '_')}.txt`
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 0)
}

onMounted(() => {
  document.addEventListener('visibilitychange', onVisibility)
  if (available.value) void loadFiles()
})
onBeforeUnmount(() => {
  clearInterval(timer)
  document.removeEventListener('visibilitychange', onVisibility)
  gen++
})
</script>

<template>
  <div data-test="logs-tab">
    <Callout v-if="!available" tone="info">{{ s.logs.unavailable }}</Callout>
    <template v-else>
      <p v-if="hasExt('logs_unified')" class="logs-all"><router-link :to="allLogs" data-test="logs-open-all"><Icon name="fileText" />{{ s.logs.openAll }}</router-link></p>
      <div v-if="filesError" class="stack" data-test="logs-error">
        <Callout v-if="filesError.code === 'busy'" tone="warn" data-test="logs-not-mounted">{{ s.logs.notMounted }}</Callout>
        <Callout v-else-if="filesError.code === 'forbidden'" tone="warn" data-test="logs-forbidden">{{ s.logs.forbidden }}</Callout>
        <ErrorPanel :error="filesError" />
        <div><button class="btn" type="button" @click="loadFiles"><Icon name="rotateCw" />{{ s.app.retry }}</button></div>
      </div>
      <p v-else-if="filesLoading && !files.length" class="muted" role="status">{{ s.app.loading }}</p>
      <p v-else-if="!files.length" class="empty panel">{{ s.logs.filesEmpty }}</p>
      <div v-else class="logs-layout">
        <section class="panel logs-files" aria-labelledby="logs-files-h">
          <header><h2 id="logs-files-h">{{ s.logs.files }}</h2><button class="btn btn-sm btn-ghost btn-icon" type="button" :aria-label="s.logs.reload" :title="s.logs.reload" @click="loadFiles"><Icon name="rotateCw" /></button></header>
          <ul class="log-file-list" data-test="log-files">
            <li v-for="(f, i) in sorted" :key="f.name">
              <button class="log-file" type="button" :disabled="f.compressed" :aria-current="f.name === selected ? 'true' : undefined" :aria-describedby="f.compressed ? `log-why-${i}` : undefined" :data-file="f.name" @click="selected = f.name">
                <span class="row log-file-top"><span class="mono log-file-name">{{ f.name }}</span><span class="badge" :class="f.kind === 'active' ? 'info' : ''">{{ f.kind === 'active' ? s.logs.active : s.logs.rotated }}</span><span v-if="f.compressed" class="badge warn">{{ s.logs.compressed }}</span></span>
                <span class="faint log-file-meta"><span class="mono">{{ bytes(f.size) }}</span> · <span :title="ago(f.modified_at)">{{ s.logs.modified(stamp(f.modified_at)) }}</span></span>
              </button>
              <p v-if="f.compressed" :id="`log-why-${i}`" class="log-why">{{ s.logs.compressedWhy }}</p>
            </li>
          </ul>
        </section>

        <section class="panel logs-viewer" aria-labelledby="logs-view-h">
          <header>
            <h2 id="logs-view-h" class="mono">{{ selected ? s.logs.viewer(selected) : s.logs.pick }}</h2>
            <span class="faint" data-test="log-count">{{ s.logs.lines(count) }}<span v-if="current"> · {{ bytes(current.size) }}</span></span>
          </header>
          <form class="logs-tools" @submit.prevent="read">
            <div class="logs-ctl"><label for="log-tail">{{ s.logs.tail }}</label><select id="log-tail" v-model.number="tail" data-test="log-tail"><option v-for="n in TAILS" :key="n" :value="n">{{ n }}</option></select></div>
            <div class="logs-ctl"><label for="log-since">{{ s.logs.since }}</label><select id="log-since" v-model="since" data-test="log-since"><option v-for="x in SINCE" :key="x" :value="x">{{ x ? s.logs.sinceOpt[x] : s.logs.sinceAll }}</option></select></div>
            <div class="logs-ctl logs-grep"><label for="log-grep">{{ s.logs.grep }}</label><input id="log-grep" v-model="grep" type="search" maxlength="128" :placeholder="s.logs.grepHint" data-test="log-grep" /></div>
            <button class="btn" type="submit" data-test="log-apply"><Icon name="search" />{{ s.logs.apply }}</button>
            <span class="grow"></span>
            <div class="row logs-acts">
              <button class="btn" type="button" :aria-pressed="follow" :class="{ 'btn-primary': follow }" data-test="log-follow" @click="follow = !follow"><Icon :name="follow ? 'pause' : 'play'" />{{ follow ? s.logs.following : s.logs.follow }}</button>
              <button class="btn btn-icon" type="button" :aria-pressed="wrap" :aria-label="s.logs.wrap" :title="s.logs.wrap" data-test="log-wrap" @click="wrap = !wrap"><Icon name="wrapText" /></button>
              <button class="btn btn-icon" type="button" :aria-label="copied ? s.logs.copied : s.logs.copy" :title="s.logs.copy" data-test="log-copy" @click="copy"><Icon :name="copied ? 'check' : 'copy'" /></button>
              <button class="btn btn-icon" type="button" :aria-label="s.logs.download" :title="s.logs.download" data-test="log-download" @click="download"><Icon name="download" /></button>
            </div>
          </form>
          <p v-if="follow && hidden" class="faint logs-state">{{ s.logs.paused }}</p>
          <ErrorPanel v-if="readError" :error="readError" class="logs-err" />
          <p v-if="stopped" class="faint logs-state">{{ s.logs.stoppedFollow }}</p>
          <div class="logs-box-wrap">
            <div ref="box" class="logs-box" :class="{ wrap }" role="log" aria-live="off" :aria-label="s.logs.region(selected)" :aria-busy="reading" tabindex="0" data-test="log-view" @scroll="onScroll">
              <p v-if="!reading && !count && !readError" class="logs-none">{{ s.logs.noLines }}</p>
              <div v-for="ln in st.lines" :key="ln.id" class="log-line" :class="ln.marker ? `log-mark log-${ln.marker}` : ''" :data-marker="ln.marker">
                <template v-if="ln.marker">{{ ln.marker === 'rotated' ? s.logs.rotatedMark : s.logs.truncatedMark }}</template>
                <template v-else><span class="log-n" aria-hidden="true">{{ ln.n ?? '' }}</span><span class="log-t">{{ ln.text }}</span></template>
              </div>
            </div>
            <button v-if="!atEnd" class="btn btn-sm logs-jump" type="button" data-test="log-jump" @click="toEnd"><Icon name="arrowDownToLine" />{{ s.logs.jump }}<span v-if="st.unseen" class="logs-new" data-test="log-new">{{ s.logs.newLines(st.unseen) }}</span></button>
          </div>
          <span class="sr-only" role="status">{{ copied ? s.logs.copied : '' }}</span>
        </section>
      </div>
    </template>
  </div>
</template>

<style>
.logs-all { margin: 0 0 8px; display: flex; justify-content: flex-end; }
.logs-all a { display: inline-flex; gap: 6px; align-items: center; }
.logs-layout { display: grid; gap: 12px; grid-template-columns: minmax(220px, 280px) minmax(0, 1fr); align-items: start; }
.log-file-list { list-style: none; margin: 0; padding: 6px; display: grid; gap: 2px; max-height: 560px; overflow-y: auto; }
.log-file { display: grid; gap: 2px; width: 100%; text-align: left; padding: 6px 8px; border: 1px solid transparent; border-radius: var(--radius); background: none; cursor: pointer; color: var(--text); }
.log-file:hover:not(:disabled) { background: var(--surface-2); }
.log-file[aria-current='true'] { background: var(--accent-soft); border-color: var(--accent); }
.log-file[aria-current='true'] .badge.info { color: var(--text); }
.log-file:disabled { cursor: not-allowed; color: var(--text-2); }
.log-file-top { gap: 6px; flex-wrap: wrap; }
.log-file-name { font-weight: 500; overflow-wrap: anywhere; }
.log-file-meta { font-size: 12px; }
.log-why { font-size: 12px; color: var(--text-2); margin: 0 8px 6px; }
.logs-tools { display: flex; flex-wrap: wrap; gap: 8px; align-items: flex-end; padding: 8px 12px; border-bottom: 1px solid var(--border); }
.logs-ctl { display: grid; gap: 2px; }
.logs-ctl label { font-size: 12px; color: var(--text-2); font-weight: 500; }
.logs-ctl select { width: auto; }
.logs-grep { flex: 1 1 160px; max-width: 280px; }
.logs-acts { gap: 6px; }
.logs-state { margin: 6px 12px 0; font-size: 12px; }
.logs-err { margin: 8px 12px 0; }
.logs-box-wrap { position: relative; }
.logs-box { height: min(60vh, 560px); overflow: auto; padding: 8px 0; font-family: var(--font-mono); font-size: 12.5px; line-height: 1.5; background: var(--surface-2); border-radius: 0 0 var(--radius-lg) var(--radius-lg); tab-size: 8; }
.logs-box:focus-visible { outline-offset: -2px; }
.log-line { display: flex; gap: 12px; padding: 0 12px; white-space: pre; min-width: max-content; }
.logs-box.wrap .log-line { white-space: pre-wrap; overflow-wrap: anywhere; min-width: 0; }
.log-line:hover { background: var(--surface-3); }
.log-n { flex: none; min-width: 4ch; text-align: right; color: var(--text-3); user-select: none; }
.log-mark { justify-content: center; margin: 4px 12px; padding: 2px 8px; border-radius: var(--radius); font-family: var(--font-sans); font-size: 12px; white-space: normal; min-width: 0; }
.log-rotated { background: var(--warn-bg); color: var(--warn); }
.log-truncated { background: var(--surface-3); color: var(--text-2); }
.logs-none { padding: 24px 12px; text-align: center; color: var(--text-2); font-family: var(--font-sans); }
.logs-jump { position: absolute; right: 16px; bottom: 12px; box-shadow: var(--shadow); }
.logs-new { margin-left: 4px; padding: 0 6px; border-radius: 999px; background: var(--accent); color: var(--accent-text); font-size: 12px; }
@media (max-width: 900px) { .logs-layout { grid-template-columns: minmax(0, 1fr); } .log-file-list { max-height: 220px; } }
</style>
