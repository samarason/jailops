<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, shallowRef, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { can, hasExt } from '@jailops/shared/composables/session'
import { projectState } from '@/composables/project'
import { shellCommand } from '@/composables/shell'
import { ApiError } from '@jailops/shared/api/client'
import type { EventStream } from '@jailops/shared/api/client'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import { Screen, keyToBytes, xtermColor, type Cell } from '@/lib/vt100'
import { runOp } from '@jailops/shared/composables/ops'
import type { Jail, ShellSetupResult } from '@jailops/shared/api/types'

// `connect` asks for a session: a new number connects once the jail runs (the Shell buttons and /jails/NAME/shell).
const props = defineProps<{ jail: Jail; connect?: number }>()
const emit = defineEmits<{ changed: [] }>()
const name = computed(() => props.jail.metadata.name)
const available = computed(() => hasExt('jail_console'))
const running = computed(() => props.jail.status.power === 'running')
const shell = computed(() => (props.jail.spec as unknown as { shell?: string }).shell || '/bin/sh')

const screen = shallowRef(new Screen(80, 24))
const tick = ref(0) // bumps on every write so the view re-renders
const state = reactive({ phase: 'idle' as 'idle' | 'connecting' | 'open' | 'closed', exit: undefined as number | undefined })
const error = ref<ApiError | null>(null)
const copied = ref(false)
const cliCopied = ref(false)
const project = computed(() => (can('projects') ? props.jail.metadata.project || projectState.current : ''))
const cli = computed(() => shellCommand(name.value, project.value))
const asked = ref(0)
const term = ref<HTMLElement | null>(null)
const probe = ref<HTMLElement | null>(null)
let sessionId = ''
let stream: EventStream | null = null
let ro: ResizeObserver | null = null
let pending = ''
let flush: ReturnType<typeof setTimeout> | undefined

// the 16 colours, light enough to read on the dark screen (4.5:1 and more on #0b0f17 for all but black); the other 240 are xterm's
const palette = ['#000', '#ff6b5e', '#3fd06a', '#e2c93f', '#7a95ff', '#e57ae6', '#3fcfd6', '#c7c7c7', '#8a8a8a', '#ff8a80', '#6ff58f', '#fffc67', '#9fb2ff', '#ff9cff', '#7ffcff', '#fff']
const color = (n: number) => (n < 0 ? undefined : n < 16 ? palette[n] : xtermColor(n))

interface Run { text: string; style: Record<string, string> }
const lines = computed<Run[][]>(() => {
  void tick.value
  const sc = screen.value
  return sc.grid.map((row, y) => {
    const runs: Run[] = []
    let cur: Run | null = null
    let key = ''
    row.forEach((c: Cell, x) => {
      const cursor = state.phase === 'open' && y === sc.y && x === sc.x
      const k = `${c.fg}|${c.bg}|${c.bold}|${c.ul}|${c.rev}|${cursor}`
      if (!cur || k !== key) {
        const style: Record<string, string> = {}
        let fg = color(c.fg), bg = color(c.bg)
        if (c.rev || cursor) { [fg, bg] = [bg ?? 'var(--surface)', fg ?? 'var(--text)'] }
        if (fg) style.color = fg
        if (bg) style.background = bg
        if (c.bold) style.fontWeight = '600'
        if (c.ul) style.textDecoration = 'underline'
        cur = { text: '', style }
        key = k
        runs.push(cur)
      }
      cur.text += c.ch
    })
    return runs
  })
})

function write(bytes: Uint8Array | string): void {
  screen.value.write(bytes)
  tick.value++
}
function schedule(): void {
  if (flush) return
  flush = setTimeout(() => {
    flush = undefined
    const chunk = pending
    pending = ''
    void api.exec.input(name.value, sessionId, chunk).catch((e) => (error.value = e instanceof ApiError ? e : null))
  }, 8)
}
function send(data: string): void {
  if (state.phase !== 'open') return
  pending += data
  schedule()
}

function measure(): { cols: number; rows: number } {
  const el = term.value
  const p = probe.value
  if (!el || !p) return { cols: 80, rows: 24 }
  const r = p.getBoundingClientRect()
  const cw = r.width / 10 || 8
  const ch = r.height || 16
  return { cols: Math.max(20, Math.floor((el.clientWidth - 16) / cw)), rows: Math.max(5, Math.floor(Math.min(el.clientHeight || 400, 480) / ch)) }
}
let lastSize = ''
function fit(): void {
  const { cols, rows } = measure()
  const key = `${cols}x${rows}`
  if (key === lastSize) return
  lastSize = key
  screen.value.resize(cols, rows)
  tick.value++
  if (state.phase === 'open') void api.exec.resize(name.value, sessionId, cols, rows).catch(() => undefined)
}

async function connect(): Promise<void> {
  error.value = null
  state.phase = 'connecting'
  state.exit = undefined
  await nextTick()
  lastSize = ''
  screen.value = new Screen(80, 24)
  fit()
  const { cols, rows } = measure()
  try {
    const r = await api.exec.open(name.value, { shell: true, tty: true, cols, rows })
    sessionId = (r.kind === 'sync' ? (r.data as { id: string }).id : '') || ''
    state.phase = 'open'
    stream = api.exec.output(name.value, sessionId, {
      onEvent: (e) => {
        const m = e.metadata as { data?: string; exit?: number }
        if (m?.data) write(Uint8Array.from(atob(m.data), (c) => c.charCodeAt(0)))
        if (m?.exit !== undefined) end(m.exit)
      },
      onError: () => end(undefined),
    })
    term.value?.focus()
  } catch (e) {
    state.phase = 'closed'
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  }
}
// A jail whose shell is bash but has none (an older jail, or a first start without the package repository) can be
// given it here: the shell setup installs bash and the prompt, then the shell opens.
const bashMissing = computed(() => error.value?.code === 'not_found' && shell.value === '/usr/local/bin/bash' && hasExt('jail_shell_setup'))
const settingUp = ref(false)
async function setUpShell(): Promise<void> {
  settingUp.value = true
  try {
    await runOp<ShellSetupResult>(s.exec.setupTitle(name.value), () => api.shellSetup.run(name.value))
    error.value = null
    emit('changed')
    await connect()
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    settingUp.value = false
  }
}
function end(code: number | undefined): void {
  if (state.phase === 'closed') return
  state.phase = 'closed'
  state.exit = code
  stream?.close()
  stream = null
}
async function disconnect(): Promise<void> {
  const id = sessionId
  end(undefined)
  if (id) await api.exec.close(name.value, id).catch(() => undefined)
}

function onKey(e: KeyboardEvent): void {
  if (state.phase !== 'open') return
  // Ctrl+Shift+C and Ctrl+Shift+V are the browser's copy and paste; plain Ctrl+C goes to the jail.
  if (e.ctrlKey && e.shiftKey && (e.key === 'C' || e.key === 'V')) return
  const b = keyToBytes(e)
  if (b === null) return
  e.preventDefault()
  send(b)
}
function onPaste(e: ClipboardEvent): void {
  const t = e.clipboardData?.getData('text')
  if (t) {
    e.preventDefault()
    send(t.replace(/\r?\n/g, '\r'))
  }
}
async function paste(): Promise<void> {
  try {
    send((await navigator.clipboard.readText()).replace(/\r?\n/g, '\r'))
  } catch {
    term.value?.focus()
  }
}
async function copy(): Promise<void> {
  const text = screen.value.allText()
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    /* clipboard blocked: the selection still works by hand */
  }
  copied.value = true
  setTimeout(() => (copied.value = false), 1500)
}

/** A requested session opens as soon as the jail runs (a Start and open shell waits here for the start). */
const waiting = computed(() => !!props.connect && props.connect !== asked.value && !running.value)
function maybeConnect(): void {
  if (!props.connect || props.connect === asked.value || !running.value || !available.value) return
  asked.value = props.connect
  if (state.phase !== 'open' && state.phase !== 'connecting') void connect()
  else term.value?.focus()
}
watch([() => props.connect, running], maybeConnect)

async function copyCli(): Promise<void> {
  try {
    await navigator.clipboard.writeText(cli.value)
  } catch {
    /* clipboard blocked: the command is shown and can be selected */
  }
  cliCopied.value = true
  setTimeout(() => (cliCopied.value = false), 1500)
}

onMounted(() => {
  maybeConnect()
  if (term.value && typeof ResizeObserver !== 'undefined') {
    ro = new ResizeObserver(() => fit())
    ro.observe(term.value)
  }
})
onBeforeUnmount(() => {
  ro?.disconnect()
  stream?.close()
  if (state.phase === 'open' && sessionId) void api.exec.close(name.value, sessionId).catch(() => undefined)
})
defineExpose({ screen, write })
</script>

<template>
  <div class="stack" data-test="exec-tab">
    <div class="row"><span class="muted">{{ s.exec.lead }}</span></div>
    <Callout v-if="!available" tone="warn" data-test="exec-unavailable"><strong>{{ s.exec.unavailableTitle }}</strong><br />{{ s.exec.unavailableText }}</Callout>
    <template v-else>
      <Callout v-if="waiting" tone="info" data-test="exec-waiting">{{ s.exec.waiting }}</Callout>
      <Callout v-else-if="!running">{{ s.exec.notRunning }}</Callout>
      <div class="row">
        <button v-if="state.phase !== 'open' && state.phase !== 'connecting'" class="btn btn-primary" type="button" :disabled="!running" data-test="exec-open" @click="connect">{{ s.exec.connect }}</button>
        <button v-else class="btn" type="button" data-test="exec-close" @click="disconnect">{{ s.exec.disconnect }}</button>
        <button class="btn" type="button" :disabled="state.phase !== 'open'" @click="paste">{{ s.exec.paste }}</button>
        <button class="btn" type="button" data-test="exec-copy" @click="copy">{{ copied ? s.exec.copied : s.exec.copy }}</button>
        <span class="faint mono" :title="s.exec.shellTitle" data-test="exec-shell">{{ s.exec.asUser(shell) }} · {{ s.exec.size(screen.cols, screen.rows) }}</span>
        <span v-if="state.phase === 'connecting'" class="pill info pulse">{{ s.exec.connecting }}</span>
        <span v-else-if="state.phase === 'open'" class="pill ok">{{ s.exec.connected }}</span>
        <span v-else-if="state.phase === 'closed'" class="pill">{{ s.exec.closed(state.exit) }}</span>
      </div>
      <ErrorPanel v-if="error" :error="error" />
      <Callout v-if="bashMissing" tone="info" data-test="exec-setup">
        <p>{{ s.exec.setupText }}</p>
        <div class="row"><button class="btn btn-primary btn-sm" type="button" :disabled="settingUp" data-test="exec-setup-go" @click="setUpShell">{{ settingUp ? s.exec.settingUp : s.exec.setup }}</button></div>
      </Callout>
    </template>
    <div ref="term" class="term" tabindex="0" role="textbox" aria-multiline="true" :aria-label="s.exec.terminal" data-test="terminal" @keydown="onKey" @paste="onPaste">
      <span ref="probe" class="term-probe" aria-hidden="true">MMMMMMMMMM</span>
      <pre class="term-screen"><div v-for="(runs, y) in lines" :key="y" class="term-line"><span v-for="(r, i) in runs" :key="i" :style="r.style">{{ r.text }}</span></div></pre>
    </div>
    <p class="faint">{{ s.exec.hint }}</p>
    <div class="exec-cli" data-test="exec-cli">
      <span class="faint">{{ s.exec.cli }}</span>
      <code class="exec-cli-cmd" data-test="exec-cli-cmd">{{ cli }}</code>
      <button class="btn btn-sm" type="button" :aria-label="s.exec.copyCli" data-test="exec-cli-copy" @click="copyCli"><Icon :name="cliCopied ? 'check' : 'copy'" />{{ cliCopied ? s.exec.copied : s.exec.copyCli }}</button>
      <span class="sr-only" role="status">{{ cliCopied ? s.exec.copiedCli : '' }}</span>
      <span class="faint exec-cli-one">{{ s.exec.cliOne(name, project) }}</span>
    </div>
  </div>
</template>

<style>
.term { position: relative; background: #0b0f17; color: #d7dde8; border: 1px solid var(--border-strong); border-radius: var(--radius); padding: 8px; height: 420px; overflow: auto; font-family: var(--font-mono); font-size: 13px; line-height: 1.25; }
.term:focus { outline: 2px solid var(--focus); outline-offset: 1px; }
.term-screen { margin: 0; font: inherit; white-space: pre; }
.term-line { min-height: 1.25em; }
.exec-cli { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 10px; padding: 8px 10px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface-2); font-size: 13px; }
.exec-cli-cmd { padding: 2px 6px; border-radius: var(--radius); background: var(--surface); border: 1px solid var(--border); color: var(--text); word-break: break-all; }
.exec-cli-one { flex-basis: 100%; font-size: 12px; }
.term-probe { position: absolute; visibility: hidden; white-space: pre; font: inherit; }
</style>
