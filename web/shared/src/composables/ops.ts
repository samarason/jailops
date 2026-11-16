import { reactive } from 'vue'
import { getClient, ApiError } from '@jailops/shared/api/client'
import type { MutationResult, Operation } from '@jailops/shared/api/types'
import { dataVersion } from './events'

export interface Toast {
  id: number
  title: string
  status: 'running' | 'success' | 'failure' | 'cancelled'
  progress: number
  opId?: string
  mayCancel: boolean
  error?: { code: string; message: string; hint?: string; detail?: Record<string, string> }
  /** Operation metadata of a finished operation, for dry-run previews. */
  metadata?: unknown
  cancelFn?: () => Promise<void>
}

export const toasts = reactive<Toast[]>([])
let seq = 0

export const POLL_MS = { value: 150 }

/** How long a finished toast stays: long enough to read a failure, short enough not to pile up over the page. */
export const TOAST_MS = { success: 5000, cancelled: 5000, failure: 15000 }

const timers = new Map<number, { left: number; started: number; handle?: ReturnType<typeof setTimeout> }>()

export function dismiss(id: number): void {
  const tm = timers.get(id)
  if (tm?.handle) clearTimeout(tm.handle)
  timers.delete(id)
  const i = toasts.findIndex((t) => t.id === id)
  if (i >= 0) toasts.splice(i, 1)
}

function arm(id: number, ms: number): void {
  const tm = { left: ms, started: Date.now(), handle: setTimeout(() => dismiss(id), ms) as ReturnType<typeof setTimeout> | undefined }
  timers.set(id, tm)
}

/** Hover or keyboard focus holds a toast; leaving it gives back the time that was left. */
export function holdToast(id: number): void {
  const tm = timers.get(id)
  if (!tm?.handle) return
  clearTimeout(tm.handle)
  tm.handle = undefined
  tm.left = Math.max(1000, tm.left - (Date.now() - tm.started))
}
export function releaseToast(id: number): void {
  const tm = timers.get(id)
  if (!tm || tm.handle) return
  tm.started = Date.now()
  tm.handle = setTimeout(() => dismiss(id), tm.left)
}

function errorOf(e: unknown): Toast['error'] {
  if (e instanceof ApiError) return { code: e.code, message: e.message, hint: e.hint, detail: e.detail }
  return { code: 'internal', message: e instanceof Error ? e.message : String(e) }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/**
 * Run a mutating request through the async operation flow. A toast shows progress. A failure toast carries the
 * api.Error code, message and hint and stays 15 seconds (5 for success), longer while pointed at or focused. The promise
 * resolves with the finished operation (or null for a sync reply) and rejects with the ApiError,
 * so a dialog can show the same error inline.
 */
export async function runOp<T = unknown>(title: string, start: () => Promise<MutationResult<T>>, opts: { silent?: boolean; poll?: (id: string) => Promise<Operation>; cancel?: (id: string) => Promise<void> } = {}): Promise<{ op: Operation | null; data?: T }> {
  const t = reactive<Toast>({ id: ++seq, title, status: 'running', progress: 0, mayCancel: false })
  if (!opts.silent) toasts.push(t)
  try {
    const r = await start()
    if (r.kind === 'sync') {
      t.status = 'success'
      t.progress = 100
      finish(t)
      return { op: null, data: r.data }
    }
    let op = r.op
    t.opId = op.id
    if (opts.cancel) t.cancelFn = () => opts.cancel!(op.id)
    for (;;) {
      t.progress = op.progress ?? t.progress
      t.mayCancel = op.may_cancel && !op.status.includes('success')
      if (op.status === 'success' || op.status === 'failure' || op.status === 'cancelled') break
      await sleep(POLL_MS.value)
      op = await (opts.poll ?? ((id) => getClient().getOperation(id)))(op.id)
    }
    t.metadata = op.metadata
    t.mayCancel = false
    if (op.status === 'success') {
      t.status = 'success'
      t.progress = 100
      finish(t)
      return { op }
    }
    if (op.status === 'cancelled') {
      t.status = 'cancelled'
      finish(t)
      return { op }
    }
    const err = op.error ?? { code: 'internal', message: 'The operation failed.' }
    t.status = 'failure'
    t.error = err
    finish(t)
    throw new ApiError(err, 0)
  } catch (e) {
    if (t.status !== 'failure') {
      t.status = 'failure'
      t.error = errorOf(e)
      arm(t.id, TOAST_MS.failure)
    }
    throw e
  }
}

function finish(t: Toast): void {
  dataVersion.value++
  arm(t.id, t.status === 'failure' ? TOAST_MS.failure : TOAST_MS.success)
}

export async function cancelToast(t: Toast): Promise<void> {
  if (!t.opId) return
  try {
    if (t.cancelFn) await t.cancelFn()
    else await getClient().cancelOperation(t.opId)
  } catch (e) {
    t.error = errorOf(e)
  }
}
