import { computed, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import { imageBody, type ImageForm } from '@/lib/images'

export type ImageRunPhase = 'idle' | 'creating' | 'building' | 'done' | 'failed' | 'cancelled'

/**
 * Creating an image and building its first generation, for the Create image dialog and the wizard: the existing
 * routes one after the other (POST /images, then POST /images/{name}/generations), the build followed as an
 * operation with its progress. A retry after a failed build builds again; the image is not created twice. `silent`
 * leaves out the toast of the build where the page itself shows it to the end (the wizard).
 */
export function useImageCreate(opts: { silent?: boolean } = {}) {
  const phase = ref<ImageRunPhase>('idle')
  const progress = ref(0)
  const error = ref<ApiError | null>(null)
  /** Which request failed: the definition or the build. */
  const failedAt = ref<'' | 'create' | 'build'>('')
  const opId = ref('')
  const mayCancel = ref(false)
  /** The image this run created: a retry only builds it. */
  const created = ref('')
  const busy = computed(() => phase.value === 'creating' || phase.value === 'building')
  // each run and reset takes a number: a run that was reset away (a dialog opened again) writes nothing more
  let gen = 0

  async function run(f: ImageForm): Promise<boolean> {
    const mine = ++gen
    const live = () => mine === gen
    error.value = null
    failedAt.value = ''
    progress.value = 0
    opId.value = ''
    try {
      if (created.value !== f.name) {
        phase.value = 'creating'
        failedAt.value = 'create'
        await runOp(s.imageCreate.createOp(f.name), () => api.images.create(imageBody(f)), { silent: true })
        if (!live()) return false
        created.value = f.name
      }
      if (!f.build) {
        phase.value = 'done'
        failedAt.value = ''
        return true
      }
      phase.value = 'building'
      failedAt.value = 'build'
      const r = await runOp(s.imageCreate.buildOp(f.name), () => api.images.build(f.name, {}), {
        silent: opts.silent,
        poll: async (id) => {
          const op = await api.operations.wait(id)
          if (live()) {
            opId.value = id
            progress.value = op.progress ?? progress.value
            mayCancel.value = op.may_cancel && op.status === 'running'
          }
          return op
        },
      })
      if (!live()) return false
      mayCancel.value = false
      failedAt.value = ''
      phase.value = r.op?.status === 'cancelled' ? 'cancelled' : 'done'
      if (phase.value === 'done') progress.value = 100
      return phase.value === 'done'
    } catch (e) {
      if (!live()) return false
      mayCancel.value = false
      error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
      phase.value = 'failed'
      return false
    }
  }

  /** Ask the server to stop the build; the poll then sees it cancelled. */
  async function cancel(): Promise<void> {
    if (!opId.value) return
    try {
      await api.operations.cancel(opId.value)
    } catch (e) {
      error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
    }
  }

  function reset(): void {
    gen++
    phase.value = 'idle'
    progress.value = 0
    error.value = null
    failedAt.value = ''
    opId.value = ''
    mayCancel.value = false
    created.value = ''
  }

  return { phase, progress, error, failedAt, opId, mayCancel, created, busy, run, cancel, reset }
}
