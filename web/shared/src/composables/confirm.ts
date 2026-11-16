import { reactive } from 'vue'

/**
 * Confirmation tiers, one rule for both consoles:
 *  1. a safe, undoable action runs at once (start, take a snapshot, preview);
 *  2. a disruptive one asks first and names what it touches (stop or restart a running jail, upgrade an image and
 *     its jails, uninstall an app);
 *  3. data loss needs the name typed (delete a jail, roll data back, delete a project, a volume, a network with
 *     jails, a firewall policy in use).
 * A view calls confirmAction(); ConfirmHost (in the shell) shows ConfirmDialog. Escape and focus follow Modal.
 */
export type Tier = 1 | 2 | 3

export interface ConfirmRequest {
  title: string
  confirmLabel: string
  run: () => Promise<unknown>
  text?: string
  items?: string[]
  itemsLabel?: string
  /** Set for tier 3. */
  typeName?: string
  typeLabel?: string
  danger?: boolean
  /** Tier 1 runs without a dialog. Default: 3 with typeName, else 2. */
  tier?: Tier
  done?: () => void
}

export const confirmState = reactive({ req: null as ConfirmRequest | null })

export function tierOf(r: Pick<ConfirmRequest, 'tier' | 'typeName'>): Tier {
  return r.tier ?? (r.typeName ? 3 : 2)
}

/** Ask (tier 2 or 3) or run at once (tier 1). A tier-1 failure is the toast's to show. */
export function confirmAction(r: ConfirmRequest): void {
  if (tierOf(r) === 1) {
    void r.run().then(() => r.done?.(), () => undefined)
    return
  }
  confirmState.req = r
}

export function closeConfirm(): void {
  confirmState.req = null
}
