import { describe, expect, it } from 'vitest'
import { isHostDir, isLost, pathProblem } from './volumes'
import type { Volume } from '@jailops/shared/api/types'

const vol = (spec: Partial<Volume['spec']>, state?: string): Volume => ({ metadata: { name: 'v', scope: 'host' }, spec: { uid: 0, gid: 0, ...spec }, status: { used: 0, ...(state ? { state } : {}) } }) as Volume

describe('volumes of host directories', () => {
  it('knows a directory of the host and a lost mount', () => {
    expect(isHostDir(vol({ path: '/mnt/box/backups' }))).toBe(true)
    expect(isHostDir(vol({}))).toBe(false)
    expect(isLost(vol({ path: '/mnt/box' }, 'lost'))).toBe(true)
    expect(isLost(vol({ path: '/mnt/box' }, 'ok'))).toBe(false)
  })
  it('takes a clean absolute path of the characters an fstab line takes', () => {
    for (const ok of ['/mnt/box', '/mnt/storagebox/backups', '/mnt/a_b-c.d+e@f:g=h,i']) expect(pathProblem(ok)).toBe('')
    for (const bad of ['', '/', 'mnt/box', '/mnt//box', '/mnt/../etc', '/mnt/./box', '/mnt/box/', '/mnt/my box', '/mnt/box;ls']) expect(pathProblem(bad)).not.toBe('')
  })
})
