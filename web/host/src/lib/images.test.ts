import { describe, expect, it } from 'vitest'
import { autoAtProblem, autoUpgradeSpec, baseImageState, baseRelease, defaultImage, freebsdImages, freebsdReleaseProblem, hostRelease, imageBody, imageLabel, imageNameFor, imageProblems, initialImageForm, newHostRelease, patchLevel, releaseProblem } from './images'
import type { Image, ServerInfo } from '@jailops/shared/api/types'

const info = (kernel: string, arch = 'amd64') => ({ environment: { os: 'FreeBSD', kernel_version: kernel, arch } }) as unknown as ServerInfo

describe('the host release', () => {
  it('comes from the server without the patch level, and only when it is a release', () => {
    expect(baseRelease('15.1-RELEASE-p3')).toBe('15.1-RELEASE')
    expect(hostRelease(info('15.1-RELEASE-p3'))).toBe('15.1-RELEASE')
    expect(hostRelease(info('15.2-STABLE'))).toBe('15.2-STABLE')
    // an older or unreadable release proposes nothing: the field is typed
    expect(hostRelease(info('14.3-RELEASE'))).toBe('')
    expect(hostRelease(info(''))).toBe('')
    expect(hostRelease(null)).toBe('')
  })
})

describe('the release rules', () => {
  it.each([
    ['15.1-RELEASE', ''],
    ['15.1', ''],
    ['15.1-RELEASE-p2', ''],
    ['16.0-CURRENT', ''],
    ['15.0-RELEASE', 'JailOps supports FreeBSD 15.1 and later.'],
    ['14.3-RELEASE', 'JailOps supports FreeBSD 15.1 and later.'],
    ['15', 'A release such as 15.1-RELEASE.'],
    ['15.1 RELEASE', 'A release such as 15.1-RELEASE.'],
    ['latest', 'A release such as 15.1-RELEASE.'],
    ['', 'Required.'],
  ])('FreeBSD %s', (r, want) => expect(freebsdReleaseProblem(r)).toBe(want))
  it('checks Alpine and Debian as the server does', () => {
    expect(releaseProblem('alpine', '3.22')).toBe('')
    expect(releaseProblem('alpine', 'v3.22.1')).toBe('')
    expect(releaseProblem('alpine', 'edge')).toMatch(/Alpine release/)
    expect(releaseProblem('debian', 'trixie')).toBe('')
    expect(releaseProblem('debian', '-x')).toMatch(/suite/)
    expect(releaseProblem('debian', 'a/b')).toMatch(/suite/)
  })
})

describe('the form', () => {
  it('starts with the image of this host\'s release, upgraded every night', () => {
    expect(initialImageForm(info('15.1-RELEASE-p3', 'arm64'))).toEqual({ kind: 'freebsd', name: 'freebsd-15-1', release: '15.1-RELEASE', arch: 'arm64', keys: '', build: true, auto: false, at: '03:00', packages: true })
    expect(initialImageForm(info('15.2-RELEASE')).name).toBe('freebsd-15-2')
    expect(initialImageForm(null).release).toBe('15.1-RELEASE')
    expect(initialImageForm(null).name).toBe('freebsd-15-1')
    expect(initialImageForm(null).arch).toBe('')
    // a Linux image is not upgraded at night unless asked
    expect(initialImageForm(null, 'alpine')).toMatchObject({ name: 'alpine-3-22', release: '3.22', auto: false })
    expect(initialImageForm(null, 'debian').name).toBe('debian-trixie')
  })
  it('proposes the name from the release: one image is one release', () => {
    expect(imageNameFor('freebsd', '15.1-RELEASE')).toBe('freebsd-15-1')
    expect(imageNameFor('freebsd', '16.0-CURRENT')).toBe('freebsd-16-0')
    expect(imageNameFor('freebsd', '15.2-RELEASE-p4')).toBe('freebsd-15-2')
    expect(imageNameFor('freebsd', '')).toBe('freebsd')
    expect(imageNameFor('freebsd', '15')).toBe('freebsd')
    expect(imageNameFor('alpine', 'v3.22.1')).toBe('alpine-3-22')
    expect(imageNameFor('debian', 'trixie')).toBe('debian-trixie')
    expect(imageNameFor('debian', 'a/b')).toBe('debian')
  })
  it('names the problems of each field with the shared name rule', () => {
    const f = initialImageForm(info('15.1-RELEASE'))
    expect(imageProblems(f, [])).toEqual({})
    expect(imageProblems(f, ['freebsd-15-1']).name).toBe('An image named freebsd-15-1 exists already.')
    expect(imageProblems({ ...f, name: 'FreeBSD' }, []).name).toMatch(/^Lowercase letters/)
    expect(imageProblems({ ...f, name: '' }, []).name).toBe('Required.')
    expect(imageProblems({ ...f, release: '14.3-RELEASE' }, []).release).toBe('JailOps supports FreeBSD 15.1 and later.')
    expect(imageProblems({ ...f, arch: '' }, []).arch).toBe('Choose amd64 or arm64.')
    expect(imageProblems({ ...f, kind: 'debian', release: 'trixie', keys: '' }, []).keys).toMatch(/keyring/)
    // the time of the nightly upgrade, only while it is on
    expect(imageProblems({ ...f, auto: true, at: '' }, []).at).toBe('Required.')
    expect(imageProblems({ ...f, at: '' , auto: false }, [])).toEqual({})
  })
  it.each([
    ['03:00', ''], ['00:00', ''], ['23:59', ''],
    ['', 'Required.'], ['3:00', 'A time of day such as 03:00.'], ['24:00', 'A time of day such as 03:00.'], ['12:60', 'A time of day such as 03:00.'], ['noon', 'A time of day such as 03:00.'],
  ])('the time of day %s', (at, want) => expect(autoAtProblem(at)).toBe(want))
  it('sends the definition the CLI sends, with the nightly upgrade', () => {
    const f = initialImageForm(info('15.1-RELEASE'))
    expect(imageBody({ ...f, auto: true })).toEqual({ metadata: { name: 'freebsd-15-1' }, spec: { os: 'freebsd', release: '15.1-RELEASE', arch: 'amd64', source: { type: 'pkgbase' }, auto_upgrade: { enabled: true, packages: true } } })
    expect(imageBody({ ...f, auto: true, at: '04:30', packages: false }).spec.auto_upgrade).toEqual({ enabled: true, at: '04:30', packages: false })
    expect(imageBody(f).spec.auto_upgrade).toBeUndefined()
    expect(imageBody({ ...f, kind: 'alpine', name: 'alpine', release: ' 3.22 ', auto: false }).spec).toEqual({ os: 'linux', release: '3.22', arch: 'amd64', source: { type: 'minirootfs' } })
    expect(imageBody({ ...f, kind: 'debian', name: 'debian', release: 'trixie', keys: '/k.gpg' }).spec.source).toEqual({ type: 'debootstrap', keys: '/k.gpg' })
    expect(autoUpgradeSpec(false, '03:00', true)).toEqual({ enabled: false, packages: true })
  })
  it('knows when apps have no image to start from', () => {
    expect(baseImageState([])).toBe('none')
    expect(baseImageState([{ spec: { os: 'linux' } } as never])).toBe('none')
    expect(baseImageState([{ spec: { os: 'freebsd' } } as never])).toBe('ok')
  })
})

const img = (name: string, release: string, os = 'freebsd') => ({ metadata: { name }, spec: { os, release }, status: {} }) as unknown as Image

describe('several releases', () => {
  const all = [img('alp', '3.22', 'linux'), img('freebsd-15-1', '15.1-RELEASE'), img('freebsd-16-0', '16.0-RELEASE'), img('b-15-2', '15.2-RELEASE'), img('a-15-2', '15.2-RELEASE-p3')]
  it('orders the FreeBSD images by release, newest first, then by name', () => {
    expect(freebsdImages(all).map((i) => i.metadata.name)).toEqual(['freebsd-16-0', 'a-15-2', 'b-15-2', 'freebsd-15-1'])
  })
  it('presets the image of the newest release this host runs, as the server picks it', () => {
    expect(defaultImage(all, '15.2-RELEASE')).toBe('a-15-2')
    expect(defaultImage(all, '16.0-RELEASE')).toBe('freebsd-16-0')
    expect(defaultImage(all, '15.1-RELEASE')).toBe('freebsd-15-1')
    // an unknown host release limits nothing; a host older than every image has no default
    expect(defaultImage(all, '')).toBe('freebsd-16-0')
    expect(defaultImage([img('freebsd-16-0', '16.0-RELEASE')], '15.1-RELEASE')).toBe('')
    expect(defaultImage([img('alp', '3.22', 'linux')], '15.1-RELEASE')).toBe('')
    expect(imageLabel(all[1])).toBe('freebsd-15-1 (15.1-RELEASE)')
  })
  it('notices a host that runs a newer release than every image', () => {
    const one = [img('freebsd-15-1', '15.1-RELEASE')]
    expect(newHostRelease(one, info('15.2-RELEASE-p1'))).toBe('15.2-RELEASE')
    expect(newHostRelease(one, info('15.1-RELEASE-p4'))).toBe('')
    expect(newHostRelease([...one, img('freebsd-15-2', '15.2-RELEASE')], info('15.2-RELEASE'))).toBe('')
    // no FreeBSD image at all: the empty page offers the first; an unreadable release says nothing
    expect(newHostRelease([], info('15.2-RELEASE'))).toBe('')
    expect(newHostRelease(one, info(''))).toBe('')
  })
})

describe('patchLevel', () => {
  it('is the pN of a release generation and nothing for a snapshot or an unknown one', () => {
    expect(patchLevel('15.1-RELEASE-p6')).toBe('p6')
    expect(patchLevel('15.1-RELEASE')).toBe('')
    expect(patchLevel('15.snap20261031190411')).toBe('')
    expect(patchLevel(undefined)).toBe('')
  })
})
