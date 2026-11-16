// Pure helpers of the Create image dialog and the wizard's base image step. They mirror the server's checks
// (service.validateImage, the image sources in internal/imagegen/source.go) so a typing mistake shows early; the
// server is the judge and its message is shown as it comes.
import type { Image, ImageAutoUpgrade, ImageSpec, ServerInfo } from '@jailops/shared/api/types'
import { nameProblem } from '@jailops/shared/lib/names'

/** The kinds of image the API creates: FreeBSD from pkgbase, Alpine from its minirootfs, Debian with debootstrap. */
export type ImageKind = 'freebsd' | 'alpine' | 'debian'
export const IMAGE_KINDS: ImageKind[] = ['freebsd', 'alpine', 'debian']
const SOURCE: Record<ImageKind, { os: ImageSpec['os']; type: string }> = {
  freebsd: { os: 'freebsd', type: 'pkgbase' },
  alpine: { os: 'linux', type: 'minirootfs' },
  debian: { os: 'linux', type: 'debootstrap' },
}
/** The release a new image of each kind starts with when the host does not suggest one. */
export const DEFAULT_RELEASE: Record<ImageKind, string> = { freebsd: '15.1-RELEASE', alpine: '3.22', debian: 'trixie' }

/** The oldest FreeBSD release JailOps supports (the doctor check host.release). */
export const MIN_FREEBSD = { major: 15, minor: 1 }
export const ARCHES = ['amd64', 'arm64']
/** The time of day of the nightly upgrade when none is chosen (api.DefaultAutoUpgradeAt), in the host's time zone. */
export const DEFAULT_AUTO_AT = '03:00'

/** A FreeBSD release without its patch level: "15.1-RELEASE" for "15.1-RELEASE-p3" (api.BaseRelease). */
export function baseRelease(r: string): string {
  const i = r.indexOf('-p')
  return i > 0 ? r.slice(0, i) : r
}

/** The patch level of a generation's FreeBSD version, "p6" of "15.1-RELEASE-p6"; '' for a release without one, a
 *  snapshot of a branch or a generation built before JailOps recorded it. */
export function patchLevel(v: string | undefined): string {
  const i = (v ?? '').indexOf('-RELEASE-')
  return i > 0 ? v!.slice(i + '-RELEASE-'.length) : ''
}

/** The host's FreeBSD release as GET /api/v1 reports it (environment.kernel_version), without the patch level; ''
 *  when the server does not say or the value is not a release. */
export function hostRelease(info: ServerInfo | null | undefined): string {
  const r = baseRelease(info?.environment?.kernel_version ?? '')
  return freebsdReleaseProblem(r) ? '' : r
}
/** The host's architecture, '' when the server does not report it. */
export const hostArch = (info: ServerInfo | null | undefined): string => info?.environment?.arch ?? ''

/** MAJOR and MINOR of a release ("15.1-RELEASE-p3" is [15, 1]), null when it is not one. */
export function releaseNumbers(r: string): [number, number] | null {
  const m = /^([0-9]{1,4})\.([0-9]{1,4})([-.]|$)/.exec(r)
  return m ? [Number(m[1]), Number(m[2])] : null
}
/** Compares two releases by MAJOR.MINOR: negative when a is older, 0 for the same release. */
export function compareRelease(a: [number, number], b: [number, number]): number {
  return a[0] - b[0] || a[1] - b[1]
}

/** The name an image of a release is proposed with: one image is one release, so the release is in the name
 *  ("freebsd-15-1" for 15.1-RELEASE, api.ImageNameForRelease; "alpine-3-22", "debian-trixie"). The kind alone when
 *  the release is not one yet. */
export function imageNameFor(kind: ImageKind, release: string): string {
  const r = release.trim()
  if (kind === 'debian') return /^[a-z][a-z0-9]*$/.test(r) ? `debian-${r}` : 'debian'
  const n = releaseNumbers(r.replace(/^v/, ''))
  return n ? `${kind}-${n[0]}-${n[1]}` : kind
}

// validate.OSRelease: 15.1, 15.1-RELEASE, 15.1-RELEASE-p3
const FREEBSD_RE = /^[0-9]{1,3}\.[0-9]{1,3}(-[A-Za-z0-9]{1,16}(-p[0-9]{1,4})?)?$/

/** The problem of a FreeBSD release, or '': the server's form, and nothing older than 15.1. */
export function freebsdReleaseProblem(r: string): string {
  if (!r) return 'Required.'
  if (!FREEBSD_RE.test(r)) return 'A release such as 15.1-RELEASE.'
  const [major, minor] = r.split('-')[0].split('.').map(Number)
  if (major < MIN_FREEBSD.major || (major === MIN_FREEBSD.major && minor < MIN_FREEBSD.minor)) return 'JailOps supports FreeBSD 15.1 and later.'
  return ''
}

/** The problem of a release for an image kind, or ''. */
export function releaseProblem(kind: ImageKind, r: string): string {
  if (kind === 'freebsd') return freebsdReleaseProblem(r)
  if (!r) return 'Required.'
  // Minirootfs.CheckSpec: <major>.<minor> or <major>.<minor>.<patch>, an optional v in front
  if (kind === 'alpine') return /^v?[0-9]+\.[0-9]+(\.[0-9]+)?$/.test(r) ? '' : 'An Alpine release such as 3.22 or 3.22.1.'
  // Debootstrap.CheckSpec: a suite name
  return r.startsWith('-') || /[\s/]/.test(r) ? 'A Debian suite name such as trixie.' : ''
}

export interface ImageForm {
  kind: ImageKind
  name: string
  release: string
  arch: string
  /** The keyring that checks a Debian release (source.keys), a path on the host. */
  keys: string
  build: boolean
  /** The nightly upgrade (spec.auto_upgrade): on, its time of day, and the packages inside the jails too. */
  auto: boolean
  at: string
  packages: boolean
}

/** The form a new image starts with: the image of this host's release, upgraded every night (a FreeBSD image).
 *  `release` proposes another release (the new release notice). */
export function initialImageForm(info: ServerInfo | null | undefined, kind: ImageKind = 'freebsd', release = ''): ImageForm {
  const r = release || (kind === 'freebsd' && hostRelease(info)) || DEFAULT_RELEASE[kind]
  return { kind, name: imageNameFor(kind, r), release: r, arch: hostArch(info), keys: '', build: true, auto: false, at: DEFAULT_AUTO_AT, packages: true }
}

/** The problem of the time of day of the nightly upgrade, or '': HH:MM, as the server reads it. */
export function autoAtProblem(at: string): string {
  if (!at) return 'Required.'
  const m = /^([0-9]{2}):([0-9]{2})$/.exec(at)
  return m && Number(m[1]) < 24 && Number(m[2]) < 60 ? '' : 'A time of day such as 03:00.'
}

export type ImageField = 'name' | 'release' | 'arch' | 'keys' | 'at'

/** Field problems of the form, by field; an empty object when it can be sent. */
export function imageProblems(f: ImageForm, taken: string[]): Partial<Record<ImageField, string>> {
  const e: Partial<Record<ImageField, string>> = {}
  const n = nameProblem(f.name, 'image')
  if (n) e.name = n
  else if (taken.includes(f.name)) e.name = `An image named ${f.name} exists already.`
  const r = releaseProblem(f.kind, f.release.trim())
  if (r) e.release = r
  if (!ARCHES.includes(f.arch)) e.arch = 'Choose amd64 or arm64.'
  if (f.auto) {
    const a = autoAtProblem(f.at)
    if (a) e.at = a
  }
  if (f.kind === 'debian' && !/^\/\S+$/.test(f.keys.trim())) e.keys = 'The path of the keyring on the host, for example /usr/local/share/keyrings/debian-archive-keyring.gpg.'
  return e
}

/** The body of POST /images for the form: the definition only; the first generation is built separately. */
export function imageBody(f: ImageForm): Pick<Image, 'metadata' | 'spec'> {
  const src = SOURCE[f.kind]
  return {
    metadata: { name: f.name },
    spec: { os: src.os, release: f.release.trim(), arch: f.arch, source: { type: src.type, ...(f.kind === 'debian' ? { keys: f.keys.trim() } : {}) }, ...(f.auto ? { auto_upgrade: autoUpgradeSpec(true, f.at, f.packages) } : {}) },
  }
}

/** spec.auto_upgrade as it is sent: the time only when it is not the default. */
export function autoUpgradeSpec(enabled: boolean, at: string, packages: boolean): ImageAutoUpgrade {
  return { enabled, ...(at && at !== DEFAULT_AUTO_AT ? { at } : {}), packages }
}

/** Whether apps have their default image: 'none' when there is no FreeBSD image at all (the base image is
 *  missing), 'ok' otherwise. */
export function baseImageState(images: Image[]): 'none' | 'ok' {
  return images.some((i) => i.spec.os === 'freebsd') ? 'ok' : 'none'
}

/** The FreeBSD images, newest release first, then by name: the order the install dialog and the jail form offer
 *  them in. */
export function freebsdImages(images: Image[]): Image[] {
  const rel = (i: Image) => releaseNumbers(i.spec.release) ?? [0, 0]
  return images.filter((i) => i.spec.os === 'freebsd').sort((a, b) => compareRelease(rel(b), rel(a)) || (a.metadata.name < b.metadata.name ? -1 : a.metadata.name > b.metadata.name ? 1 : 0))
}

/** The image an app installs from when none is named, as the server picks it (service.defaultAppImage): the
 *  FreeBSD image of the newest release this host's kernel runs, the first by name among equals; '' when there is
 *  none. An unknown host release limits nothing. */
export function defaultImage(images: Image[], host: string): string {
  const h = releaseNumbers(host)
  const ok = freebsdImages(images).filter((i) => {
    const r = releaseNumbers(i.spec.release)
    return r && (!h || compareRelease(r, h) <= 0)
  })
  return ok[0]?.metadata.name ?? ''
}

/** The label of an image in a select: its name and its release ("freebsd-15-1 (15.1-RELEASE)"). */
export const imageLabel = (i: Image): string => `${i.metadata.name} (${i.spec.release})`

/** The release of this host when it is newer than the release of every FreeBSD image there is (the host was
 *  upgraded, its image was not made yet); '' otherwise, and when there is no FreeBSD image at all (the empty page
 *  offers the first one). */
export function newHostRelease(images: Image[], info: ServerInfo | null | undefined): string {
  const host = hostRelease(info)
  const h = releaseNumbers(host)
  const fb = freebsdImages(images)
  if (!h || !fb.length) return ''
  const newest = releaseNumbers(fb[0].spec.release)
  return newest && compareRelease(h, newest) > 0 ? host : ''
}
