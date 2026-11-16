// The name rules of the server, in one place, with the hint every form shows. The server is the judge: these
// only say early what it would refuse. Keep them in step with internal/validate/names.go (Name),
// internal/validate/project.go (ProjectName), internal/service/resources.go (ValidObjectName),
// internal/validate/names.go (SetName: an address set name is part of a PF table name), sdk/api/names.go (NamePattern:
// the one rule for every name) and internal/wireguard (the interface wg-<name> has at most 15 characters).

export type NameRule = 'object' | 'project' | 'network' | 'jail' | 'volume' | 'image' | 'snapshot' | 'addressSet' | 'tunnel' | 'identity' | 'client' | 'node'

interface Rule {
  re: RegExp
  max: number
  hint: string
  reserved?: string[]
}

// The lengths of new objects (internal/validate): a project prefixes the OS name of its jails, a jail, volume or image and a snapshot share the 255 characters of a ZFS name.
// Objects created before these limits keep their longer names: an edit form never checks an existing name.
const letters = (max: number) => `Lowercase letters, digits and hyphens, starting with a letter, not ending in a hyphen, at most ${max} characters.`
/** api.NamePattern: lowercase letters, digits and hyphens, starting with a letter, not ending in a hyphen. The length is checked apart. */
export const NAME_PATTERN = /^[a-z]([a-z0-9-]*[a-z0-9])?$/

/** The rules by name. `object` covers storage, profiles, firewall policies and app instances' other objects. */
export const nameRules: Record<NameRule, Rule> = {
  object: { re: NAME_PATTERN, max: 63, hint: letters(63) },
  project: { re: NAME_PATTERN, max: 13, hint: letters(13) + ' Not "all" or "host".', reserved: ['all', 'host'] },
  network: { re: NAME_PATTERN, max: 13, hint: letters(13) },
  jail: { re: NAME_PATTERN, max: 32, hint: letters(32) },
  volume: { re: NAME_PATTERN, max: 32, hint: letters(32) },
  image: { re: NAME_PATTERN, max: 32, hint: letters(32) },
  snapshot: { re: NAME_PATTERN, max: 64, hint: letters(64) },
  addressSet: { re: NAME_PATTERN, max: 29, hint: letters(29) + ' Rules use it as set:name.' },
  tunnel: { re: NAME_PATTERN, max: 12, hint: 'Lowercase letters, digits and hyphens, starting with a letter, at most 12 characters: the interface is wg-<name>.' },
  identity: { re: NAME_PATTERN, max: 63, hint: letters(63) },
  // the backup node (internal/backupd): host, user and token names follow the same rule
  node: { re: NAME_PATTERN, max: 63, hint: letters(63) },
  client: { re: NAME_PATTERN, max: 63, hint: letters(63) },
}

/** The longest storage dataset path (pool/a/b): the rest of the 255 characters of a ZFS name is for the jails,
 *  volumes and snapshots below it. */
export const DATASET_MAX = 88

/** A size as the server parses it: digits, an optional K, M, G, T or P in either case, an optional B or iB
 *  ("512M", "4GiB", "1k", "100"); not zero. The server stores it as bytes. */
export function validSize(v: string): boolean {
  const m = /^(\d{1,18})(?:[KMGTPkmgtp](?:i?B)?|B)?$/.exec(v.trim())
  return !!m && /[1-9]/.test(m[1])
}

/** The hint shown under a name field. */
export function nameHint(rule: NameRule = 'object'): string {
  return nameRules[rule].hint
}

/** Empty when the name passes the rule, else the sentence to show under the field. An empty name is "required". */
export function nameProblem(v: string, rule: NameRule = 'object'): string {
  const r = nameRules[rule]
  if (!v) return 'Required.'
  if (v.length > r.max) return `At most ${r.max} characters.`
  if (r.reserved?.includes(v)) return `"${v}" is reserved.`
  if (!r.re.test(v)) return r.hint
  return ''
}

export function validName(v: string, rule: NameRule = 'object'): boolean {
  return nameProblem(v, rule) === ''
}
