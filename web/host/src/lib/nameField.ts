// The message under a name field: the rule itself is the hint above it, so a name that breaks it says so in
// a few words instead of repeating the rule (shared lib/names.ts holds the rules).
import { nameHint, nameProblem, type NameRule } from '@jailops/shared/lib/names'

export const BAD_NAME = 'This name does not follow the rule above.'

export function nameError(v: string, rule: NameRule = 'object'): string {
  const p = nameProblem(v, rule)
  return p === nameHint(rule) ? BAD_NAME : p
}
