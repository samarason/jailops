/** The command the operator runs on the new client. The token carries the server fingerprint, so the client pins it. */
export function remoteAddCommand(host: string, token: string): string {
  return `jailops remote add myhost ${host} --token ${token}`
}

/** An identity needs projects or global: never neither, and never both meaning "all by being empty". */
export function scopeValid(projects: string[], global: boolean): boolean {
  return global || projects.length > 0
}
