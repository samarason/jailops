<script setup lang="ts">
import { computed, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import Icon from '@jailops/shared/components/Icon.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import { DEVICE_KINDS, deviceNames, flatten, rowsFor, type DeviceKind } from '@/lib/configKeys'
import { isGlobalAdmin } from '@/composables/project'
import type { Jail } from '@jailops/shared/api/types'

const props = defineProps<{ jail: Jail; sources: Record<string, { value: string; source: string }> }>()
const emit = defineEmits<{ saved: [] }>()
const error = ref<ApiError | null>(null)
const profilesText = ref((props.jail.spec.profiles ?? []).join(', '))
const own = computed(() => flatten(props.jail.spec))

const rowsOf = (kind: DeviceKind, dev: string) => rowsFor(props.jail.spec).filter((r) => r.group === kind && r.dev === dev)
/** Keys a device gets from profiles that the jail itself does not set. */
const inherited = computed(() => Object.entries(props.sources).filter(([k, v]) => v.source !== 'jail' && DEVICE_KINDS.some((d) => k.startsWith(d + '.'))))
const devicesOf = (kind: DeviceKind) => {
  const names = new Set(deviceNames(props.jail.spec, kind))
  for (const [k] of inherited.value) if (k.startsWith(kind + '.')) names.add(k.split('.')[1])
  return [...names]
}

/** A proxy device publishes a port of the host: only a global administrator adds one. */
const canAdd = (kind: DeviceKind) => kind !== 'proxy' || isGlobalAdmin()
const nameFor = ref<Record<string, string>>({})
async function change(set: Record<string, string>, unset: string[], title: string): Promise<void> {
  error.value = null
  try {
    await runOp(title, () => api.jailConfig.post(props.jail.metadata.name, { set, unset }))
    emit('saved')
  } catch (e) {
    error.value = e instanceof ApiError ? e : null
  }
}
/** The key that creates a device, with a first value. */
const FIRST: Record<DeviceKind, [string, string]> = { nic: ['network', 'lan'], disk: ['mount', '/var/db/x'], devfs: ['device', 'tun'], proxy: ['listen', ':8080'] }
async function addDevice(kind: DeviceKind): Promise<void> {
  const n = (nameFor.value[kind] ?? '').trim()
  if (!n) return
  const [field, sample] = FIRST[kind]
  await change({ [`${kind}.${n}.${field}`]: kind === 'disk' ? `/var/db/${n}` : sample }, [], s.devices.addDevice + ': ' + n)
  nameFor.value[kind] = ''
}
const removeDevice = (kind: DeviceKind, name: string) => change({}, [`${kind}.${name}`], s.devices.removeDevice + ': ' + name)
const saveProfiles = () => change({ profiles: profilesText.value.replace(/\s+/g, '') }, [], s.devices.profiles)
const from = (name: string) => {
  const v = props.sources[name]
  return !v ? '' : v.source === 'jail' ? s.devices.fromJail : s.devices.fromProfile(v.source)
}
const valueOf = (name: string) => props.sources[name]?.value ?? ''
const fieldsOf = (kind: DeviceKind, dev: string) => {
  const mine = rowsOf(kind, dev).map((r) => r.name)
  const extra = inherited.value.map(([k]) => k).filter((k) => k.startsWith(`${kind}.${dev}.`))
  return [...new Set([...mine, ...extra])].filter((n) => valueOf(n) !== '' || own.value[n] !== undefined)
}
</script>

<template>
  <div class="stack" data-test="devices-tab">
    <p class="muted">{{ s.devices.lead }}</p>
    <ErrorPanel v-if="error" :error="error" />

    <section class="panel">
      <header><h2>{{ s.devices.profiles }}</h2></header>
      <div class="body stack">
        <p class="muted">{{ s.devices.profilesText }}</p>
        <div class="row"><input v-model="profilesText" class="mono grow" type="text" :aria-label="s.devices.profileList" style="max-width: 420px" /><button class="btn" type="button" data-test="save-profiles" @click="saveProfiles">{{ s.config.save }}</button></div>
        <span class="hint faint">{{ s.devices.profileListHint }}</span>
      </div>
    </section>

    <section v-for="kind in DEVICE_KINDS" :key="kind" class="panel" :data-kind="kind">
      <header><h2>{{ s.devices.kinds[kind] }}</h2>
        <form class="row" :title="canAdd(kind) ? undefined : s.devices.proxyGlobal" @submit.prevent="canAdd(kind) && addDevice(kind)"><input v-model="nameFor[kind]" class="mono" type="text" :disabled="!canAdd(kind)" :placeholder="s.devices.deviceName" :aria-label="s.devices.deviceName + ' ' + kind" style="width: 130px" /><button class="btn btn-sm" type="submit" :disabled="!canAdd(kind)"><Icon name="plus" />{{ s.devices.addDevice }}</button></form>
      </header>
      <p v-if="!devicesOf(kind).length" class="empty">{{ s.devices.none }}</p>
      <div v-for="dev in devicesOf(kind)" :key="dev" class="dev" :data-device="kind + '.' + dev">
        <div class="row" style="justify-content: space-between"><strong class="mono">{{ kind }}.{{ dev }}</strong>
          <button class="btn btn-sm btn-danger" type="button" @click="removeDevice(kind, dev)"><Icon name="trash" />{{ s.devices.removeDevice }}</button></div>
        <div class="table-wrap"><table>
          <tbody><tr v-for="n in fieldsOf(kind, dev)" :key="n" :data-field="n"><td class="mono faint" style="width: 40%">{{ n.split('.').slice(2).join('.') }}</td><td class="mono">{{ valueOf(n) }}</td><td class="faint" data-test="origin">{{ from(n) }}</td></tr></tbody>
        </table></div>
      </div>
    </section>
  </div>
</template>

<style>
.dev { padding: 8px 12px; border-top: 1px solid var(--border); }
</style>
