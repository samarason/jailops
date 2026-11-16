<script setup lang="ts">
import { computed, ref } from 'vue'
import Icon from '@jailops/shared/components/Icon.vue'
import NetworkForm from '@/components/NetworkForm.vue'
import NetTabs from '@/components/NetTabs.vue'
import RenameDialog from '@/components/RenameDialog.vue'
import { canRename } from '@/composables/rename'
import { ifMatch } from '@/lib/rename'
import { isGlobalAdmin } from '@/composables/project'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { confirmAction } from '@jailops/shared/composables/confirm'
import { rangeSize, percent, sentence } from '@jailops/shared/lib/format'
import AddrCopy from '@jailops/shared/components/AddrCopy.vue'
import Meter from '@jailops/shared/components/Meter.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import type { Lease, Network } from '@jailops/shared/api/types'

const l = useLoad(async () => {
  const nets = await api.networks.list()
  const leases: Record<string, Lease[]> = {}
  await Promise.all(nets.map(async (n) => (leases[n.metadata.name] = await api.networks.leases(n.metadata.name).catch(() => []))))
  const projects = await api.projects.list().catch(() => [])
  return { nets, leases, projects }
})
const creating = ref(false)
const editing = ref<{ net: Network; etag?: string } | null>(null)
async function edit(n: Network): Promise<void> {
  // the generation read now goes with the PUT, so an edit made meanwhile is refused rather than overwritten
  const r = await api.networks.get(n.metadata.name).catch(() => ({ data: n, etag: undefined }))
  editing.value = { net: r.data, etag: r.etag }
}
/** The jails with an address on a network (its leases). */
const jailsOn = (name: string) => [...new Set((l.data.value?.leases[name] ?? []).map((x) => x.jail))].sort()
// Tier 3 while jails are attached (they lose their address), tier 2 otherwise.
function remove(n: Network): void {
  const name = n.metadata.name
  const jails = jailsOn(name)
  confirmAction({
    title: s.networks.deleteTitle(name), confirmLabel: s.networks.deleteGo, danger: true,
    text: jails.length ? `${s.networks.deleteText} ${s.networks.deleteAttached(jails.length)}` : s.networks.deleteText,
    items: jails, itemsLabel: s.networks.attachedJails, typeName: jails.length ? name : undefined,
    run: () => runOp(s.networks.deleteTitle(name), () => api.networks.remove(name)),
    done: () => void l.reload(),
  })
}
const canWrite = computed(() => isGlobalAdmin())
// Rename (extension rename): the generation of the list goes with it as If-Match
const renaming = ref<Network | null>(null)
const open = ref<Record<string, boolean>>({})

/** The project a network is granted to: a network belongs to at most one. */
function holders(name: string) {
  return (l.data.value?.projects ?? []).filter((p) => (p.spec.networks ?? []).some((g) => g.network === name)).map((p) => ({ project: p.metadata.name }))
}
function total(n: Network): number {
  const t = (n.status.allocated ?? 0) + (n.status.free ?? 0)
  return t || rangeSize(n.spec.ipv4?.range ?? '')
}
function used(n: Network): number {
  return percent(n.status.allocated ?? 0, total(n))
}
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.networks.title }}</h1><button class="btn btn-primary" type="button" :disabled="!canWrite" data-test="new-network" @click="creating = true"><Icon name="plus" />{{ s.networks.create }}</button></div>
    <NetTabs />
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <p v-if="!l.data.value?.nets.length" class="empty panel">{{ s.networks.empty }}</p>
      <div class="stack">
        <section v-for="n in l.data.value?.nets" :key="n.metadata.name" class="panel" :data-network="n.metadata.name">
          <header>
            <div class="row">
              <h2 class="mono">{{ n.metadata.name }}</h2>
              <span v-if="n.spec.uplink" class="faint mono">{{ s.networks.via(n.spec.uplink) }}</span>
              <span class="faint">{{ s.networks.links(n.status.links?.length ?? 0) }}</span>
            </div>
            <div v-if="canWrite" class="row-actions">
              <button class="btn btn-sm" type="button" :data-test="`edit-net-${n.metadata.name}`" @click="edit(n)">{{ s.networks.edit }}</button>
              <button v-if="canRename('network')" class="btn btn-sm" type="button" :data-test="`rename-net-${n.metadata.name}`" @click="renaming = n">{{ s.rename.open(s.rename.kinds.network) }}</button>
              <button class="btn btn-sm btn-danger" type="button" :data-test="`delete-net-${n.metadata.name}`" @click="remove(n)">{{ s.networks.delete }}</button>
            </div>
          </header>
          <div class="body stack">
            <div>
              <div class="row" style="justify-content: space-between"><h3>{{ s.networks.utilisation }}</h3><span class="mono muted">{{ s.networks.allocated(n.status.allocated ?? 0, total(n)) }}</span></div>
              <Meter :value="used(n)" :label="s.networks.utilisation" :warn-at="80" :danger-at="95" />
            </div>
            <div class="grid-2">
              <dl class="kv">
                <dt>{{ s.networks.ipv4 }}</dt><dd v-if="!n.spec.ipv4" class="faint">{{ s.networks.none }}</dd><dd v-else class="mono">{{ n.spec.ipv4.subnet }}</dd>
                <template v-if="n.spec.ipv4">
                  <dt>{{ s.networks.gateway }}</dt><dd><AddrCopy :value="n.spec.ipv4.gateway" /></dd>
                  <dt>{{ s.networks.range }}</dt><dd><AddrCopy :value="n.spec.ipv4.range" /></dd>
                  <dt v-if="n.spec.ipv4.exclude?.length">{{ s.networks.exclude }}</dt><dd v-if="n.spec.ipv4.exclude?.length" class="mono">{{ n.spec.ipv4.exclude.join(', ') }}</dd>
                  <dt>{{ s.networks.nat }}</dt><dd>{{ n.spec.ipv4.nat ? s.networks.on : s.networks.off }}</dd>
                </template>
              </dl>
              <dl class="kv">
                <dt>{{ s.networks.ipv6 }}</dt>
                <dd v-if="!n.spec.ipv6 || n.spec.ipv6.mode === 'none'" class="faint">{{ s.networks.none }}</dd>
                <dd v-else><span class="badge" :class="n.spec.ipv6.mode === 'proxy' ? 'warn' : 'info'" :data-ipv6-mode="n.spec.ipv6.mode">{{ sentence(n.spec.ipv6.mode) }}</span></dd>
                <template v-if="n.spec.ipv6 && n.spec.ipv6.mode !== 'none'">
                  <dt>{{ s.networks.subnet }}</dt><dd><AddrCopy :value="n.spec.ipv6.subnet" /></dd>
                  <dt>{{ s.networks.gateway }}</dt><dd><AddrCopy value="fe80::1" /></dd>
                  <dt>{{ s.networks.range }}</dt><dd><AddrCopy :value="n.spec.ipv6.range" /></dd>
                </template>
                <dt v-if="n.spec.dns?.length">{{ s.networks.dns }}</dt><dd v-if="n.spec.dns?.length"><AddrCopy v-for="a in n.spec.dns" :key="a" :value="a" style="margin-right: 8px" /></dd>
                <dt v-if="n.spec.mtu">{{ s.networks.mtu }}</dt><dd v-if="n.spec.mtu" class="mono">{{ n.spec.mtu }}</dd>
              </dl>
            </div>
            <p v-if="n.spec.ipv6?.mode" class="faint">{{ s.networks.modeHint[n.spec.ipv6.mode] }}</p>
            <Callout v-if="n.status.orphans?.length" tone="warn">
              <strong>{{ s.networks.orphans }}</strong>: <span class="mono">{{ n.status.orphans.join(', ') }}</span><br /><span class="muted">{{ s.networks.orphanHint }}</span>
            </Callout>
            <div v-if="holders(n.metadata.name).length" data-test="net-projects">
              <h3>{{ s.networks.projects }}</h3>
              <p><router-link v-for="h in holders(n.metadata.name)" :key="h.project" class="mono" :data-holder="h.project" :to="`/projects/${h.project}`">{{ h.project }}</router-link></p>
            </div>
            <div>
              <button class="btn btn-sm" type="button" :aria-expanded="!!open[n.metadata.name]" @click="open[n.metadata.name] = !open[n.metadata.name]">{{ s.networks.leases }} ({{ l.data.value?.leases[n.metadata.name]?.length ?? 0 }})</button>
              <div v-if="open[n.metadata.name]" class="table-wrap" style="margin-top: 8px">
                <p v-if="!l.data.value?.leases[n.metadata.name]?.length" class="muted">{{ s.networks.noLeases }}</p>
                <table v-else class="rtable">
                  <thead><tr><th>{{ s.networks.address }}</th><th>{{ s.networks.jail }}</th></tr></thead>
                  <tbody><tr v-for="x in l.data.value?.leases[n.metadata.name]" :key="x.address"><td :data-label="s.networks.address"><AddrCopy :value="x.address" /></td><td :data-label="s.networks.jail"><router-link class="mono" :to="`/jails/${x.jail}`">{{ x.jail }}</router-link></td></tr></tbody>
                </table>
              </div>
            </div>
          </div>
        </section>
      </div>
    </LoadState>
    <NetworkForm :open="creating" @close="creating = false" @done="l.reload" />
    <RenameDialog :open="!!renaming" kind="network" :name="renaming?.metadata.name ?? ''" :etag="ifMatch(renaming?.metadata.generation)" @close="renaming = null" @done="l.reload" />
    <NetworkForm :open="!!editing" :network="editing?.net" :etag="editing?.etag" @close="editing = null" @done="l.reload" />
  </div>
</template>
