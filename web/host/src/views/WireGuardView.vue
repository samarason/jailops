<script setup lang="ts">
import { computed, ref } from 'vue'
import Icon from '@jailops/shared/components/Icon.vue'
import NetTabs from '@/components/NetTabs.vue'
import WireGuardServerForm from '@/components/WireGuardServerForm.vue'
import WireGuardPeerDialog from '@/components/WireGuardPeerDialog.vue'
import WireGuardJoinDialog from '@/components/WireGuardJoinDialog.vue'
import { isGlobalAdmin } from '@/composables/project'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { hasExt } from '@jailops/shared/composables/session'
import { confirmAction } from '@jailops/shared/composables/confirm'
import { refreshPending } from '@/composables/pending'
import { DEFAULT_CONFIRM } from '@/lib/hostfw'
import { wgCover, withWgAllow } from '@/lib/wgfw'
import { runOp } from '@jailops/shared/composables/ops'
import { ago, bytes } from '@jailops/shared/lib/format'
import AddrCopy from '@jailops/shared/components/AddrCopy.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ConfirmDialog from '@jailops/shared/components/ConfirmDialog.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import Modal from '@jailops/shared/components/Modal.vue'
import { handshakeLabel, peerRows, reach } from '@/lib/wireguard'
import type { WireGuard, WireGuardKeys } from '@jailops/shared/api/types'

const l = useLoad(async () => {
  const tunnels = await api.wireguard.list()
  const nets = (await api.networks.list().catch(() => [])).map((n) => n.metadata.name)
  // the host firewall, when JailOps manages it, decides whether peers reach a listen port
  const fw = hasExt('host_firewall') ? await api.host.firewall().catch(() => undefined) : undefined
  return { tunnels, nets, fw }
})
const canWrite = computed(() => isGlobalAdmin())
const creating = ref(false)
const joining = ref(false)
const peerOf = ref('')
const deleting = ref<WireGuard | null>(null)
const removingPeer = ref<{ server: string; peer: string } | null>(null)
const rotating = ref<WireGuard | null>(null)
const rotated = ref<(WireGuardKeys & { name: string }) | null>(null)

const hs = (ts: string | undefined) => handshakeLabel(ts, (t) => ago(t), s.wireguard.never)
const port = (w: WireGuard) => w.status.listen_port ?? w.spec.listen_port ?? 51820
const cover = (w: WireGuard) => wgCover(l.data.value?.fw, port(w))
/** One allow row in the host firewall, with the confirmation window: the bar at the top then asks to keep it. */
function addToHostFirewall(w: WireGuard): void {
  const fw = l.data.value?.fw
  if (!fw) return
  const p = port(w)
  confirmAction({
    title: s.wireguard.fwAddTitle(p), confirmLabel: s.wireguard.fwAdd, text: s.wireguard.fwAddText(p, DEFAULT_CONFIRM),
    run: async () => {
      await runOp(s.wireguard.fwAddTitle(p), () => api.host.applyFirewall({ spec: withWgAllow(fw, p, s.wireguard.fwComment(w.metadata.name)), confirm_within: DEFAULT_CONFIRM }))
      await refreshPending()
    },
    done: () => void l.reload(),
  })
}

async function setUp(w: WireGuard, up: boolean): Promise<void> {
  const n = w.metadata.name
  await runOp(`${up ? s.wireguard.bringUp : s.wireguard.takeDown}: ${n}`, () => (up ? api.wireguard.up(n) : api.wireguard.down(n))).catch(() => undefined)
  await l.reload()
}
const removeTunnel = () => api.wireguard.remove(deleting.value?.metadata.name ?? '')
const removePeer = () => api.wireguard.removePeer(removingPeer.value?.server ?? '', removingPeer.value?.peer ?? '')
async function rotate(): Promise<void> {
  const w = rotating.value!
  const r = await api.wireguard.rotateKeys(w.metadata.name)
  if (r.kind === 'sync') rotated.value = { ...r.data, name: w.metadata.name }
  await l.reload()
}
</script>

<template>
  <div>
    <div class="page-head">
      <div><h1>{{ s.wireguard.title }}</h1><p class="muted">{{ s.wireguard.lead }}</p></div>
      <div class="row">
        <button class="btn" type="button" :disabled="!canWrite" data-test="wg-join" @click="joining = true"><Icon name="plus" />{{ s.wireguard.join }}</button>
        <button class="btn btn-primary" type="button" :disabled="!canWrite" data-test="wg-new" @click="creating = true"><Icon name="plus" />{{ s.wireguard.create }}</button>
      </div>
    </div>
    <NetTabs />
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <p v-if="!l.data.value?.tunnels.length" class="empty panel">{{ s.wireguard.empty }}</p>
      <div class="stack">
        <section v-for="w in l.data.value?.tunnels" :key="w.metadata.name" class="panel" :data-wg="w.metadata.name">
          <header>
            <div class="row">
              <h2 class="mono">{{ w.metadata.name }}</h2>
              <span class="badge" :class="w.spec.mode === 'server' ? 'info' : 'warn'" :data-wg-mode="w.spec.mode">{{ w.spec.mode === 'server' ? s.wireguard.server : s.wireguard.client }}</span>
              <span class="pill" :class="w.status.up ? 'ok' : 'danger'" data-test="wg-state">{{ w.status.up ? s.wireguard.up : s.wireguard.down }}</span>
              <span v-if="w.spec.mode === 'server'" class="faint">{{ s.wireguard.peersCount(w.spec.peers?.length ?? 0) }}</span>
            </div>
          </header>
          <div class="body stack">
            <dl class="kv wg-kv">
              <dt>{{ s.wireguard.iface }}</dt><dd class="mono nowrap">{{ w.spec.interface ?? w.status.interface }}</dd>
              <dt>{{ s.wireguard.address }}</dt><dd class="wg-addrs"><AddrCopy v-for="a in w.spec.address" :key="a" :value="a" /></dd>
              <dt>{{ s.wireguard.reach }}</dt><dd class="mono wg-reach">{{ reach(w) }}</dd>
              <dt>{{ s.wireguard.publicKey }}</dt><dd class="wg-key"><AddrCopy :value="w.status.public_key" /></dd>
              <template v-if="w.spec.networks?.length"><dt>{{ s.wireguard.networks }}</dt><dd><span v-for="n in w.spec.networks" :key="n" class="chip mono">{{ n }}</span></dd></template>
            </dl>
            <p v-if="w.spec.down" class="muted">{{ s.wireguard.downHint }}</p>
            <template v-if="w.spec.mode === 'server'">
              <Callout v-if="cover(w).state === 'allowed'" tone="ok" data-test="wg-fw">{{ s.wireguard.fwAllowed(port(w), (cover(w) as { from: string[] }).from.join(', ')) }} <router-link to="/host">{{ s.wireguard.fwHostLink }}</router-link></Callout>
              <Callout v-else-if="cover(w).state === 'open'" tone="ok" data-test="wg-fw">{{ s.wireguard.fwOpen(port(w)) }}</Callout>
              <Callout v-else-if="cover(w).state === 'missing'" tone="warn" data-test="wg-fw">
                <p>{{ s.wireguard.fwMissing(port(w)) }}</p>
                <button v-if="canWrite" class="btn btn-sm" type="button" data-test="wg-fw-add" @click="addToHostFirewall(w)">{{ s.wireguard.fwAdd }}</button>
              </Callout>
              <Callout v-else-if="w.status.firewall_rule" tone="info" data-test="wg-fw">
                <strong>{{ s.wireguard.firewallRule }}</strong>: <code class="mono wg-rule">{{ w.status.firewall_rule }}</code><br /><span class="muted">{{ s.wireguard.firewallHint }}</span>
              </Callout>
            </template>
            <Callout v-for="x in w.status.warnings ?? []" :key="x" tone="warn">{{ x }}</Callout>
            <div>
              <div class="row" style="justify-content: space-between"><h3>{{ s.wireguard.peers }}</h3>
                <button v-if="w.spec.mode === 'server'" class="btn btn-sm" type="button" :disabled="!canWrite" data-test="wg-add-peer" @click="peerOf = w.metadata.name"><Icon name="plus" />{{ s.wireguard.addPeer }}</button></div>
              <p v-if="!peerRows(w).length" class="muted">{{ s.wireguard.noPeers }}</p>
              <div v-else class="table-wrap">
                <table data-test="wg-peers" class="rtable">
                  <thead><tr><th>{{ s.wireguard.peerName }}</th><th>{{ s.wireguard.peerAddress }}</th><th>{{ s.wireguard.handshake }}</th><th>{{ s.wireguard.transfer }}</th><th v-if="w.spec.mode === 'server'"><span class="sr-only">{{ s.wireguard.removePeer }}</span></th></tr></thead>
                  <tbody>
                    <tr v-for="p in peerRows(w)" :key="p.publicKey" :data-peer="p.name">
                      <td class="mono nowrap" :data-label="s.wireguard.peerName">{{ p.name }}</td>
                      <td class="mono" :data-label="s.wireguard.peerAddress"><span v-for="a in p.address.split(', ').filter(Boolean)" :key="a" class="wg-tok">{{ a }}</span></td>
                      <td class="nowrap" :data-label="s.wireguard.handshake" data-test="wg-handshake">{{ hs(p.handshake) }}</td>
                      <td class="mono nowrap" :data-label="s.wireguard.transfer">{{ bytes(p.rx ?? 0) }} / {{ bytes(p.tx ?? 0) }}</td>
                      <td v-if="w.spec.mode === 'server'" class="actions"><button class="btn btn-sm btn-danger" type="button" :disabled="!canWrite" :aria-label="`${s.wireguard.removePeer} ${p.name}`" @click="removingPeer = { server: w.metadata.name, peer: p.name }">{{ s.wireguard.removePeer }}</button></td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
            <div class="row-actions">
              <button v-if="w.spec.down" class="btn btn-sm" type="button" :disabled="!canWrite" data-test="wg-up" @click="setUp(w, true)">{{ s.wireguard.bringUp }}</button>
              <button v-else class="btn btn-sm" type="button" :disabled="!canWrite" data-test="wg-down" @click="setUp(w, false)">{{ s.wireguard.takeDown }}</button>
              <button class="btn btn-sm" type="button" :disabled="!canWrite" data-test="wg-rotate" @click="rotating = w">{{ s.wireguard.rotate }}</button>
              <button class="btn btn-sm btn-danger" type="button" :disabled="!canWrite" data-test="wg-delete" @click="deleting = w">{{ s.wireguard.delete }}</button>
            </div>
          </div>
        </section>
      </div>
    </LoadState>

    <WireGuardServerForm :open="creating" :networks="l.data.value?.nets ?? []" @close="creating = false" @done="l.reload" />
    <WireGuardJoinDialog :open="joining" @close="joining = false" @done="l.reload" />
    <WireGuardPeerDialog :open="!!peerOf" :server="peerOf" @close="peerOf = ''" @done="l.reload" />
    <ConfirmDialog :open="!!deleting" :title="s.wireguard.deleteTitle(deleting?.metadata.name ?? '')" :confirm-label="s.wireguard.delete" danger
      :run="removeTunnel" @close="deleting = null" @done="l.reload">
      <Callout tone="warn">{{ s.wireguard.deleteText(deleting?.metadata.name ?? '') }}</Callout>
    </ConfirmDialog>
    <ConfirmDialog :open="!!removingPeer" :title="s.wireguard.removePeerTitle(removingPeer?.peer ?? '')" :confirm-label="s.wireguard.removePeer" danger
      :run="removePeer" @close="removingPeer = null" @done="l.reload">
      <Callout tone="warn">{{ s.wireguard.removePeerText(removingPeer?.peer ?? '', removingPeer?.server ?? '') }}</Callout>
    </ConfirmDialog>
    <ConfirmDialog :open="!!rotating" :title="s.wireguard.rotateTitle(rotating?.metadata.name ?? '')" :confirm-label="s.wireguard.rotate" :run="rotate" @close="rotating = null">
      <Callout tone="warn">{{ s.wireguard.rotateText }}</Callout>
    </ConfirmDialog>
    <Modal :open="!!rotated" :title="s.wireguard.rotated" @close="rotated = null">
      <p class="mono wg-key" data-test="wg-rotated-key">{{ rotated?.public_key }}</p>
      <Callout v-if="rotated?.warning" tone="warn">{{ rotated.warning }}</Callout>
      <template #footer><button class="btn btn-primary" type="button" @click="rotated = null">{{ s.app.close }}</button></template>
    </Modal>
  </div>
</template>

<style>
/* addresses and keys break as whole tokens: one address per line, a key only where it must */
.wg-addrs { display: flex; flex-wrap: wrap; gap: 2px 12px; }
.wg-tok { display: block; white-space: nowrap; }
.wg-reach { overflow-wrap: anywhere; }
.wg-key .mono, p.wg-key { overflow-wrap: anywhere; word-break: break-all; }
.wg-key .addr { flex-wrap: nowrap; align-items: flex-start; max-width: 100%; }
.wg-rule { white-space: normal; overflow-wrap: anywhere; }
dl.wg-kv dd { overflow-wrap: normal; }
@media (max-width: 600px) {
  /* label over value: a narrow value column broke words letter by letter */
  dl.wg-kv { grid-template-columns: minmax(0, 1fr); gap: 0; }
  dl.wg-kv dt { margin-top: 8px; font-size: 12px; }
  dl.wg-kv dt:first-child { margin-top: 0; }
}
</style>
