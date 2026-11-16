<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { common as s } from '../i18n/common'
import { session, loginWithToken, loginWithPassword } from '../composables/session'
import { ApiError } from '../api/client'
import ErrorPanel from './ErrorPanel.vue'

withDefaults(defineProps<{ brand: string; totp?: boolean }>(), { totp: true })
const router = useRouter()
const route = useRoute()
const mode = ref<'token' | 'user'>('token')
const token = ref('')
const username = ref('')
const password = ref('')
const totp = ref('')
const busy = ref(false)
const error = ref<ApiError | null>(null)

async function submit(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    if (mode.value === 'token') await loginWithToken(token.value)
    else await loginWithPassword(username.value, password.value, totp.value)
    const next = typeof route.query.next === 'string' && route.query.next.startsWith('/') && !route.query.next.startsWith('//') ? route.query.next : '/'
    await router.replace(next)
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <main id="main" class="login">
    <form class="panel login-card" @submit.prevent="submit">
      <header><h1>{{ brand }}</h1><span class="faint mono">{{ session.info?.hostname }}</span></header>
      <div class="body">
        <div v-if="session.demo" class="callout info" role="note" data-test="login-demo-banner"><span>{{ s.app.demoBanner }}</span></div>
        <p class="muted">{{ s.login.lead }}</p>
        <div class="tabs" role="tablist">
          <button type="button" role="tab" :aria-selected="mode === 'token'" @click="mode = 'token'">{{ s.login.tabToken }}</button>
          <button type="button" role="tab" :aria-selected="mode === 'user'" @click="mode = 'user'">{{ s.login.tabUser }}</button>
        </div>
        <template v-if="mode === 'token'">
          <div class="field">
            <label for="tok">{{ s.login.token }}</label>
            <input id="tok" v-model="token" class="mono" type="password" autocomplete="off" spellcheck="false" required />
            <span class="hint">{{ s.login.tokenHint }}</span>
          </div>
        </template>
        <template v-else>
          <div class="field"><label for="usr">{{ s.login.username }}</label><input id="usr" v-model="username" type="text" autocomplete="username" required /></div>
          <div class="field"><label for="pw">{{ s.login.password }}</label><input id="pw" v-model="password" type="password" autocomplete="current-password" required /></div>
          <div v-if="totp" class="field">
            <label for="otp">{{ s.login.totp }}</label>
            <input id="otp" v-model="totp" class="mono" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="8" :required="session.needTotp" />
            <span class="hint">{{ s.login.totpHint }}</span>
          </div>
        </template>
        <ErrorPanel v-if="error" :error="error" />
        <div class="row" style="margin-top: 12px">
          <button class="btn btn-primary" type="submit" :disabled="busy">{{ busy ? s.login.working : s.login.submit }}</button>
          <a v-if="session.demoAvailable && !session.demo" class="btn btn-ghost" href="/?demo">{{ s.login.demo }}</a>
        </div>
      </div>
    </form>
  </main>
</template>

<style>
.login { min-height: 100vh; display: grid; place-items: center; padding: var(--gutter); }
.login-card { width: min(420px, 100%); }
.login-card > header { justify-content: space-between; }
.login-card .tabs { margin-top: 8px; }
</style>
