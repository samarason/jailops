<script setup lang="ts">
import { computed, ref } from 'vue'
import { s } from '@/i18n'
import Callout from '@jailops/shared/components/Callout.vue'

// The scope of an identity: some projects, or Global. "Choose at least one" shows once the user changed the scope
// or tried to submit (showError), never on a form nobody touched yet.
const props = defineProps<{ names: string[]; projects: string[]; global: boolean; showError?: boolean; firstId?: string }>()
const emit = defineEmits<{ 'update:projects': [string[]]; 'update:global': [boolean] }>()
const ok = computed(() => props.global || props.projects.length > 0)
const touched = ref(false)
function toggle(n: string, on: boolean): void {
  touched.value = true
  emit('update:projects', on ? [...props.projects, n] : props.projects.filter((x) => x !== n))
}
function setGlobal(on: boolean): void {
  touched.value = true
  emit('update:global', on)
}
defineExpose({ ok })
</script>

<template>
  <fieldset class="field scope-box" data-test="scope">
    <legend class="label">{{ s.trust.projects }} <span class="req" aria-hidden="true">*</span></legend>
    <label v-for="(p, i) in names" :key="p" class="check"><input :id="i === 0 ? firstId : undefined" type="checkbox" :checked="projects.includes(p)" :disabled="global" @change="toggle(p, ($event.target as HTMLInputElement).checked)" /><span class="mono">{{ p }}</span></label>
    <label class="check"><input :id="names.length ? undefined : firstId" type="checkbox" :checked="global" data-test="global-toggle" @change="setGlobal(($event.target as HTMLInputElement).checked)" />{{ s.trust.global }}</label>
    <Callout v-if="global" tone="warn" data-test="global-warning">{{ s.trust.globalWarning }}</Callout>
    <span v-if="!ok && (showError || touched)" class="err" role="alert" data-test="scope-required">{{ s.trust.scopeRequired }}</span>
  </fieldset>
</template>
