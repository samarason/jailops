<script setup lang="ts">
import { confirmState, closeConfirm } from '../composables/confirm'
import ConfirmDialog from './ConfirmDialog.vue'

// The dialog behind confirmAction(): one instance in the shell.
const noop = () => Promise.resolve()
</script>

<template>
  <ConfirmDialog
    :open="!!confirmState.req"
    :title="confirmState.req?.title ?? ''"
    :confirm-label="confirmState.req?.confirmLabel ?? ''"
    :danger="confirmState.req?.danger ?? !!confirmState.req?.typeName"
    :run="confirmState.req?.run ?? noop"
    :text="confirmState.req?.text"
    :items="confirmState.req?.items"
    :items-label="confirmState.req?.itemsLabel"
    :type-name="confirmState.req?.typeName"
    :type-label="confirmState.req?.typeLabel"
    @done="confirmState.req?.done?.()"
    @close="closeConfirm"
  />
</template>
