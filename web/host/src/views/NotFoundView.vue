<script setup lang="ts">
import { s } from '@/i18n'
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.app.notFoundTitle }}</h1></div>
    <div class="empty panel"><p>{{ s.app.notFound }}</p><router-link to="/">{{ s.nav.overview }}</router-link></div>
  </div>
</template>
