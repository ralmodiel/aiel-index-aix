<template>
  <div title="Hello title">
    <h1>Welcome back</h1>
    <button placeholder="Search here" @click="go">Save changes</button>
    <p>{{ message }}</p>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
const message = ref('hi')
function go() { helper() }
function helper() { return 1 }
</script>
