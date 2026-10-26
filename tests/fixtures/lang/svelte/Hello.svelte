<script lang="ts">
  export let name: string = 'x';
  function bump() { helper(); }
  function helper() { return 1; }
</script>

<h1>Hello there</h1>
<button on:click={bump}>Click me</button>
