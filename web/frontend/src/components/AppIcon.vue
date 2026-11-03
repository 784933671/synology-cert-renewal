<script setup lang="ts">
defineProps<{ name: string }>()
const paths: Record<string, string> = {
  shield: 'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z M8 12l3 3 5-6',
  overview: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  certificate: 'M5 3h14v18H5z M9 7h6 M9 11h6 M9 15h3',
  renewal: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 7v5l3 2',
  notifications: 'M3 5h18v14H3z M3 6l9 7 9-7',
  failures: 'M12 3 2 21h20z M12 9v5 M12 17h.01',
  audit: 'M5 3h14v18H5z M9 8h6 M9 12h6 M9 16h4',
  security: 'M5 10h14v11H5z M8 10V7a4 4 0 0 1 8 0v3 M12 14v3',
  account: 'M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0 M4 21v-2a8 8 0 0 1 16 0v2',
  refresh:
    'M20 7v5h-5 M4 17v-5h5 M6 7a7 7 0 0 1 12-1l2 6 M4 12l2 6a7 7 0 0 0 12-1',
  check: 'm5 12 4 4L19 6',
  menu: 'M4 6h16 M4 12h16 M4 18h16',
  close: 'm6 6 12 12 M6 18 18 6',
  logout: 'M9 3H4v18h5 M10 12h11 m-4-4 4 4-4 4',
  plus: 'M12 4v16 M4 12h16',
  server: 'M4 3h16v18H4z M4 12h16 M8 7h1 M8 16h1 M13 7h3 M13 16h3',
}
</script>
<template>
  <svg class="icon" aria-hidden="true" viewBox="0 0 24 24">
    <path :d="paths[name] || paths.shield" />
  </svg>
</template>
