# SW-S04 fixtures

Each `lib/chat-store.ts` has a class with `accessor` fields, so these also check that the parser
handles them. If it didn't, SW-S04 would fall back to text matching and flag the type members in
the decoy. No fixture contains a key.

`decoy-vue/src/Chat.vue` sets `dangerouslyAllowBrowser: false` in a Vue `<script setup>` block.
Vue and Svelte files are read by text matching rather than parsed, so this checks that the text
fallback never flags an explicit `false`.
