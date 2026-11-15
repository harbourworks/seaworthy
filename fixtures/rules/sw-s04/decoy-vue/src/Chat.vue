<script setup lang="ts">
import OpenAI from "openai";

// Vue files are read by text matching, so this checks that an explicit false is not flagged there.
const client = new OpenAI({ apiKey: "x", dangerouslyAllowBrowser: false });
</script>

<template>
  <p>{{ client ? "ready" : "loading" }}</p>
</template>
