// Tests must never reach a real licence server (or anything else). Any stray fetch fails loudly.
globalThis.fetch = (async (input: unknown) => {
  throw new Error(`Network call attempted in a test: ${String(input)}`);
}) as typeof fetch;
