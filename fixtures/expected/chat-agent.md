# chat-agent: answer key

Next.js 14 App Router, Firebase (Firestore and Storage), OpenAI with a tool-calling agent, Cursor MCP config. Paths are relative to `fixtures/apps/chat-agent/`.

## Planted flaws

| Rule | File | Line | What is wrong |
| --- | --- | --- | --- |
| SW-S04 | `lib/openai-browser.ts` | 4, 5 | OpenAI key from a `NEXT_PUBLIC_` variable with `dangerouslyAllowBrowser`; used by the client page `app/chat/page.tsx` line 4 |
| SW-D03 | `firestore.rules` | 5 | `allow read, write: if true` on every document |
| SW-D04 | `storage.rules` | 5 | `allow read, write;` with no condition on every file |
| SW-A01 | `app/api/assistant/route.ts` | 34 | `POST` has no auth check, and it drives a shell tool |
| SW-A03 | `app/api/assistant/route.ts` | 34 | Costly LLM endpoint with no rate limit |
| SW-A04 | `app/api/assistant/route.ts` | 10 | `Access-Control-Allow-Origin: *` with `Allow-Credentials: true` |
| SW-L01 | `app/api/assistant/route.ts` | 40 | Client-supplied `persona` concatenated into the system prompt |
| SW-L02 | `app/chat/page.tsx` | 25 | Model output rendered with `dangerouslySetInnerHTML` (the prompt even asks for HTML) |
| SW-L03 | `app/api/assistant/route.ts` | 19, 50 | `run_shell` tool executes model-chosen commands with no allow-list, auth or confirmation |
| SW-L04 | `.cursor/mcp.json` | 5 | Database password in plain text in server args |
| SW-L04 | `.cursor/mcp.json` | 11 | GitHub token in plain text (also SW-S01) |
| SW-L04 | `.cursor/mcp.json` | 15 | Remote MCP server over plain HTTP on `0.0.0.0`, no auth configured |
| SW-X01 | `package.json` | 12 | `next` 14.2.3 is old; expected to have known advisories. **Confirm against OSV during the teardown.** |
| SW-X02 | `package.json` | 14, 17 | `openai-stream-guard-utils` and `react-markdown-safe-html` do not exist on npm (checked 9 Nov 2026). Re-check before each teardown run: someone could register them |
| SW-B01 | (project) | n/a | No `next.config.js` at all, so no security headers |

## Decoys (should NOT be flagged)

| Where | Why it is fine |
| --- | --- |
| `app/chat/page.tsx` line 16, the system prompt | Fixed string; user input goes in its own `user` message |
| `app/api/assistant/route.ts` line 7 | Server-side OpenAI key from a non-public variable |
| `lib/firebase.ts` line 5 | Firebase web API keys are meant to be public; the real problem is the rules |
| `.gitignore` | Lists `.env`, and no `.env` is committed |
