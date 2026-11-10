import pc from "picocolors";
import { createInterface } from "node:readline/promises";
import { run } from "./main.js";

async function ask(question: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return /^y(es)?$/i.test((await rl.question(question)).trim());
  } finally {
    rl.close();
  }
}

run(process.argv.slice(2), {
  out: (s) => console.log(s),
  err: (s) => console.error(s),
  env: process.env,
  cwd: process.cwd(),
  now: () => new Date(),
  interactive: Boolean(process.stdout.isTTY) && !process.env.CI,
  ask: process.stdin.isTTY && process.stdout.isTTY && !process.env.CI ? ask : undefined,
})
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    console.error(pc.red(`  Seaworthy hit an internal error: ${(err as Error)?.stack ?? String(err)}`));
    process.exitCode = 2;
  });
