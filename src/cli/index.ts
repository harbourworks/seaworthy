import pc from "picocolors";
import { run } from "./main.js";

run(process.argv.slice(2), {
  out: (s) => console.log(s),
  err: (s) => console.error(s),
  env: process.env,
  cwd: process.cwd(),
  now: () => new Date(),
})
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    console.error(pc.red(`  Seaworthy hit an internal error: ${(err as Error)?.stack ?? String(err)}`));
    process.exitCode = 2;
  });
