# Fixtures

**Every app under `apps/` is deliberately insecure. Never deploy it, never run `npm install` in it, and never copy code from it.**

- All keys and tokens are fake. They are shaped like real ones so scanners will flag them. They grant access to nothing.
- Some `package.json` files name packages that do not exist on npm (rule SW-X02). Installing would fetch whatever someone later publishes under that name.
- The planted flaws for each app are listed in `expected/<app>.md`, **outside** the app folder. When uploading an app to a competitor scanner, upload only the app folder, so the answer key does not go with it.

These apps serve two jobs: the corpus for the competitor teardown, then the vulnerable half of each rule's test pair. The fixed half gets written alongside each rule during the build.
