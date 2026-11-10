# Seaworthy

A local pre-launch security check for AI-built apps. Free to use, and the source is public.

**Status: early build.** Private. Two rules work end to end (SW-S01, SW-D01), plus the Pro and Agency features and licensing ([docs/pro-tiers.md](docs/pro-tiers.md)). `npm run build && node dist/cli.js <path>`.

- Spec: kept in the private planning repo (`harbourworks/dynamo-planning`), section 7.
- Progress: [BUILD-LOG.md](BUILD-LOG.md).
- Test apps: [fixtures/](fixtures/README.md). They are deliberately vulnerable.

**Licence:** source-available, not open source. The scanner is under the [Functional Source License](LICENSE) (FSL-1.1-ALv2): free for any use except a competing product, and each release becomes Apache 2.0 two years after it is published. The paid features in `src/pro/` are under the [Seaworthy Commercial Licence](LICENSE-COMMERCIAL.md).

Seaworthy is a trading name of Dynamo Maritime Ltd, registered in England and Wales, company number 17152743.
