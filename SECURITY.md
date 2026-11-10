# Security policy

## Reporting a problem in Seaworthy itself

Email **support@dynamomaritime.com** with "Security" in the subject. Please include the version (`npx seaworthy-cli --version`), what you found, and how to reproduce it. A small, made-up example is ideal; please don't send real secrets or code you can't share.

We'll acknowledge it within two working days and keep you updated until it's fixed. Please give us a reasonable chance to release a fix before you publish details. We're happy to credit you in the release notes.

## What counts

- Anything that makes Seaworthy upload code, send data it says it doesn't, or print a secret it should have masked.
- A repository that can make Seaworthy run a command or write outside the folder it scans (for example through git config, hooks or crafted file names).
- A way to use paid features without a valid licence.
- Anything in the MCP server, the GitHub Action or the workflows `seaworthy init` writes that lets untrusted input run as a command.

A finding Seaworthy misses, or a false alarm, is a normal bug rather than a security issue: email us or open an issue.

## Supported versions

Fixes go into the latest release. Run `npx seaworthy-cli@latest` to get it.
