# Teardown plan (build days 1 to 2)

**Question:** do at least 5 of the 22 v1 checks find real problems that the existing tools miss? If yes, build Seaworthy. If no, build the UK/EU boilerplate first.

## Tools to compare

| Tool | Type | How we run it | Account needed |
| --- | --- | --- | --- |
| AtRisk | Paid, hosted | GitHub connection or upload | Yes (Sammy, Dynamo email) |
| Epherem | Free, hosted | ZIP upload or GitHub connection | Yes (Sammy, Dynamo email) |
| SecureScope | Hosted | To check | Yes (Sammy, Dynamo email) |
| Gitleaks | Free, local | CLI | No |
| Semgrep (community rules) | Free, local | CLI | No |
| OSV-Scanner | Free, local | CLI | No |

Names and features of the hosted tools come from a single web search and are unconfirmed. Recording what each one actually is comes first.

## Corpus

1. Our own vulnerable apps in `fixtures/apps/` (answer keys in `fixtures/expected/`).
2. Two or three real AI-built repos with the owner's written permission, to keep the comparison honest. We planted the flaws in our own apps, so on those alone the result is biased in our favour.

For hosted tools that connect to GitHub, each fixture app gets pushed to its own throwaway private repo. Delete it afterwards.

## Results

One file per tool: `results/<tool>.md`, one row per rule ID: caught / missed / partial / false positive, with notes. The go/no-go sum goes at the bottom of this file.
