# SW-S01 fixtures

Database connection strings (issue #31).

- `vulnerable/scripts/deploy.ts` has a high-entropy password for a host that isn't reserved. It
  must be reported. The password is made up and the host doesn't exist.
- `fixed/scripts/deploy.ts` reads the connection string from `process.env`.
- `decoy/scripts/deploy.test.ts` is the issue's reproduction: one URL with the password
  `password` and one at a reserved example domain (`example.org`, RFC 2606). Neither
  database exists, so neither may be reported.
