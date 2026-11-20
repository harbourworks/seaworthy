# SW-P01 fixtures

The split webhook layout: a route receives the request and passes the event to a handler module in
another file.

- `vulnerable/`: the route parses the body with `req.json()` and passes it on unverified. The handler
  module is reported at medium confidence, because it doesn't read a request body itself.
- `fixed/`: the same handler, called by a route that verifies the event with `constructEvent`.
- `decoy/`: a handler in a file named like a webhook, imported by a relative `.js` path from a route that
  verifies with `constructEventAsync`. Nothing is flagged.

No real keys: every secret is read from an environment variable.
