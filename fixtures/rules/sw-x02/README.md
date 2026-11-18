# SW-X02 fixtures

SW-X02 needs answers from the npm registry, so the tests run these folders against a fake registry
in which `react-markdown-safe-html` and every name in the decoy are missing. Nothing here is meant to be installed.

- `vulnerable`: depends on `react-markdown-safe-html`, a made-up name.
- `fixed`: depends on the real `react-markdown` instead.
- `decoy`: every dependency comes from somewhere other than the npm registry (a local folder, a git
  host or a URL), so none of them is looked up or flagged, even though the fake registry doesn't have them.
