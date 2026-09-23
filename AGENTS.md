# Repository implementation workflow

For implementation or deployment work in this repository:

- Read [the documentation index](docs/README.md) and
  [the implementation log](docs/IMPLEMENTATION-LOG.md) before making changes.
- Add a dated entry to `docs/IMPLEMENTATION-LOG.md` in the same change. Use its
  template and state separately what changed in the repository, what was
  actually applied to a host, what is currently active, and what was not tested
  or was deferred.
- Update current-state docs, service runbooks, and ADRs when the implementation
  changes deployed behavior, operating steps, or an accepted architectural
  decision. The implementation log is history, not the current-state source of
  truth.
- Keep audit records factual and append-only. Correct past records with a dated
  addendum rather than silently rewriting them.
- Never put secrets, real attacker credentials, raw attacker payloads, access
  tokens, private keys, or sensitive config contents in repository docs or
  fixtures. Describe protected backup locations without copying their contents.
