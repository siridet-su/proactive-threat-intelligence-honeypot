# CyberLab multi-member safe receipt v1

`production.reproduction.cyberlab_multimember` is the successor boundary for a
single logical session whose normalized private events occur in more than one
daily CyberLab member. It is deliberately separate from the frozen
`cyberlab_cowrie_adapter.v1` receipt and does not alter parser, ATT&CK, trust,
or prediction semantics.

The builder accepts only normalized private sessions and independently verified
member receipts. Receipts are sorted by frozen chronological order, and the
ordered member list is content-addressed. Exact duplicate event keys with the
same semantic payload are retained once; a duplicate key with conflicting
payload fails closed. The merged events are deterministically ordered and
reindexed. `cowrie.session.closed` is the only terminal authority: a merged
session without that event remains `active/unresolved`.

The safe v2 session contains HMAC-derived session, member, and event IDs plus
bounded command evidence references and lengths. It does not contain raw
session IDs, command text, source addresses, or private messages. Provenance
binds the adapter receipt, source-member hashes and official checksums,
pseudonymization key ID, member-receipt hash, session hash, replay identity,
and both contract versions.

Publication is interruption-safe and no-overwrite. Re-publishing identical
content is idempotent; a different existing receipt or a publication race is a
closed failure. Tests use synthetic gzip members only.
