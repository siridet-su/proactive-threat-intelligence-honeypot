# CyberLab external adapter v3

The v2 adapter correctly applies the label-blind sensor boundary before
semantic parsing.  v3 adds one narrowly scoped missing-evidence rule for an
eligible `cowrie.command.input` event whose exact command text is absent.

The event is preserved as a private quarantine record with reason
`missing_command_text`.  It produces no command, trusted label, ATT&CK
candidate, or classifier event.  The event is a causal barrier: trusted
observations before and after it are constructed as separate deterministic
segments.  A segment before a barrier is `active/unresolved`, regardless of a
later close; only the final segment may inherit an explicit
`cowrie.session.closed` terminal state.  Thus no next-behavior target can cross
unknown evidence, while valid evidence on either side remains usable.

All other v2/v1 rules remain strict.  Wrong, mixed, or missing sensors are
excluded before event validation; malformed non-command fields and malformed
eligible command events other than this exact missing-text case fail closed.
The v1 and v2 adapters, receipts, and failure evidence remain immutable.
