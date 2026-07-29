# Typed scheduled-task family decision

Decision date: 2026-07-30

Baseline: `8db3744`

Disposition: **retain as shadow-only**

## Frozen contract

Within the documented shell subset, `crontab -l` is a schedule inspection,
`crontab -e` is an interactive modification attempt, `crontab -r` is a
deletion attempt, and `crontab FILE` is a schedule replacement/modification
attempt. These are literal Cowrie command observations only. They do not prove
the prior schedule state, job installation, execution, continued access,
persistence intent, or real-host effect.

Failed, unknown, malformed, unsupported-option, incomplete, expansion-
dependent, and compound outcomes are ineligible. Reading a crontab-formatted
file is a file read, not a scheduled-task operation. ATT&CK context cannot
create a literal scheduled-task fact.

## Evidence and decision

The sole retained demonstration example is a compound shell sequence. Cowrie's
event outcome applies to the compound event and cannot prove any individual
fragment. The current typed representation also cannot distinguish creation
of a previously absent schedule from replacement of an existing one, because
that state is not observed.

Consequently, activation would add persistence-flavored output without a
qualifying retained example. The independent evaluation and holdout verify the
lossless shadow distinction among inspect, modify, and delete and confirm that
no v4 finding, hypothesis, v3 finding, or guidance is authorized.

Activation remains blocked until direct single-fragment evidence is retained
and any output is explicitly worded as an attempt without creation,
installation, execution, intent, or persistence claims.

