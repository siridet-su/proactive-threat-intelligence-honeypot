# Developer access to project MongoDB

Status: operating guidance for a future handoff; no new account or network
access is created by this repository change.

The project stores canonical events and operations data in MongoDB Atlas.
The Dashboard's `honeypot_db.users` collection contains operator identities
and password hashes; `honeypot_db.auth_sessions` contains active-session
metadata. Other collections can include attacker-submitted fields or sensitive
backup metadata. Read-only access prevents modification; it does not hide
those fields or prevent a reader from copying visible data.

## When a developer needs live data

1. In Atlas, create a **separate database user for that developer**. Use
   **Specific Privileges** with `read` on each approved database and
   collection. Fill the collection name; leaving it blank grants the whole
   database, including `users` and `auth_sessions` in `honeypot_db`. Do not
   grant `readAnyDatabase` or database-wide `read` for a general telemetry
   handoff. Do not reuse the Pi worker, Dashboard, administrator, or personal
   Atlas credential. Set an expiry for temporary access where supported.
2. Limit Atlas network access to that developer's current IP or an approved
   private route. Do not open a broad internet range for convenience.
3. Give the new user's connection details through a private password manager
   or another approved secret channel. Place them only in the developer's
   ignored local `.env` file. Never commit the URI or paste it into a ticket.
4. Validate with the developer that a read query works and an insert/update is
   denied. Remove the database user and network allowance at handoff end.

Dashboard pages that query only the approved collections can use this account
for inspection. A complete Dashboard login cannot run against this read-only
account: login/session code reads `users` and writes `auth_sessions`. Admin
actions that persist schedule, backup, user, or other state also fail. Use a
separate test database with synthetic operator accounts for interactive UI
development. If the developer needs to inspect the User Management display,
provide a sanitized export containing only its display fields; do not include
password hashes, session records, reset data, or real operator contact details
unless explicitly needed and approved.

If the developer must **receive no database credential at all**, give them a
sanitized, time-bounded export or a read-only API/projection instead of direct
Atlas access. A distinct read-only database user protects the owner's existing
credential but is still a credential and still exposes every field the role
can read. Review the export or projection for attacker-submitted values and
backup control fields before release.

Reference: [Atlas database users](https://www.mongodb.com/docs/atlas/security-add-mongodb-users/),
[Atlas IP access lists](https://www.mongodb.com/docs/atlas/security/add-ip-address-to-list/),
and [MongoDB read roles](https://www.mongodb.com/docs/manual/reference/built-in-roles/).
