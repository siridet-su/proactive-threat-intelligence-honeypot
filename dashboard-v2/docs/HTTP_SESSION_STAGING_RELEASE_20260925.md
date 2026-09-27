# HTTP session staging release check

The Threat Intel HTTP detail release is `efad9f7500139f193375ff7b6132afbe75853133`.
Its first staging deployment attempt passed CI build/package but the deploy
wrapper rejected the pre-existing `current` symlink because it used an
absolute target. On 2026-09-25 the staging-only pointer was normalized to
`releases/2e41df41eb1caa71333d6565b123fbe117c53383-2c84d5e64537`;
it resolves to the exact same release directory. The staging service stayed
active and `GET /api/auth/login` still returned 405 afterward.

This file triggers a new staging CI run so deployment uses the reviewed
wrapper and its health check/rollback contract. It does not change
production or the HTTP evidence boundary.
