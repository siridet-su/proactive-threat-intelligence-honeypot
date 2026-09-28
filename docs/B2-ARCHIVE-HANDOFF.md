# B2 archive ownership and developer handoff

Status: clean-host installation policy. The existing Pi's B2 runtime is a
separate deployment and is not changed by the fresh installer.

## New installs

The one-command fresh installer stages `/etc/honeypot/backup.env` as a blank,
root-owned mode-`0600` file, but leaves
`honeypot-hardware-backup-control.service` stopped and disabled. Core telemetry
can start without any B2 credential. The operator creates their **own** B2
destination bucket and a separate application key with the permissions needed
to upload to that bucket. Only the operator adds that key to the private env.
They then rerun `scripts/install_fresh_pi.py` with `--enable-backup` and verify
an actual archive upload and restore under their own account. The installer
checks file shape and key presence, not whether the key can write remotely.
The installer does not copy the existing Pi's bucket, key, or old objects.

## Access to historical objects

If the owner wants a successor developer to inspect old archives, create a
**different** B2 application key restricted to the historical bucket and, if
practical, the archive prefix. Grant read/list access only; omit `writeFiles`
and `deleteFiles`. Share it through a private secret channel, keep it out of
Git, and revoke it when the handoff ends. This key is for download or restore
inspection only. Do not put it in the Pi's `backup.env` or use it as the new
backup destination credential. Read-only access still exposes the data in
objects it can read, including sensitive telemetry; review scope before
sharing. If no key should be shared, provide a reviewed, sanitized export.

Backblaze documents the separate
[`listFiles`, `readFiles`, `writeFiles`, and `deleteFiles` capabilities](https://www.backblaze.com/docs/cloud-storage-application-key-capabilities)
and [bucket/prefix restrictions for application keys](https://www.backblaze.com/docs/cloud-storage-create-and-manage-app-keys).
