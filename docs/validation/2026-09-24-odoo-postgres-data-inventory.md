---
title: Odoo and PostgreSQL data inventory
date: 2026-09-24
environment: staging
commit: uncommitted-worktree
status: partial
---

# Odoo and PostgreSQL data inventory

## Objective

Record what the running Odoo/PostgreSQL stack contains without dumping business
records, credentials, message bodies, attachment contents, or configuration
secret values. This is a read-only inventory snapshot, not a backup or a
certification that all records are synthetic.

## Procedure

- Confirmed the running Compose services and loopback port bindings.
- Queried PostgreSQL database names/sizes, public table names, module states,
  and aggregate row counts inside `BEGIN READ ONLY` transactions as the
  database role `odoo`.
- Queried only aggregate attachment metadata (`store_fname`, `db_datas`, and
  `file_size` counts/sums); no attachment row values were printed.
- Compared distinct attachment paths against the Odoo runtime `data_dir` using
  a read-only check that emitted counts and byte totals only.
- Did not execute any `INSERT`, `UPDATE`, `DELETE`, or DDL; no Odoo HTTP/app
  login or ERP workflow was attempted.

## Observed runtime and databases

- Compose reports Odoo 17 and PostgreSQL 16 as running. Odoo is published on
  `127.0.0.1:8069`; PostgreSQL is published on `127.0.0.1:5432`.
- Non-template databases: `odoo_production` (49 MB) and `postgres` (7,519 kB).
- `odoo_production` contains 455 public base tables.
- The Odoo data volume is mounted at `/var/lib/odoo`; runtime `data_dir` is
  `/var/lib/odoo/.local/share/Odoo`.
- At inventory time, web-corp was a separate service and had no Odoo URL in its
  Compose environment. The old Odoo middleware service was absent. Therefore
  these database records were not being served through web-corp at this time.

## Installed modules

`ir_module_module` contains 664 module records: 62 installed, 26 marked
uninstallable, and 576 uninstalled. Key installed modules observed were
`base`, `web`, `mail`, `sale`, `account`, `hr`, and `stock`. `contacts`, `crm`,
`sale_management`, `purchase`, and `website` were uninstalled. This describes
the installed-module state, not the completeness of every workflow.

## Business and application data

| Table/model area | Rows | Notes from aggregate-only inspection |
| --- | ---: | --- |
| `res_company` | 1 | Company record; value not read. |
| `res_users` | 5 | User/account records; credentials and profile fields not read. |
| `res_partner` | 15 | Partner/contact records; `customer_rank` and `supplier_rank` were zero for all rows. |
| `product_template` / `product_product` | 7 / 7 | Product templates and variants. |
| `sale_order` / `sale_order_line` | 5 / 5 | All five orders were in `draft` state. |
| `account_move` / `account_move_line` | 5 / 10 | All five moves were `out_invoice` and `draft`. |
| `hr_employee` | 5 | Employee records; names and fields not read. |
| `stock_quant` | 4 | Inventory-quantity records. |
| `mail_message` / `mail_followers` | 66 / 36 | Chatter/message and follower metadata; message bodies not read. |
| `res_users_log` | 1 | User-log row; contents not read. |
| `ir_logging` | 0 | No rows in Odoo's `ir_logging` table at query time. |
| `ir_config_parameter` | 20 | Configuration rows; values intentionally not read because they may contain secrets. |
| `ir_model_data` | 16,761 | Odoo module/external-ID metadata. |

The sibling deployment tree has a seed script for partners, products, sales
orders, and invoices. This inventory did not inspect record values, so it does
not prove that every live record is synthetic or that no sensitive value is
present.

## Attachment/filestore consistency finding

- `ir_attachment` has 518 rows. Of these, 517 have a `store_fname` and none
  have a database blob in `db_datas`.
- The non-deduplicated sum of `ir_attachment.file_size` for those rows is
  11,910,663 bytes.
- The runtime filestore contains 404 distinct paths referenced by the DB;
  only 8 of those paths existed at check time and 396 did not. The 8 present
  files total 38,965 bytes. Multiple attachment rows can reference the same
  path, which is why 517 rows correspond to 404 distinct paths.
- Treat these 396 references as an attachment availability/integrity issue
  until explained. Any missing attachment may fail to open in Odoo. No files
  were created, restored, deleted, or otherwise changed during this check.

## Limitations and data handling

- No names, emails, login/password values or hashes, parameter values, message
  bodies, attachment names, or attachment contents were read into this report.
- The `res_users_log` count and zero `ir_logging` count do not establish that
  all HTTP/authentication events are captured. Odoo container logs and Core
  event delivery were not inspected or tested here.
- Database and filestore snapshots may change after this point. The report is
  not a live monitor.
- Treat the Odoo/PostgreSQL volumes as sensitive: they include user/contact,
  ERP, configuration, chatter, and attachment metadata. Do not expose port
  8069 or PostgreSQL beyond loopback without a separately reviewed design.

## Follow-up

- Before any repair or cleanup, take and verify a coordinated backup of both
  the PostgreSQL data and the Odoo data/filestore volume; do not use
  `docker compose down -v`.
- Investigate the 396 missing filestore paths and decide whether to restore
  files from a known backup or remove only verified stale references. Neither
  action was authorized or performed in this inventory.
- Confirm the live records are synthetic and decide which Odoo audit events
  must be bridged into Deception Core before connecting web-corp to Odoo.
