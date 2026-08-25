# GCP Gate-B ownership / shared-project resolution study

Date: 2026-08-23  
Status: **COMPLETE_VALID / READ-ONLY / ZERO-DELETION**  
Target: `project-dff4b23a-3010-4936-a02` / `capstone` / `asia-southeast1-b`

This study resolves ownership evidence for Gate B without deleting, creating,
or modifying any GCP resource. It does not alter IAM, disks, networking,
production, model artifacts, or D–J state.

## Decision

- **Project scope:** `SHARED_OR_UNPROVEN`; dedicated honeypot exclusivity is not proven.
- **Prior ambiguous scopes:** 94.
- **Resolved:** 90 default-network scopes classified `GCP_PLATFORM_DEFAULT`.
- **Remaining:** 4 `AMBIGUOUS_PRESERVE` supplemental scopes.
- **B1 destructive cleanup:** `PASS_EMPTY_ALLOWLIST_NO_CLEANUP_NEEDED`.
- **B2 non-destructive shadow deployment:** `PASS_NON_DESTRUCTIVE_SHADOW_DEPLOYMENT`.
- **Cleanup required:** `FALSE`.
- **Deployment mode:** additive, localhost-only, shadow-only, zero deletions.

## Project scope evidence

The project display name is the generic `My First Project`, it is under an
organization parent, and no dedicated-project label or readable project IAM
policy was found. The presence of one `capstone` VM is not evidence of project
exclusivity. The default network and standard default rules are project-wide
infrastructure. Therefore the study records `SHARED_OR_UNPROVEN` and does not
infer ownership or deletion rights from names.

## Resource resolution

The 90 Compute/network scopes consisting of one `default` network, 42
auto-created `default` subnetworks, 43 `default-route-*` routes, and four
`default-allow-*` firewall rules were classified `GCP_PLATFORM_DEFAULT`.
Evidence includes their standard names/descriptions, default-network
references, common 2026-08-07 creation cohort, and auto-created subnet CIDRs.
They are preserved and are never deletion candidates.

The four supplemental scopes remain `AMBIGUOUS_PRESERVE` because the active
principal cannot enumerate them:

- service accounts (`iam.serviceAccounts.list` denied);
- GCS buckets (`storage.buckets.list` denied);
- Artifact Registry repositories (`artifactregistry.locations.list` denied);
- Cloud Scheduler jobs (API disabled / location required).

No service-account keys, tokens, bucket objects, or secret values were read.

## Runtime and repository correlation

The VM is `capstone`, uses the default network and the `capstone` boot and
backup disks, and runs the existing production services from
`/opt/honeypot` with canonical state under `/var/lib/honeypot`. Repository
references in `docs/CURRENT_PRODUCTION_STATE.md`,
`docs/GCP_VM_CURRENT_ARCHITECTURE.md`, `docs/DEPLOYMENT_AND_RECOVERY.md`,
`docs/SYSTEM_ARCHITECTURE.md`, and the AI advisory environment example support
the production correlation; they are not used alone as deletion authority.

## Non-destructive deployment conflict check

Read-only VM checks found no listener on `127.0.0.1:18082`, no Track-B or
Final-POC systemd unit, no uploaded prediction-only bundle, and about 100.428
GiB free. Existing production listeners remain `100.85.50.74:8080`,
`127.0.0.1:8081`, and `127.0.0.1:8090`. A new versioned localhost-only sidecar
can therefore be additive and does not require touching ambiguous/default
resources. This does not itself perform or authorize deployment.

## Permission gaps

See `gcp_gate_b_read_permission_gaps.json`. The minimum missing read access is
recorded per API; no IAM expansion was requested or performed. Cloud Run,
Cloud Functions, Pub/Sub, Secret Manager, and Scheduler APIs were disabled or
unavailable, so their inventories remain outside the ownership proof. They are
not required for B2 because the proposed sidecar uses none of them.

## Required answers

1. Project proven dedicated? **No.**
2. Scope? **SHARED_OR_UNPROVEN.**
3. Prior ambiguous resolved? **90.**
4. Remaining ambiguous preserve? **4.**
5. Platform defaults? **1 network, 42 subnetworks, 43 routes, 4 firewall rules.**
6. Verified runtime? **capstone instance and capstone-public-ip (2).**
7. Source of record? **capstone boot disk (1).**
8. Backups? **capstone-backup disk and 14 READY snapshots (15).**
9. Service accounts? **capstone's attached runtime identity is visible; project enumeration denied.**
10. Account used by capstone? **97738468999-compute@developer.gserviceaccount.com.**
11. Buckets? **Enumeration denied; none can be asserted.**
12. Source-of-record buckets? **Unverified; preserve-only gap.**
13. Artifact Registry? **Enumeration denied; none can be asserted.**
14. Scheduler jobs? **API unavailable/disabled; none can be asserted.**
15. Cloud Run/Functions/Pub/Sub relevant? **No evidence of use; APIs unavailable/disabled.**
16. Permission-blocked inventories? **IAM, buckets, Artifact Registry, Scheduler, and disabled supplemental APIs.**
17. Minimum missing permissions? **Recorded exactly in the permission-gap artifact.**
18. Existing Track-B/Final-POC runtime? **No.**
19. Port 127.0.0.1:18082 free? **Yes, no listener observed.**
20. Destructive cleanup required? **No.**
21. Deletion allowlist empty? **Yes.**
22. Is empty acceptable? **Yes; additive deployment needs zero deletion.**
23. Shadow deployment with zero deletions? **Yes, B2 PASS.**
24. Would ambiguous resources be modified? **No.**
25. B1? **PASS_EMPTY_ALLOWLIST_NO_CLEANUP_NEEDED.**
26. B2? **PASS_NON_DESTRUCTIVE_SHADOW_DEPLOYMENT.**
27. A/C/D–J? **All PASS from current evidence and frozen runtime receipt.**
28. Additive shadow requirements? **Satisfied for zero-deletion localhost-only mode; deployment remains separately authorized.**
29. Remaining blocker? **No B2 blocker; supplemental ownership visibility remains incomplete for destructive cleanup.**
30. Delete anything now? **NO.**

## Hashes

- `gcp_gate_b_ownership_resolution.json`: `086417b51602ca124621372f6a08b3344424b6e8df2a7f186e8c80f4a8be01eb`
- `gcp_gate_b_resource_classification.json`: `66c486a8e5a6b3136d9b748917d939efd4106c397829cd20c20048a7c5fcbfb4`
- `gcp_gate_b_read_permission_gaps.json`: `0db8b2c2371300399cff99e0fe35fb835229e2c77e31c5f6ea7eb501ae883820`
- `gcp_project_scope_assessment.json`: `aed6a34eb87c196d1fe940057d70c160a562c5cc36499b288b3450833589fcc8`
- `gcp_non_destructive_deployment_conflict_check.json`: `49bf93d7f20d03bb809f85f21cf75967361f68058328c2f2f36ee487c169b31f`
- `gcp_verified_deletion_allowlist_v2.json`: `7c76bca946a45977554a2d0cbbd4d1422727232d195e334d4bd8eeab463dec78`

## Preservation

```text
GCP RESOURCES DELETED = NONE
GCP RESOURCES CREATED = NONE
GCP RESOURCES MODIFIED = NONE
IAM MODIFIED = FALSE
DISK MODIFIED = FALSE
PRODUCTION MODIFIED = FALSE
MODEL RETRAINED = FALSE
TEMPERATURE REFIT = FALSE
SEALED DATA ACCESSED = FALSE
```

GATE B RESOLVED FOR DEPLOYMENT BUT NOT DESTRUCTIVE CLEANUP — READY FOR ZERO-DELETION FINAL SHADOW DEPLOYMENT
