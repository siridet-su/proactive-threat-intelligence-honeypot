# Documentation Index

## Cowrie hardware fusion documents

1. [Experiment contract v1](experiment_contract.v1.md)
2. [XGBoost, TCN and Fusion architecture](model_architecture_xgboost_tcn_fusion.v1.md)
3. [Pi two-TTP PoC result — 2026-09-02](pi_poc_results_2026-09-02.md)
4. [Hardware-impact experiment protocol v2](hardware_impact_experiment_protocol.v2.md)
5. [Hardware Go Agent feature-parity audit — 2026-09-02](hardware_agent_feature_parity_2026-09-02.md)
6. [Dataset builder v1](dataset_builder.v1.md)
7. [Experimental 1 Hz collector v1](experimental_collector.v1.md)
8. [Dataset split policy v1](dataset_split_policy.v1.md)
9. [Dataset storage plan v1](dataset_storage_plan.v1.md)
10. [Pi environment audit — 2026-09-01](pi_environment_audit_2026-09-01.md)
11. [Stage A idle pilot report — 2026-09-01](pilot_idle_collection_2026-09-01.md)
12. [Bounded workload contract v1](bounded_workload_contract.v1.md)
13. [Raspberry Pi safe-container hardware PoC v1](pi_poc_runbook.v1.md)

## Imported SecureBERT review

เอกสารใน `securebert_deep_review/` ถูกคัดลอกมาจาก
`/home/siridet/Downloads/securebert_deep_review` เมื่อ 2026-09-01 โดยรักษาชื่อไฟล์และ
โครง relative links เดิมไว้ ต้นฉบับใน Downloads ไม่ได้ถูกลบหรือย้าย

เอกสาร SecureBERT หลักที่ต้องอ่านก่อนพัฒนา:

1. [ModernBERT live state](securebert_deep_review/securebert_modernbert_live_state.md)
2. [Cowrie command + hardware model plan](securebert_deep_review/cowrie_hardware_multimodal_model_plan_live_state.md)
3. [SecureBERT final review](securebert_deep_review/securebert_review_final_report.v1.md)
4. [Production integration review](securebert_deep_review/securebert_production_integration.v1.md)
5. [Rule/model authority matrix](securebert_deep_review/securebert_rule_model_authority_matrix.v1.json)

ไฟล์ Markdown และ JSON อื่นในโฟลเดอร์เดียวกันเป็น review evidence สำหรับ architecture,
checkpoint identity, preprocessing, label space, calibration, determinism, performance,
fail-closed behavior และ thesis claim boundaries
