CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    sensor_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    eventid TEXT NOT NULL,
    timestamp TIMESTAMPTZ,
    payload_json JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed, received_at);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    start_time TIMESTAMPTZ,
    ended BOOLEAN NOT NULL DEFAULT false,
    session_source TEXT NOT NULL DEFAULT 'unknown_legacy'
        CHECK (session_source IN ('production_live', 'e2e_test', 'seed_data', 'demo_fixture', 'unknown_legacy')),
    is_external_source BOOLEAN NOT NULL DEFAULT false,
    payload_json JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS session_source TEXT NOT NULL DEFAULT 'unknown_legacy';
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS is_external_source BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_sessions_source_updated
    ON sessions(session_source, updated_at);
CREATE INDEX IF NOT EXISTS idx_sessions_source_external_updated
    ON sessions(session_source, is_external_source, updated_at);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    reason TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS analysis_jobs (
    job_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    report_id TEXT,
    error TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS feed_status (
    name TEXT PRIMARY KEY,
    payload_json JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS observables (
    observable_type TEXT NOT NULL,
    observable_value TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    sighting_count INTEGER NOT NULL DEFAULT 0,
    payload_json JSONB NOT NULL,
    PRIMARY KEY (observable_type, observable_value)
);
CREATE INDEX IF NOT EXISTS idx_observables_last_seen
    ON observables(last_seen);

CREATE TABLE IF NOT EXISTS observable_sightings (
    sighting_id TEXT PRIMARY KEY,
    observable_type TEXT NOT NULL,
    observable_value TEXT NOT NULL,
    session_id TEXT NOT NULL,
    sensor_id TEXT,
    src_ip TEXT,
    event_id TEXT,
    eventid TEXT,
    role TEXT NOT NULL,
    source TEXT NOT NULL,
    timestamp TIMESTAMPTZ,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_observable_sightings_observable
    ON observable_sightings(observable_type, observable_value, created_at);
CREATE INDEX IF NOT EXISTS idx_observable_sightings_session
    ON observable_sightings(session_id, created_at);

CREATE TABLE IF NOT EXISTS threat_hunt_jobs (
    job_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    observable_type TEXT NOT NULL,
    observable_value TEXT NOT NULL,
    trigger_reason TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
    result_json JSONB,
    payload_json JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (session_id, observable_type, observable_value)
);
CREATE INDEX IF NOT EXISTS idx_threat_hunt_jobs_status
    ON threat_hunt_jobs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_threat_hunt_jobs_observable
    ON threat_hunt_jobs(observable_type, observable_value);

CREATE TABLE IF NOT EXISTS session_links (
    link_id TEXT PRIMARY KEY,
    session_id_a TEXT NOT NULL,
    session_id_b TEXT NOT NULL,
    link_type TEXT NOT NULL,
    observable_type TEXT,
    observable_value TEXT,
    confidence REAL,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_session_links_session_a
    ON session_links(session_id_a, created_at);
CREATE INDEX IF NOT EXISTS idx_session_links_session_b
    ON session_links(session_id_b, created_at);
CREATE INDEX IF NOT EXISTS idx_session_links_observable
    ON session_links(observable_type, observable_value);

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    primary_fingerprint_type TEXT,
    primary_fingerprint_value TEXT,
    hassh_fingerprint TEXT,
    ja3_fingerprint TEXT,
    tactic_sequence_hash TEXT,
    command_pattern_hash TEXT,
    source_ip TEXT,
    session_count INTEGER NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_tactics_json JSONB NOT NULL,
    max_confirmed_severity TEXT NOT NULL DEFAULT 'info',
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_campaigns_hassh
    ON campaigns(hassh_fingerprint);
CREATE INDEX IF NOT EXISTS idx_campaigns_ja3
    ON campaigns(ja3_fingerprint);
CREATE INDEX IF NOT EXISTS idx_campaigns_command_pattern
    ON campaigns(command_pattern_hash);
CREATE INDEX IF NOT EXISTS idx_campaigns_tactic_sequence
    ON campaigns(tactic_sequence_hash);
CREATE INDEX IF NOT EXISTS idx_campaigns_source_ip
    ON campaigns(source_ip);

CREATE TABLE IF NOT EXISTS campaign_sessions (
    link_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    match_reasons_json JSONB NOT NULL,
    confidence DOUBLE PRECISION,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (campaign_id, session_id)
);
CREATE INDEX IF NOT EXISTS idx_campaign_sessions_campaign
    ON campaign_sessions(campaign_id, created_at);
CREATE INDEX IF NOT EXISTS idx_campaign_sessions_session
    ON campaign_sessions(session_id, created_at);

CREATE TABLE IF NOT EXISTS enrichment_records (
    observable_type TEXT NOT NULL,
    observable_value TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    provider_status_json JSONB NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (observable_type, observable_value)
);
CREATE INDEX IF NOT EXISTS idx_enrichment_records_expires
    ON enrichment_records(expires_at);

CREATE TABLE IF NOT EXISTS enrichment_jobs (
    job_id TEXT PRIMARY KEY,
    observable_type TEXT NOT NULL,
    observable_value TEXT NOT NULL,
    session_id TEXT,
    status TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'normal',
    priority_reason TEXT,
    payload_json JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (observable_type, observable_value)
);
CREATE INDEX IF NOT EXISTS idx_enrichment_jobs_status
    ON enrichment_jobs(status, next_retry_at, created_at);
ALTER TABLE enrichment_jobs
    ADD COLUMN IF NOT EXISTS priority TEXT NOT NULL DEFAULT 'normal';
ALTER TABLE enrichment_jobs
    ADD COLUMN IF NOT EXISTS priority_reason TEXT;
CREATE INDEX IF NOT EXISTS idx_enrichment_jobs_priority
    ON enrichment_jobs(status, priority, next_retry_at, created_at);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    delivery_id TEXT PRIMARY KEY,
    alert_id TEXT,
    report_id TEXT,
    target_url_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS prediction_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    session_status TEXT NOT NULL,
    event_id TEXT,
    features_hash TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_prediction_snapshots_session
    ON prediction_snapshots(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_prediction_snapshots_created
    ON prediction_snapshots(created_at);

CREATE TABLE IF NOT EXISTS prediction_backtest_runs (
    run_id TEXT PRIMARY KEY,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_prediction_backtest_runs_created
    ON prediction_backtest_runs(created_at);

CREATE TABLE IF NOT EXISTS prediction_calibration_runs (
    run_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    applied BOOLEAN NOT NULL DEFAULT false,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_prediction_calibration_runs_created
    ON prediction_calibration_runs(created_at);

CREATE TABLE IF NOT EXISTS analyst_feedback (
    feedback_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    snapshot_id TEXT,
    label TEXT NOT NULL,
    feedback_type TEXT NOT NULL DEFAULT 'operator_usefulness',
    operator_signal TEXT,
    action_status TEXT,
    label_authority TEXT,
    evidence_confidence DOUBLE PRECISION,
    evidence_origin TEXT NOT NULL DEFAULT 'live_cowrie',
    weight_eligible BOOLEAN NOT NULL DEFAULT false,
    correct_next_tactic TEXT,
    observed_prefix TEXT,
    predicted_top_tactic TEXT,
    predicted_ranking TEXT,
    final_actual_next_tactic TEXT,
    tactic_granularity TEXT NOT NULL DEFAULT 'tactic',
    analyst_corrected_at TIMESTAMPTZ,
    notes TEXT,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_analyst_feedback_session
    ON analyst_feedback(session_id, created_at);

CREATE TABLE IF NOT EXISTS classification_review_labels (
    label_id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    command_index INTEGER NOT NULL DEFAULT 0,
    command TEXT NOT NULL,
    predicted_ttp TEXT,
    predicted_tactic TEXT,
    predicted_source TEXT,
    predicted_confidence DOUBLE PRECISION,
    reviewed_ttp TEXT,
    reviewed_tactic TEXT,
    reviewer TEXT,
    notes TEXT,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_classification_review_session
    ON classification_review_labels(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_classification_review_review_id
    ON classification_review_labels(review_id);
