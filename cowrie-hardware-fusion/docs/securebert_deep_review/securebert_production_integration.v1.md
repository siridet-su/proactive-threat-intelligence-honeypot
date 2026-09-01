# Production integration

The active d5f release runs both `honeypot-session-worker.service` and
`honeypot-analysis-worker.service` as user/group `honeypot`. The normal application
release does not contain model bytes; model paths resolve through the separately
installed frozen bundle.

`SessionWorker.__init__` eagerly calls `load_securebert_classifier`, then loads and
verifies the classifier environment, and binds the callable into one
`NotebookParityClassifier`. The model is synchronous, one fragment at a time, with no
canonical batching, timeout, queue isolation, or inference worker pool.

`analysis_worker.analyze_job` reconstructs the durable prefix and calls
`load_securebert_classifier` while constructing its replay classifier. This is inside
the job-analysis function, so model construction can recur per analysis job rather
than being a process singleton. A local warm-cache load was fast, but a roughly
599-MB checkpoint and ~826-MiB measured process RSS make repeated construction an
operational concern.

The adapter's `device=auto` chooses CUDA when available, otherwise CPU. The active
classifier environment declares `device=cpu`; local reproduction used CPU. No live
process-level device probe was performed during this read-only repository review, so
GPU use is not independently claimed.

If imports, paths, or loading fail, the wrapper logs a redacted error and returns
`None`; rules and ingest continue. Model exceptions become audit-only status. Model
failure can remove corroboration or disagreement-veto behavior, but cannot stop ingest
or directly write canonical classification, semantic facts, response, prediction, or
shadow authority.

The installed model assets are fully hashed during bundle/preactivation validation,
but ordinary worker startup verifies source/policy hashes only. It does not recompute
checkpoint, tokenizer, config, or label-mapping hashes. This gap should be addressed
before claiming end-to-end runtime fail-closed model identity.

