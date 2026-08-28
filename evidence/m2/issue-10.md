# Issue #10 — durable frozen ListTasks pagination evidence

## Contract delivered

- First page freezes authorization-scoped membership, canonical order (`status_timestamp DESC NULLS LAST, task_id ASC`), task revision, projected task JSON, and constant `totalSize` for five minutes.
- Inserts and updates after page one cannot enter, leave, move, or alter later pages.
- SQLite schema v6 persists bounded snapshot metadata, ordered frozen entries with SHA-256 task digests, and only SHA-256 hashes of versioned 32-byte HMAC-derived opaque capabilities. A metadata HMAC binds snapshot ID, scope/query digests, page/total/frozen-byte/version/key-generation/time fields, and every ordered entry ordinal/ID/digest/revision. Every exact position `P, 2P, ... < N` is pre-issued and independently recomputed from the durable cursor key on startup and follow-up.
- Follow-up pages read only frozen entries; first-page membership uses separate tenant/owner SQL shapes with context/status/timestamp predicates pushed into SQL and eight ordering-index families.
- The in-memory bounded store retains only canonical serialized task bytes and deserializes the requested page. Its 64 MiB registry account uses checked arithmetic over every retained Vec/String capacity, fixed structure slot, and conservative allocator overhead; tokens are single-owned. Recreation intentionally invalidates its tokens.
- The request guard reads each list page exactly once from its authoritative store, validates page bounds, filters, projection, IDs, uniqueness, order, and the exact frozen task policy state. Repository-owned bounded/SQLite stores declare self-authenticating snapshot pages; generic stores additionally run the provenance hook's current-row comparison, so inconsistent injected list results still fail closed. Projected completed tasks may omit artifact bodies only after the signed receipt's task/context/policy binding verifies; policy metadata is accepted only for its exact lifecycle state.

## Repeatable tests

- `tests/store.rs::pagination_freezes_membership_total_order_and_projection`
- `tests/store.rs::frozen_pagination_matches_reference_under_mutation` — 24 deterministic proptest cases across page sizes, timestamp ties/nulls, multibyte IDs, inserts, and status/timestamp updates between every page.
- `tests/store.rs::concurrent_first_and_later_page_mutations_match_explicit_order_oracle` — barrier-raced snapshot acquisition and later-page mutation against an explicit fixture order (not the production comparator).
- `tests/store.rs::snapshot_expiry_uses_injected_monotonic_time_at_exact_boundary`, `page_size_one_snapshot_registry_byte_bound_recovers_after_expiry`, and `million_element_nested_values_are_charged_as_frozen_canonical_bytes` — exact-boundary expiry, rollback resistance, canonical-byte accounting for a million-element nested `serde_json::Value`, page-size-one capacity, and reclamation.
- `tests/sqlite_store.rs::sqlite_pagination_freezes_total_membership_and_projection_across_restart` — restart, replay, frozen JSON, constant total, membership exclusion, SHA-256 equality, and raw-token absence from DB/WAL/SHM.
- `tests/sqlite_store.rs::reopen_rejects_every_snapshot_chain_corruption_class`, `followup_page_fails_generically_when_snapshot_metadata_is_tampered`, and `failed_oversized_admission_cannot_roll_back_complete_expired_snapshot_gc` — token substitution, missing/extra positions, coordinated scope/query/time edits, revision/order/metadata corruption, generic follow-up rejection, fail-closed reopen, and independently committed complete GC.
- `tests/tenant_persistence.rs::authorized_list_persists_timestamps_and_freezes_filtered_canonical_pages` — authorized timestamp persistence/filter/order and barrier-raced SQLite first/later pages.
- `sqlite_store::tests::list_query_families_use_exact_ordering_indexes_without_temp_sort` — all eight tenant/owner context/status query families assert the intended index and reject task scans/temp B-trees.
- `tests/task_management_interop.rs::official_clients_list_tasks_with_filters_stable_pagination_and_projection` — official JSON-RPC and REST clients, tamper/query/projection/oversize rejection, and page-one → live update → frozen page-two success. `inconsistent_list_results_cannot_bypass_authoritative_store_validation` retains the malicious-store rejection.
- `tests/authorized_durable_protocol.rs::visible_list_totals_pagination_and_cursors_are_scope_bound_across_restart` — tenant/account/visibility/policy scope and restart invalidation on policy revision.

## Honest limits

- Expiry uses the durable handler's injected audit clock for authorized production requests. SQLite persists wall-clock issuance/expiry because durable expiry must survive restart; startup rejects future-shifted/overflowed issue times and requires `expiry = issued + TTL`, but wall-clock movement across process restarts cannot provide monotonic-time semantics. The generic in-memory store uses an `Instant` baseline and exposes `new_with_clock` for deterministic monotonic-clock tests; observed time is clamped against rollback.
- Key generation and token format are persisted and validated exactly at version/generation 1. SQLite stores SHA-256 of each raw HMAC-derived capability, never the capability itself; the durable cursor key is the minting authority. A future format/key rotation must introduce and validate a new exact generation.
- PostgreSQL remains logical reference DDL only; executable migrations and PostgreSQL plan evidence are outside this SQLite adapter.
