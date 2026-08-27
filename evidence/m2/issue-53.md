# Child #53 final-review evidence

## RED → GREEN

- Public source compatibility
  - RED: `cargo test --test public_api_compat` failed with `E0063: missing field dispatch_id in initializer of MeshRequest` at `tests/public_api_compat.rs:5`.
  - GREEN: after removing public `MeshRequest::dispatch_id` and retaining delivery identity in `AdmissionRecord`/`OutboxLease`/outbox rows, `cargo test --test public_api_compat --no-run` succeeded; the final all-target suite ran the external integration test successfully.
- Terminal typed-result requirement
  - RED: `cargo test --test atomic_lifecycle terminal_transition_without_typed_result_is_rejected_without_mutation -- --exact` failed because `commit_transition(..., None, ...)` returned `Ok(Applied)`.
  - GREEN: the same command passed after terminal transitions began requiring a final result and preserving the original row/event on rejection.
- Exact typed-result binding
  - RED: the same focused terminal test failed when a final `Task` result had the correct ID but different task content; the transition was accepted.
  - GREEN: the same command passed after final task/message results were required to exactly match the committed terminal task.
- Review-probe RED baselines (from the three supplied exact-tree review reports)
  - Forged continuation context committed and poisoned reopen.
  - A terminal transition without a final result replayed the original Submitted admission.
  - A 2 MiB `event_kind` committed and reopened.
  - Existing external `MeshRequest` struct literals failed to compile without a new field.
  - Test review found unbounded barrier reads, sequential claimers, missing retry/DLQ fault rollback evidence, narrow ASCII aggregate coverage, terminal replay only in-process, and leaked fixtures.
- Focused GREEN additions
  - `cargo test --test atomic_lifecycle retry_and_dead_letter_faults_roll_back_then_persist_exact_attempt_sequence -- --exact` — passed.
  - `cargo test --test atomic_lifecycle every_atomic_table_reopen_aggregate_counts_multibyte_bytes_without_mutation -- --exact` — passed (events, idempotency, outbox, attempts).
  - `cargo test --test atomic_lifecycle` — final exact-tree run passed 29 atomic lifecycle tests.

## Final gates

- `cargo test --all-targets --all-features` — passed (all unit/integration targets; atomic lifecycle suite green).
- `cargo fmt --all -- --check` — passed.
- `cargo doc --no-deps --all-features` — passed.
- `cargo audit` — exit 0; no vulnerability failure; one allowed pre-existing `bincode 1.3.3` unmaintained warning (`RUSTSEC-2025-0141`) through pinned `smesh-core`/`smesh-runtime`.
- `git diff --check` — passed.
- Temporary fixture check after the full suite: `atomic_temp_dirs 0`.
- `cargo clippy --all-targets --all-features -- -D warnings` initially found one test-only `too_many_lines` lint in the new retry/DLQ matrix; the test received a narrow explanatory lint allowance and clippy was rerun in the final verification cycle.

## Final adversarial review fixes

Independent exact-tree probes then reproduced three additional RED cases:

- canonical admission accepted a task payload whose message content differed from the canonical request;
- restart recovery requeued a leased final attempt into an unclaimable pending state;
- a forged `OutboxLease.task_id` could dead-letter a different task.

The final implementation now requires exact canonical request/task/result binding, atomically dead-letters abandoned final attempts during restart recovery, and fences acknowledgement/failure by durable task ID in addition to owner, token, attempt, maximum, and expiry. Focused regression tests for all three cases pass.

A subsequent exact-tree review found that replay identity also needed to bind the complete admission snapshot, continuation seed, and typed result, and that acknowledged-but-nonterminal delivery could be stranded at restart. Replay now rejects changed admission or continuation snapshots even when the canonical request digest is unchanged. Restart recovery fails acknowledged nonterminal work closed with explicit unknown-downstream-effect evidence, completes idempotency replay, and supersedes the delivered outbox intent. The test admission helper now verifies its expected derived dispatch instead of silently discarding inputs.

The final recovery probe covered multiple delivered intents for one interrupted/continued task. Recovery now supersedes every delivered intent for that task while completing only unresolved idempotency records; an earlier completed message retains its exact typed replay result and the unresolved continuation replays the recovery failure.

Public review then identified a transition-policy asymmetry. SDK updates now reject illegal lifecycle edges before writing events, dead-letter/recovery paths validate their transition, and intentional `Unspecified -> Failed` restart recovery is part of the legal matrix and remains valid on a second reopen. Exact schema lookup now distinguishes table names from prefixed index names, and task-based idempotency/outbox indexes bound the new lifecycle queries.
