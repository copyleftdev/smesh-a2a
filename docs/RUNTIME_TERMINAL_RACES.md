# Runtime terminal-race verification

Issue #6 verifies that cancellation and completion have one absorbing winner across the real runtime
and gateway boundaries.

## Deterministic cases

- `accepted_cancel_request_suppresses_completion_while_ack_is_pending`: once cancellation starts,
  the executor cancels its local run token before waiting for the dispatcher acknowledgement. A
  fully evidenced completion proposal released during that wait cannot publish.
- `dropping_cancel_response_stream_does_not_abandon_terminal_publication`: cancellation runs in an
  executor-owned task; dropping the caller's cancel response stream cannot orphan the terminal
  update.
- `failed_cancellation_acknowledgement_fails_task_and_closes_execution`: dropped or failed worker
  acknowledgement maps to terminal `Failed`; the original execution closes and cannot continue.
- `immediate_cancel_cannot_overtake_an_accepted_execute_command`: synchronous Execute reservation
  prevents cancel-before-dispatch reordering.
- `cancellation_acknowledges_only_after_runtime_processing_stops`: acknowledgement waits until the
  processor exits.
- `noncooperative_processor_is_aborted_before_cancel_acknowledgement`: bounded grace expires,
  processor is aborted and joined, then acknowledgement is sent.
- `cancellation_terminates_the_active_stream_without_post_cancel_work`: the public stream contains
  exactly one terminal cancellation and no later work or completion.
- `committed_completion_rejects_late_cancellation_without_second_terminal`: completion-first races
  reject late cancellation with `TASK_NOT_CANCELABLE`.
- `worker_completion_without_policy_evidence_cannot_publish_artifacts_or_complete` and
  `contradiction_after_completion_proposal_still_blocks_publication`: candidate artifacts and late
  events cannot evade the completion policy.

## Replay and stress

`tests/runtime_terminal_races.rs` models completion and cancellation attempts as an ordered trace.
The first terminal attempt is replayed as the absorbing winner; late work, missing terminal state,
and duplicate cancellation before a winner are rejected.

```bash
cargo test --test executor --test interop --test runtime_worker --test runtime_terminal_races
cargo test --test runtime_terminal_races terminal_winner_replay_stress_1000_without_sleeps
```

The stress test replays 1,000 alternating completion-first and cancellation-first traces without
wall-clock sleeps and verifies the same winner on a second replay.
