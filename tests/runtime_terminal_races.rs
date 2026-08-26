use a2a::TaskState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RaceAction {
    CompletionAttempt,
    CancellationAttempt,
    WorkEvent,
    DuplicateCancellation,
}

fn replay(actions: &[RaceAction]) -> Result<TaskState, &'static str> {
    let mut terminal = None;
    for action in actions {
        match action {
            RaceAction::CompletionAttempt => {
                terminal.get_or_insert(TaskState::Completed);
            }
            RaceAction::CancellationAttempt => {
                terminal.get_or_insert(TaskState::Canceled);
            }
            RaceAction::DuplicateCancellation => {
                if terminal.is_none() {
                    return Err("duplicate cancellation preceded a terminal winner");
                }
            }
            RaceAction::WorkEvent if terminal.is_some() => {
                return Err("work event followed terminal winner");
            }
            RaceAction::WorkEvent => {}
        }
    }
    terminal.ok_or("race trace has no terminal winner")
}

#[test]
fn terminal_winner_replay_stress_1000_without_sleeps() {
    for iteration in 0..1_000 {
        let actions = if iteration % 2 == 0 {
            vec![
                RaceAction::WorkEvent,
                RaceAction::CancellationAttempt,
                RaceAction::DuplicateCancellation,
                RaceAction::CompletionAttempt,
            ]
        } else {
            vec![
                RaceAction::WorkEvent,
                RaceAction::CompletionAttempt,
                RaceAction::CancellationAttempt,
                RaceAction::DuplicateCancellation,
            ]
        };
        let winner = replay(&actions).unwrap();
        let expected = if iteration % 2 == 0 {
            TaskState::Canceled
        } else {
            TaskState::Completed
        };
        assert_eq!(winner, expected);
        assert_eq!(replay(&actions).unwrap(), winner, "replay changed winner");
    }
}

#[test]
fn replay_rejects_late_work_and_missing_terminal() {
    assert!(replay(&[RaceAction::CancellationAttempt, RaceAction::WorkEvent]).is_err());
    assert!(replay(&[RaceAction::WorkEvent]).is_err());
}
