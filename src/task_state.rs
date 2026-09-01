/// Closed task lifecycle transition matrix shared by durable backends and fuzz qualification.
#[doc(hidden)]
#[must_use]
pub fn task_state_transition_allowed(from: &a2a::TaskState, to: &a2a::TaskState) -> bool {
    use a2a::TaskState;
    if from == to {
        return true;
    }
    match from {
        TaskState::Unspecified => matches!(
            to,
            TaskState::Submitted | TaskState::Failed | TaskState::Rejected
        ),
        TaskState::Submitted => matches!(
            to,
            TaskState::Working
                | TaskState::InputRequired
                | TaskState::AuthRequired
                | TaskState::Completed
                | TaskState::Failed
                | TaskState::Canceled
                | TaskState::Rejected
        ),
        TaskState::Working => matches!(
            to,
            TaskState::InputRequired
                | TaskState::AuthRequired
                | TaskState::Completed
                | TaskState::Failed
                | TaskState::Canceled
                | TaskState::Rejected
        ),
        TaskState::InputRequired | TaskState::AuthRequired => matches!(
            to,
            TaskState::Working | TaskState::Failed | TaskState::Canceled | TaskState::Rejected
        ),
        TaskState::Completed | TaskState::Failed | TaskState::Canceled | TaskState::Rejected => {
            false
        }
    }
}
