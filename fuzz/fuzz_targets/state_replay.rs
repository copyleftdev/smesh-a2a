#![no_main]

use libfuzzer_sys::fuzz_target;
use smesh_a2a::{RuntimeEventCapture, task_state_transition_allowed};

const MAX_INPUT: usize = 16 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let _ = RuntimeEventCapture::replay(data);
    let _ = serde_json::from_slice::<a2a::TaskStatus>(data);
    let _ = serde_json::from_slice::<a2a::StreamResponse>(data);
    if data.len() >= 2 {
        let states = [
            a2a::TaskState::Unspecified,
            a2a::TaskState::Submitted,
            a2a::TaskState::Working,
            a2a::TaskState::InputRequired,
            a2a::TaskState::AuthRequired,
            a2a::TaskState::Completed,
            a2a::TaskState::Failed,
            a2a::TaskState::Canceled,
            a2a::TaskState::Rejected,
        ];
        let from = &states[usize::from(data[0]) % states.len()];
        let to = &states[usize::from(data[1]) % states.len()];
        let _ = task_state_transition_allowed(from, to);
    }
});
