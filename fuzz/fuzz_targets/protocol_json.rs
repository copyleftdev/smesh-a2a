#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let _ = serde_json::from_slice::<serde_json::Value>(data);
    let _ = serde_json::from_slice::<a2a::jsonrpc::JsonRpcRequest>(data);
    let _ = serde_json::from_slice::<a2a::jsonrpc::JsonRpcResponse>(data);
    let _ = serde_json::from_slice::<a2a::SendMessageRequest>(data);
    let _ = serde_json::from_slice::<a2a::ListTasksRequest>(data);
    let _ = serde_json::from_slice::<a2a::SendMessageResponse>(data);
    let _ = serde_json::from_slice::<a2a::StreamResponse>(data);
    let _ = serde_json::from_slice::<a2a::Task>(data);
    let _ = serde_json::from_slice::<a2a::Part>(data);
    let _ = serde_json::from_slice::<a2a::SecurityScheme>(data);
    let _ = serde_json::from_slice::<a2a::OAuthFlows>(data);
    let _ = serde_json::from_slice::<a2a::AgentCard>(data);
});
