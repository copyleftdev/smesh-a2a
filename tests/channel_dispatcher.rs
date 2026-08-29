use a2a::{Message, Part, Role};
use futures::StreamExt;
use smesh_a2a::{
    ChannelDispatcher, DispatchCommand, InputLimits, MeshDispatcher, MeshEvent, MeshRequest,
};
use smesh_core::SignalType;
use std::time::Duration;

#[tokio::test]
async fn channel_dispatcher_hands_a_real_signal_to_the_smesh_worker() {
    let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(4);
    let dispatcher = ChannelDispatcher::new(command_tx, "gateway-node");
    let request = MeshRequest::from_a2a(
        "task-1".into(),
        "context-1".into(),
        &Message::new(Role::User, vec![Part::text("review")]),
        InputLimits::default(),
    )
    .unwrap();

    let mut events = dispatcher.dispatch(request.clone());
    let command = command_rx.recv().await.unwrap();
    let DispatchCommand::Execute {
        request: received,
        signal,
        events: event_tx,
        budget,
    } = command
    else {
        panic!("expected execute command");
    };

    assert_eq!(received, request);
    assert!(budget.max_output_bytes() > 0);
    assert!(budget.max_event_count() > 0);
    assert_eq!(signal.signal_type, SignalType::Query);
    assert_eq!(signal.origin_node_id, "gateway-node");

    event_tx
        .send(Ok(MeshEvent::Completed {
            summary: "done".into(),
        }))
        .await
        .unwrap();
    drop(event_tx);

    assert!(matches!(
        events.next().await.unwrap().unwrap(),
        MeshEvent::Completed { .. }
    ));
}

#[tokio::test]
async fn channel_dispatcher_waits_for_cancellation_acknowledgement() {
    let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(1);
    let dispatcher = ChannelDispatcher::new(command_tx, "gateway-node");

    let worker = tokio::spawn(async move {
        let DispatchCommand::Cancel { task_id, ack } = command_rx.recv().await.unwrap() else {
            panic!("expected cancellation command");
        };
        assert_eq!(task_id, "task-9");
        ack.send(Ok(())).unwrap();
    });

    dispatcher.cancel("task-9").await.unwrap();
    worker.await.unwrap();
}

#[tokio::test]
async fn channel_dispatcher_times_out_a_dropped_cancellation_acknowledgement() {
    let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(1);
    let dispatcher =
        ChannelDispatcher::new(command_tx, "gateway-node").with_timeout(Duration::from_millis(10));

    let worker = tokio::spawn(async move {
        let DispatchCommand::Cancel { ack, .. } = command_rx.recv().await.unwrap() else {
            panic!("expected cancellation command");
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(ack);
    });

    let error = dispatcher.cancel("task-timeout").await.unwrap_err();
    assert!(error.to_string().contains("acknowledgement"));
    worker.await.unwrap();
}
