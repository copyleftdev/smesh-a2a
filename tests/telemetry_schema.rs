use smesh_a2a::telemetry::{
    Attribute, AttributeKey, DropReason, EventName, MetricName, MetricPoint, Outcome,
    SeriesRegistry, Signal, SpanName, TelemetryRecord, TelemetrySchemaError,
    classify_edge_availability,
};

fn metric(operation: &str) -> TelemetryRecord {
    TelemetryRecord::metric(
        MetricPoint::new(
            MetricName::A2aRequest,
            1,
            vec![Attribute::new(AttributeKey::Operation, operation).unwrap()],
        )
        .unwrap(),
    )
}

fn a(key: AttributeKey, value: &str) -> Attribute {
    Attribute::new(key, value).unwrap()
}

#[allow(clippy::too_many_lines)] // Exhaustive closed event schema fixture.
fn required_event_attributes(event: EventName) -> Vec<Attribute> {
    use AttributeKey as K;
    let oro = || {
        vec![
            a(K::Outcome, "ok"),
            a(K::Reason, "committed"),
            a(K::Operation, "terminal_commit"),
        ]
    };
    let task = || {
        let mut values = oro();
        values.push(a(K::TaskId, "task-1"));
        values.push(a(K::ContextId, "context-1"));
        values.push(a(K::MessageId, "message-1"));
        values
    };
    let dispatch = || {
        vec![
            a(K::Outcome, "ok"),
            a(K::Reason, "committed"),
            a(K::Operation, "outbox_attempt"),
            a(K::DispatchId, "dispatch-1"),
            a(K::TaskId, "task-1"),
            a(K::ContextId, "context-1"),
            a(K::MessageId, "message-1"),
        ]
    };
    let artifact = || {
        vec![
            a(K::Outcome, "ok"),
            a(K::Reason, "committed"),
            a(K::Operation, "artifact_register"),
            a(K::ArtifactId, "artifact-1"),
            a(K::DispatchId, "dispatch-1"),
            a(K::TaskId, "task-1"),
            a(K::ContextId, "context-1"),
            a(K::MessageId, "message-1"),
        ]
    };
    match event {
        EventName::RequestCompleted => vec![
            a(K::RequestId, "0123456789abcdef0123456789abcdef"),
            a(K::Outcome, "ok"),
            a(K::Reason, "served"),
            a(K::Operation, "http_request"),
        ],
        EventName::AuthenticationDecided => vec![
            a(K::RequestId, "0123456789abcdef0123456789abcdef"),
            a(K::Outcome, "ok"),
            a(K::Reason, "verified"),
        ],
        EventName::AuthorizationDecided => vec![
            a(K::RequestId, "0123456789abcdef0123456789abcdef"),
            a(K::Outcome, "ok"),
            a(K::Reason, "verified"),
            a(K::Operation, "authorize"),
        ],
        EventName::QuotaDecided => vec![a(K::Outcome, "ok"), a(K::Operation, "lease_acquire")],
        EventName::TaskAdmitted | EventName::TaskTerminal => task(),
        EventName::CancellationRequested => task()
            .into_iter()
            .filter(|attribute| {
                !matches!(
                    attribute.key(),
                    key if key == K::MessageId.as_str() || key == K::ContextId.as_str()
                )
            })
            .collect(),
        EventName::CancellationAcknowledged | EventName::CancellationStopped => task()
            .into_iter()
            .filter(|attribute| attribute.key() != K::MessageId.as_str())
            .collect(),
        EventName::TaskTransitioned => oro(),
        EventName::DispatchClaimed
        | EventName::DispatchAttempted
        | EventName::DispatchRetried
        | EventName::DispatchDeadLettered
        | EventName::ReceiverAdmitted
        | EventName::ReceiverCompleted
        | EventName::LeaseRenewed => dispatch(),
        EventName::RuntimeLifecycle
        | EventName::RuntimeClaim
        | EventName::RuntimeContradiction
        | EventName::RuntimeTerminal => vec![
            a(K::Outcome, "ok"),
            a(K::Reason, "lifecycle"),
            a(K::Operation, "runtime_capture"),
        ],
        EventName::ArtifactStaged
        | EventName::ArtifactRegistered
        | EventName::ArtifactPromoted
        | EventName::ArtifactResolved
        | EventName::ArtifactCorruptionDetected => artifact(),
        EventName::WorkerState => vec![a(K::Outcome, "ok"), a(K::Worker, "outbox")],
        EventName::TelemetryDropped => vec![
            a(K::Outcome, "failed"),
            a(K::Signal, "logs"),
            a(K::DropReason, "queue_full"),
        ],
        EventName::AuditProjectorState => vec![
            a(
                K::EventId,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            a(K::AuditSource, "task_events"),
            a(K::Outcome, "ok"),
            a(K::Reason, "committed"),
            a(K::Operation, "task_terminal"),
        ],
    }
}

fn required_span_attributes(span: SpanName) -> Vec<Attribute> {
    use AttributeKey as K;
    let oro = || {
        vec![
            a(K::Outcome, "ok"),
            a(K::Reason, "committed"),
            a(K::Operation, "terminal_commit"),
        ]
    };
    let task = || {
        let mut values = oro();
        values.extend([
            a(K::TaskId, "task-1"),
            a(K::ContextId, "context-1"),
            a(K::MessageId, "message-1"),
        ]);
        values
    };
    let dispatch = || {
        vec![
            a(K::Outcome, "ok"),
            a(K::Reason, "committed"),
            a(K::Operation, "outbox_attempt"),
            a(K::DispatchId, "dispatch-1"),
            a(K::TaskId, "task-1"),
            a(K::ContextId, "context-1"),
            a(K::MessageId, "message-1"),
        ]
    };
    match span {
        SpanName::HttpRequest => vec![
            a(K::RequestId, "0123456789abcdef0123456789abcdef"),
            a(K::Outcome, "ok"),
            a(K::Reason, "served"),
            a(K::Operation, "http_request"),
        ],
        SpanName::AuthVerify => vec![a(K::Outcome, "ok"), a(K::Reason, "verified")],
        SpanName::AuthJwksFetch
        | SpanName::AuthorizationResolve
        | SpanName::A2aOperation
        | SpanName::DurableRead
        | SpanName::RuntimeProcess => oro(),
        SpanName::DurableAdmission | SpanName::DurableCancel | SpanName::DurableCommit => task(),
        SpanName::OutboxClaim
        | SpanName::OutboxAttempt
        | SpanName::LeaseRenew
        | SpanName::ReceiverAdmit
        | SpanName::ReceiverExecute => dispatch(),
        SpanName::ArtifactOperation => vec![
            a(K::Outcome, "ok"),
            a(K::Reason, "committed"),
            a(K::Operation, "artifact_register"),
            a(K::ArtifactId, "artifact-1"),
            a(K::DispatchId, "dispatch-1"),
            a(K::TaskId, "task-1"),
            a(K::ContextId, "context-1"),
            a(K::MessageId, "message-1"),
        ],
        SpanName::QuotaOperation => {
            vec![a(K::Outcome, "ok"), a(K::Operation, "lease_acquire")]
        }
        SpanName::WorkerCycle => vec![a(K::Outcome, "ok"), a(K::Worker, "outbox")],
    }
}

#[test]
fn unknown_span_log_metric_or_attribute_is_rejected() {
    assert!(SpanName::parse("smesh.http.request").is_ok());
    assert!(SpanName::parse("smesh.http.request.task-123").is_err());
    assert!(EventName::parse("smesh.task.terminal").is_ok());
    assert!(EventName::parse("smesh.dispatch.attempted").is_ok());
    assert!(EventName::parse("smesh.lease.renewed").is_ok());
    assert!(EventName::parse("smesh.worker.state").is_ok());
    assert!(EventName::parse("smesh.task.terminal.secret").is_err());
    assert!(MetricName::parse("smesh.a2a.request").is_ok());
    assert!(MetricName::parse("smesh.dynamic.metric").is_err());
    assert!(AttributeKey::parse("smesh.outcome").is_ok());
    assert!(AttributeKey::parse("customer.secret").is_err());
}

#[test]
fn metric_attributes_reject_correlation_identity_and_unknown_enum_values() {
    let forbidden = [
        "smesh.request.id",
        "a2a.task.id",
        "a2a.context.id",
        "a2a.message.id",
        "smesh.dispatch.id",
        "smesh.signal.hash",
        "smesh.artifact.id",
        "smesh.audit.decision_id",
        "tenant.id",
        "principal.id",
    ];
    for key in forbidden {
        let point = MetricPoint::new(
            MetricName::A2aRequest,
            1,
            vec![Attribute::new_unchecked_for_test(key, "unique")],
        );
        assert_eq!(
            point.unwrap_err(),
            TelemetrySchemaError::MetricAttributeForbidden
        );
    }
    assert!(Outcome::parse("ok").is_ok());
    assert!(Outcome::parse("customer-42").is_err());
}

#[test]
fn controls_overlong_values_raw_errors_and_secrets_are_rejected() {
    let valid = TelemetryRecord::log(
        EventName::TaskTerminal,
        required_event_attributes(EventName::TaskTerminal),
    );
    assert!(valid.is_ok());

    for value in [
        "line\nbreak".to_owned(),
        "x".repeat(513),
        "Bearer canary-secret".to_owned(),
        "postgres://user:password@db/private".to_owned(),
        "error: raw backend exploded".to_owned(),
    ] {
        assert!(Attribute::new(AttributeKey::TaskId, value).is_err());
    }
}

#[test]
fn required_lifecycle_classes_bypass_ordinary_sampling() {
    for &event in EventName::ALL {
        let attributes = required_event_attributes(event);
        let record = TelemetryRecord::log(event, attributes.clone()).unwrap();
        assert_eq!(record.signal(), Signal::Log);
        for index in 0..attributes.len() {
            let mut missing = attributes.clone();
            missing.remove(index);
            assert!(
                TelemetryRecord::log(event, missing).is_err(),
                "{} accepted a missing required attribute",
                event.as_str()
            );
        }
    }
    for event in [
        EventName::AuthenticationDecided,
        EventName::TaskTerminal,
        EventName::CancellationAcknowledged,
        EventName::AuthorizationDecided,
        EventName::ArtifactPromoted,
        EventName::RuntimeTerminal,
    ] {
        assert!(
            TelemetryRecord::log(event, required_event_attributes(event))
                .unwrap()
                .required()
        );
    }
    assert_eq!(DropReason::QueueFull.as_str(), "queue_full");
}

#[test]
fn every_span_has_an_exhaustive_required_shape_and_rejects_cross_shape_partial_identity() {
    for &span in SpanName::ALL {
        let attributes = required_span_attributes(span);
        let build = |attributes| {
            smesh_a2a::telemetry::ClosedSpan::new(
                span,
                [1; 16],
                [2; 8],
                None,
                vec![],
                1,
                2,
                attributes,
            )
        };
        assert!(
            build(attributes.clone()).is_ok(),
            "{} fixture is invalid",
            span.as_str()
        );
        for index in 0..attributes.len() {
            let mut missing = attributes.clone();
            missing.remove(index);
            assert!(
                build(missing).is_err(),
                "{} accepted removal of required attribute {}",
                span.as_str(),
                attributes[index].key()
            );
        }
    }
}

#[test]
fn metric_budget_is_closed_and_bounded() {
    let allowed = vec![Attribute::new(AttributeKey::Outcome, "ok").unwrap()];
    assert!(MetricPoint::new(MetricName::A2aRequest, 1, allowed).is_ok());
    let too_many = (0..9)
        .map(|_| Attribute::new(AttributeKey::Outcome, "ok").unwrap())
        .collect();
    assert_eq!(
        MetricPoint::new(MetricName::A2aRequest, 1, too_many).unwrap_err(),
        TelemetrySchemaError::TooManyAttributes
    );
    assert_eq!(
        MetricPoint::new(
            MetricName::A2aRequest,
            1,
            vec![
                Attribute::new(AttributeKey::Outcome, "ok").unwrap(),
                Attribute::new(AttributeKey::Outcome, "failed").unwrap(),
            ],
        )
        .unwrap_err(),
        TelemetrySchemaError::InvalidAttribute
    );
}

#[test]
fn live_series_registry_is_deterministic_and_rejects_before_exceeding_either_budget() {
    let mut registry = SeriesRegistry::with_limits_for_test(2, 3);
    let point = |name, operation: &str, outcome: &str| {
        MetricPoint::new(
            name,
            1,
            vec![
                Attribute::new(AttributeKey::Operation, operation).unwrap(),
                Attribute::new(AttributeKey::Outcome, outcome).unwrap(),
            ],
        )
        .unwrap()
    };

    let first = point(MetricName::A2aRequest, "get", "ok");
    assert!(registry.admit(&first));
    let same_reordered = MetricPoint::new(
        MetricName::A2aRequest,
        1,
        vec![
            Attribute::new(AttributeKey::Outcome, "ok").unwrap(),
            Attribute::new(AttributeKey::Operation, "get").unwrap(),
        ],
    )
    .unwrap();
    assert!(registry.admit(&same_reordered));
    assert_eq!(registry.series_count(), 1);

    assert!(registry.admit(&point(MetricName::A2aRequest, "list", "ok")));
    assert!(!registry.admit(&point(MetricName::A2aRequest, "cancel", "ok")));
    assert_eq!(registry.series_count(), 2);

    assert!(registry.admit(&point(MetricName::TaskAdmitted, "send", "ok")));
    assert!(!registry.admit(&point(MetricName::TaskSettled, "send", "failed")));
    assert_eq!(registry.series_count(), 3);
}

#[test]
fn queue_full_does_not_poison_a_new_metric_series_reservation() {
    let (telemetry, receiver) =
        smesh_a2a::telemetry::TelemetryHandle::metric_capture_with_limits_for_test(1, 2, 2);
    assert!(telemetry.try_emit(metric("get")));
    assert!(!telemetry.try_emit(metric("list")), "capacity one is full");
    receiver.recv().unwrap();
    assert!(
        telemetry.try_emit(metric("cancel")),
        "the failed list reservation must have rolled back"
    );
}

#[test]
fn closed_values_duplicate_keys_and_event_specific_shapes_are_rejected() {
    for (key, value) in [
        (AttributeKey::Reason, "invented_reason"),
        (AttributeKey::Operation, "invented_operation"),
        (AttributeKey::Protocol, "invented_protocol"),
        (AttributeKey::Backend, "invented_backend"),
        (AttributeKey::TaskState, "invented_state"),
        (AttributeKey::Worker, "invented_worker"),
        (AttributeKey::LeaseKind, "invented_lease"),
        (AttributeKey::ScopeKind, "invented_scope"),
        (AttributeKey::Dimension, "invented_dimension"),
        (AttributeKey::ArtifactState, "invented_artifact_state"),
        (AttributeKey::Result, "invented_result"),
    ] {
        assert_eq!(
            Attribute::new(key, value).unwrap_err(),
            TelemetrySchemaError::UnknownEnumValue
        );
    }

    let duplicate = TelemetryRecord::log(
        EventName::TaskTerminal,
        vec![
            Attribute::new(AttributeKey::Outcome, "ok").unwrap(),
            Attribute::new(AttributeKey::Outcome, "failed").unwrap(),
            Attribute::new(AttributeKey::TaskId, "task-1").unwrap(),
            Attribute::new(AttributeKey::ContextId, "context-1").unwrap(),
            Attribute::new(AttributeKey::Reason, "committed").unwrap(),
            Attribute::new(AttributeKey::Operation, "terminal_commit").unwrap(),
        ],
    );
    assert_eq!(
        duplicate.unwrap_err(),
        TelemetrySchemaError::InvalidAttribute
    );

    assert!(TelemetryRecord::log(EventName::RequestCompleted, vec![]).is_err());
    assert!(
        TelemetryRecord::log(
            EventName::RequestCompleted,
            vec![
                Attribute::new(AttributeKey::RequestId, "0123456789abcdef0123456789abcdef")
                    .unwrap(),
                Attribute::new(AttributeKey::Outcome, "ok").unwrap(),
                Attribute::new(AttributeKey::Reason, "served").unwrap(),
                Attribute::new(AttributeKey::Operation, "http_request").unwrap(),
                Attribute::new(AttributeKey::ArtifactId, "artifact-not-allowed").unwrap(),
            ],
        )
        .is_err()
    );
}

#[test]
fn digest_correlation_values_are_canonical_and_identifier_values_are_tokenized() {
    for invalid in [
        "sha256:ABCDEFabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "sha256:abcd",
        "not-a-digest",
    ] {
        assert!(Attribute::new(AttributeKey::SignalHash, invalid).is_err());
    }
    assert!(
        Attribute::new(
            AttributeKey::SignalHash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .is_ok()
    );
    assert!(Attribute::new(AttributeKey::TaskId, "space is forbidden").is_err());
}

#[test]
fn edge_availability_population_is_closed_and_matches_domain_semantics() {
    use axum::http::StatusCode;
    for status in [StatusCode::BAD_REQUEST, StatusCode::UNAUTHORIZED] {
        assert_eq!(classify_edge_availability(status), "ineligible");
    }
    for status in [
        StatusCode::OK,
        StatusCode::FORBIDDEN,
        StatusCode::NOT_FOUND,
        StatusCode::CONFLICT,
        StatusCode::TOO_MANY_REQUESTS,
    ] {
        assert_eq!(classify_edge_availability(status), "eligible_good");
    }
    for status in [
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::BAD_GATEWAY,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        assert_eq!(classify_edge_availability(status), "eligible_bad");
    }
}
