//! Real renewal races plus synchronous first-poll loss injection.
use super::*;
use crate::*;
use async_trait::async_trait;

#[derive(Clone, Copy, Debug)]
enum Failure {
    Healthy,
    Stale,
    Error,
    Timeout,
    Owner,
    Runtime,
    DriverDrop,
    StarvedWorker,
    ReplayPending,
    SuccessSettlementPending,
    InterruptionSettlementPending,
    CancellationSettlementPendingBeforeAdmission,
    CancellationSettlementPendingAfterStop,
    RemoteCancellation,
    TerminalCancellationRace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OrdinaryStageGate {
    BeginReceive,
    Context,
    CancellationQuery,
}

struct RaceAuthority {
    before_query_return: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    begin_receives: Arc<AtomicUsize>,
    failure: Failure,
    lease: ReceiverLease,
    query_gate: bool,
    context_gate: bool,
    ordinary_stage_gate: Option<OrdinaryStageGate>,
    cancellation_queries: AtomicUsize,
    completion_calls: AtomicUsize,
    entered: Arc<Notify>,
    renewed: Arc<Notify>,
    release: Arc<Notify>,
}

struct SettlementGuard(Arc<Notify>);

impl Drop for SettlementGuard {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}
fn unused() -> a2a::A2AError {
    a2a::A2AError::internal("unused panicking authority capability")
}

impl crate::QuotaLeaseAuthority for RaceAuthority {}

impl AuthorityIdentity for RaceAuthority {
    fn capabilities(&self) -> AuthorityCapabilities {
        AuthorityCapabilities {
            lease_renewal: true,
            quota_reservations: false,
        }
    }

    fn completion_receipt_key(&self) -> Option<[u8; 32]> {
        None
    }

    fn authorization_resource_digest(&self, _: &str) -> Result<String, a2a::A2AError> {
        Err(unused())
    }
}

impl ChangeObserver for RaceAuthority {
    fn change_observation(&self) -> ChangeObservation {
        ChangeObservation::default()
    }
}

#[async_trait]
impl AuthorizationAuditSink for RaceAuthority {
    async fn append_denied_authorization_decision(
        &self,
        _: AuthorizationAuditInput,
    ) -> Result<(), a2a::A2AError> {
        Err(unused())
    }
    async fn append_authorization_decision(
        &self,
        _: AuthorizationAuditInput,
    ) -> Result<(), a2a::A2AError> {
        Err(unused())
    }
}

#[async_trait]
impl AuthorizedTaskRead for RaceAuthority {
    async fn get_authorized(
        &self,
        _: &OwnedTaskScope,
        _: &str,
        _: AuthorizationAuditInput,
    ) -> Result<Option<a2a::Task>, a2a::A2AError> {
        Err(unused())
    }
    async fn list_authorized(
        &self,
        _: &OwnedTaskScope,
        _: &a2a::ListTasksRequest,
        _: AuthorizationAuditInput,
        _: &str,
    ) -> Result<a2a::ListTasksResponse, a2a::A2AError> {
        Err(unused())
    }
}

#[async_trait]
impl TaskAdmission for RaceAuthority {
    async fn replay_authorized(
        &self,
        _: &OwnedTaskScope,
        _: &str,
        _: &a2a::SendMessageRequest,
        _: bool,
        _: AuthorizationAuditInput,
    ) -> Result<Option<a2a::SendMessageResponse>, a2a::A2AError> {
        Err(unused())
    }
    async fn authorize_and_admit(
        &self,
        _: &OwnedTaskScope,
        _: SendMessageAdmission,
        _: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, a2a::A2AError> {
        Err(unused())
    }
    async fn authorize_and_continue(
        &self,
        _: &OwnedTaskScope,
        _: SendMessageAdmission,
        _: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, a2a::A2AError> {
        Err(unused())
    }
}

#[async_trait]
impl TaskLifecycle for RaceAuthority {
    async fn final_result_scoped(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<a2a::SendMessageResponse>, a2a::A2AError> {
        Err(unused())
    }
}

#[async_trait]
impl CancellationAuthority for RaceAuthority {
    async fn cancel_authorized(
        &self,
        _: &OwnedTaskScope,
        _: &str,
        _: i64,
        _: AuthorizationAuditInput,
    ) -> Result<CancellationOutcome, a2a::A2AError> {
        Err(unused())
    }
}

#[async_trait]
impl OutboxAuthority for RaceAuthority {
    async fn load_runtime_authority_context(
        &self,
        outbox: &OutboxLease,
        receiver: &ReceiverLease,
        _: i64,
    ) -> Result<crate::DurableRuntimeAuthorityContext, a2a::A2AError> {
        if self.context_gate || self.ordinary_stage_gate == Some(OrdinaryStageGate::Context) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        let context = loopback_development_context(outbox, receiver).map_err(|_| unused())?;
        DurableRuntimeAuthorityContext::production(
            context.scope().clone(),
            context.correlation().clone(),
            context.request().clone(),
            context.transport_payload_digest().to_owned(),
            context.authorized_request_digest().to_owned(),
            ExecutionReservation {
                reservation_id: "reservation-race".into(),
                reservation_version: 1,
                binding_digest: content_digest(b"binding-race"),
                policy_id: "quota-race".into(),
                policy_revision: 1,
                policy_digest: content_digest(b"quota-race"),
                budget: ExecutionBudget::new(65536, 64).unwrap(),
            },
        )
    }

    async fn claim_outbox(
        &self,
        owner: &str,
        now: i64,
        duration: i64,
    ) -> Result<Option<OutboxLease>, a2a::A2AError> {
        let _ = (owner, now, duration);
        Err(unused())
    }
    async fn renew_outbox_lease(
        &self,
        _: &OutboxLease,
        _: i64,
    ) -> Result<LeaseRenewalOutcome, a2a::A2AError> {
        Ok(LeaseRenewalOutcome::Unsupported)
    }
    async fn task_for_outbox(&self, _: &OutboxLease) -> Result<Option<a2a::Task>, a2a::A2AError> {
        Err(unused())
    }
    async fn finish_outbox_attempt(
        &self,
        _: &OutboxLease,
        _: AttemptDisposition,
        _: i64,
    ) -> Result<TransitionOutcome, a2a::A2AError> {
        Err(unused())
    }
    async fn append_stream_progress(
        &self,
        _: &str,
        _: &str,
        _: a2a::StreamResponse,
        _: i64,
    ) -> Result<Option<a2a::StreamResponse>, a2a::A2AError> {
        Err(unused())
    }
    async fn commit_delivery(
        &self,
        _: &OutboxLease,
        _: a2a::Task,
        _: a2a::SendMessageResponse,
        _: &[a2a::StreamResponse],
        _: i64,
    ) -> Result<TransitionOutcome, a2a::A2AError> {
        Err(unused())
    }
}

#[async_trait]
impl ReceiverAuthority for RaceAuthority {
    async fn begin_receive(
        &self,
        envelope: DurableDispatchEnvelope,
        _: &str,
        _: i64,
        _: i64,
    ) -> Result<ReceiverAdmission, a2a::A2AError> {
        let receive = self.begin_receives.fetch_add(1, Ordering::SeqCst) + 1;
        if matches!(self.failure, Failure::ReplayPending) && receive == 2 {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        if matches!(
            self.failure,
            Failure::RemoteCancellation | Failure::TerminalCancellationRace
        ) && receive == 2
        {
            return Ok(ReceiverAdmission::Replay(canceled_events()));
        }
        if self.ordinary_stage_gate == Some(OrdinaryStageGate::BeginReceive) {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        let mut lease = self.lease.clone();
        lease.tenant_scope = envelope.tenant_scope;
        lease.task_id = envelope.request.task_id;
        lease.dispatch_id = envelope.dispatch_id;
        lease.payload_digest = envelope.payload_digest;
        lease.lease_epoch = match lease.tenant_scope.as_str() {
            "tenant-a" => 7,
            "tenant-b" => 11,
            _ => lease.lease_epoch,
        };
        Ok(ReceiverAdmission::Execute(lease))
    }
    async fn renew_receiver_lease(
        &self,
        _: &ReceiverLease,
        _: i64,
    ) -> Result<LeaseRenewalOutcome, a2a::A2AError> {
        self.renewed.notify_one();
        match self.failure {
            Failure::Healthy
            | Failure::SuccessSettlementPending
            | Failure::InterruptionSettlementPending
            | Failure::CancellationSettlementPendingBeforeAdmission
            | Failure::CancellationSettlementPendingAfterStop
            | Failure::RemoteCancellation
            | Failure::TerminalCancellationRace => Ok(LeaseRenewalOutcome::Applied {
                lease_until: self.lease.lease_until + 60_000,
            }),
            Failure::Stale | Failure::StarvedWorker => Ok(LeaseRenewalOutcome::Stale),
            Failure::Error => Err(unused()),
            Failure::Timeout
            | Failure::Owner
            | Failure::Runtime
            | Failure::DriverDrop
            | Failure::ReplayPending => std::future::pending().await,
        }
    }
    async fn complete_loopback_receive(
        &self,
        _: &ReceiverLease,
        _: &[MeshEvent],
        _: i64,
    ) -> Result<(), a2a::A2AError> {
        self.completion_calls.fetch_add(1, Ordering::SeqCst);
        if matches!(self.failure, Failure::SuccessSettlementPending) {
            let _guard = SettlementGuard(Arc::clone(&self.release));
            self.entered.notify_one();
            std::future::pending().await
        } else if matches!(self.failure, Failure::ReplayPending) {
            Ok(())
        } else {
            Err(unused())
        }
    }
    async fn complete_loopback_outcome(
        &self,
        _: &ReceiverLease,
        _: &crate::DurableReceiverResult,
        _: i64,
    ) -> Result<(), a2a::A2AError> {
        self.completion_calls.fetch_add(1, Ordering::SeqCst);
        if matches!(self.failure, Failure::InterruptionSettlementPending) {
            let _guard = SettlementGuard(Arc::clone(&self.release));
            self.entered.notify_one();
            std::future::pending().await
        } else {
            Err(unused())
        }
    }
    async fn complete_canceled_receive(
        &self,
        _: &ReceiverLease,
        _: &[MeshEvent],
        _: i64,
    ) -> Result<(), a2a::A2AError> {
        self.completion_calls.fetch_add(1, Ordering::SeqCst);
        if matches!(
            self.failure,
            Failure::CancellationSettlementPendingBeforeAdmission
                | Failure::CancellationSettlementPendingAfterStop
        ) {
            let _guard = SettlementGuard(Arc::clone(&self.release));
            self.entered.notify_one();
            std::future::pending().await
        } else if matches!(
            self.failure,
            Failure::RemoteCancellation | Failure::TerminalCancellationRace
        ) {
            Ok(())
        } else {
            Err(unused())
        }
    }
    async fn cancellation_requested(&self, _: &str) -> Result<bool, a2a::A2AError> {
        let query = self.cancellation_queries.fetch_add(1, Ordering::SeqCst) + 1;
        if self.query_gate
            || (self.ordinary_stage_gate == Some(OrdinaryStageGate::CancellationQuery)
                && query == 1)
        {
            self.entered.notify_one();
            self.release.notified().await;
        }
        if let Some(inject_loss) = self.before_query_return.lock().unwrap().take() {
            inject_loss();
        }
        Ok(match self.failure {
            Failure::CancellationSettlementPendingBeforeAdmission => true,
            Failure::CancellationSettlementPendingAfterStop | Failure::RemoteCancellation => {
                query >= 2
            }
            Failure::TerminalCancellationRace => query >= 3,
            _ => false,
        })
    }
}

#[async_trait]
impl TranscriptAuthority for RaceAuthority {
    async fn stream_frames_after_scoped(
        &self,
        _: &str,
        _: &str,
        _: usize,
    ) -> Result<StreamTranscriptBatch, a2a::A2AError> {
        Err(unused())
    }
    async fn subscription_snapshot_authorized(
        &self,
        _: &OwnedTaskScope,
        _: &str,
    ) -> Result<Option<(a2a::Task, SubscriptionCursor)>, a2a::A2AError> {
        Err(unused())
    }
    async fn task_events_after_scoped(
        &self,
        _: &OwnedTaskScope,
        _: &str,
        _: u64,
    ) -> Result<TaskEventBatch, a2a::A2AError> {
        Err(unused())
    }
}

#[async_trait]
impl AuthorityDiagnostics for RaceAuthority {
    async fn authorization_decision_count(&self) -> Result<u64, a2a::A2AError> {
        Err(unused())
    }
    async fn atomic_record_counts(&self) -> Result<AtomicRecordCounts, a2a::A2AError> {
        Err(unused())
    }
    async fn durable_effect_count(&self) -> Result<u64, a2a::A2AError> {
        Err(unused())
    }
}

#[async_trait]
impl AuthorityShutdown for RaceAuthority {
    async fn shutdown(&self) -> Result<(), a2a::A2AError> {
        Ok(())
    }
    fn close_owned_sync(&self) {}
}

crate::impl_unsupported_artifact_authority!(RaceAuthority);
struct RaceAdapter {
    entered: Arc<Notify>,
    admissions: Arc<AtomicUsize>,
}

struct PendingPrepareAdapter {
    entered: Arc<Notify>,
    dropped: Arc<Notify>,
}

struct PrepareGuard(Arc<Notify>);

impl Drop for PrepareGuard {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

struct PanicOnceAdapter {
    admissions: Arc<AtomicUsize>,
    reaped: Arc<Notify>,
}

struct PanicOncePermit(Arc<PanicOnceAdapter>);

struct PanicReapGuard(Arc<Notify>);

impl Drop for PanicReapGuard {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

#[async_trait]
impl PreparedDurableRuntimeDispatch for PanicOncePermit {
    async fn admit(
        self: Box<Self>,
        _: DurableWorkEnvelope,
        _: CancellationToken,
    ) -> RuntimeAdapterAdmission {
        let _reap = PanicReapGuard(Arc::clone(&self.0.reaped));
        assert_ne!(
            self.0.admissions.fetch_add(1, Ordering::SeqCst),
            0,
            "hostile admission panic"
        );
        let (sent, received) = tokio::sync::oneshot::channel();
        sent.send(RuntimeAdapterOutcome::AdmittedUnknown).unwrap();
        RuntimeAdapterAdmission::Admitted(RuntimeAdapterExecution::new(received))
    }
}

#[async_trait]
impl DurableRuntimeAdapter for PanicOnceAdapter {
    async fn prepare(&self) -> RuntimeAdapterPreparation {
        RuntimeAdapterPreparation::Ready(Box::new(PanicOncePermit(Arc::new(Self {
            admissions: Arc::clone(&self.admissions),
            reaped: Arc::clone(&self.reaped),
        }))))
    }

    async fn cancel_durable(&self, _: &DurableDispatchCorrelation) -> RuntimeCancellationRequest {
        RuntimeCancellationRequest::NotActive
    }
}

#[async_trait]
impl DurableRuntimeAdapter for PendingPrepareAdapter {
    async fn prepare(&self) -> RuntimeAdapterPreparation {
        let _guard = PrepareGuard(Arc::clone(&self.dropped));
        self.entered.notify_one();
        std::future::pending().await
    }

    async fn cancel_durable(&self, _: &DurableDispatchCorrelation) -> RuntimeCancellationRequest {
        unreachable!("prepare expiry has no admitted execution to cancel")
    }
}

struct OrdinaryStageAdapter {
    admissions: Arc<AtomicUsize>,
    entered: Arc<Notify>,
    outcome_release: Option<Arc<Notify>>,
}

struct PendingAdmissionAdapter {
    entered: Arc<Notify>,
    dropped: Arc<Notify>,
    cancellations: Arc<AtomicUsize>,
}

struct PendingAdmissionPermit(Arc<PendingAdmissionAdapter>);

struct PendingAdmissionGuard(Arc<Notify>);

impl Drop for PendingAdmissionGuard {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

#[async_trait]
impl PreparedDurableRuntimeDispatch for PendingAdmissionPermit {
    async fn admit(
        self: Box<Self>,
        _: DurableWorkEnvelope,
        _: CancellationToken,
    ) -> RuntimeAdapterAdmission {
        let _guard = PendingAdmissionGuard(Arc::clone(&self.0.dropped));
        self.0.entered.notify_one();
        std::future::pending().await
    }
}

#[async_trait]
impl DurableRuntimeAdapter for PendingAdmissionAdapter {
    async fn prepare(&self) -> RuntimeAdapterPreparation {
        RuntimeAdapterPreparation::Ready(Box::new(PendingAdmissionPermit(Arc::new(Self {
            entered: Arc::clone(&self.entered),
            dropped: Arc::clone(&self.dropped),
            cancellations: Arc::clone(&self.cancellations),
        }))))
    }

    async fn cancel_durable(&self, _: &DurableDispatchCorrelation) -> RuntimeCancellationRequest {
        self.cancellations.fetch_add(1, Ordering::SeqCst);
        RuntimeCancellationRequest::Requested
    }
}

struct OrdinaryStagePermit(Arc<OrdinaryStageAdapter>);

#[async_trait]
impl PreparedDurableRuntimeDispatch for OrdinaryStagePermit {
    async fn admit(
        self: Box<Self>,
        _: DurableWorkEnvelope,
        _: CancellationToken,
    ) -> RuntimeAdapterAdmission {
        self.0.admissions.fetch_add(1, Ordering::SeqCst);
        self.0.entered.notify_one();
        if let Some(release) = &self.0.outcome_release {
            release.notified().await;
        }
        let (sent, received) = tokio::sync::oneshot::channel();
        sent.send(RuntimeAdapterOutcome::ConfirmedStopped).unwrap();
        RuntimeAdapterAdmission::Admitted(RuntimeAdapterExecution::new(received))
    }
}

#[async_trait]
impl DurableRuntimeAdapter for OrdinaryStageAdapter {
    async fn prepare(&self) -> RuntimeAdapterPreparation {
        RuntimeAdapterPreparation::Ready(Box::new(OrdinaryStagePermit(Arc::new(Self {
            admissions: Arc::clone(&self.admissions),
            entered: Arc::clone(&self.entered),
            outcome_release: self.outcome_release.clone(),
        }))))
    }

    async fn cancel_durable(&self, _: &DurableDispatchCorrelation) -> RuntimeCancellationRequest {
        unreachable!("ordinary stage deadline occurs before runtime cancellation")
    }
}

#[derive(Clone, Copy)]
enum SettlementAdapterOutcome {
    Unknown,
    Success,
    Interruption,
    ConfirmedStopped,
}

struct SettlementAdapter {
    outcome: SettlementAdapterOutcome,
    admissions: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct RemoteCancellationAdapter {
    admitted: Arc<Notify>,
    outcome: Arc<Mutex<Option<tokio::sync::oneshot::Sender<RuntimeAdapterOutcome>>>>,
    cancellations: Arc<AtomicUsize>,
}

struct RemoteCancellationPermit(Arc<RemoteCancellationAdapter>);

#[async_trait]
impl PreparedDurableRuntimeDispatch for RemoteCancellationPermit {
    async fn admit(
        self: Box<Self>,
        _: DurableWorkEnvelope,
        _: CancellationToken,
    ) -> RuntimeAdapterAdmission {
        let (sent, received) = tokio::sync::oneshot::channel();
        *self.0.outcome.lock().unwrap() = Some(sent);
        self.0.admitted.notify_one();
        RuntimeAdapterAdmission::Admitted(RuntimeAdapterExecution::new(received))
    }
}

#[async_trait]
impl DurableRuntimeAdapter for RemoteCancellationAdapter {
    async fn prepare(&self) -> RuntimeAdapterPreparation {
        RuntimeAdapterPreparation::Ready(Box::new(RemoteCancellationPermit(Arc::new(self.clone()))))
    }

    async fn cancel_durable(&self, _: &DurableDispatchCorrelation) -> RuntimeCancellationRequest {
        self.cancellations.fetch_add(1, Ordering::SeqCst);
        if let Some(outcome) = self.outcome.lock().unwrap().take() {
            let _ = outcome.send(RuntimeAdapterOutcome::ConfirmedStopped);
            RuntimeCancellationRequest::Requested
        } else {
            RuntimeCancellationRequest::NotActive
        }
    }
}

struct SettlementPermit {
    outcome: SettlementAdapterOutcome,
    admissions: Arc<AtomicUsize>,
}

#[async_trait]
impl PreparedDurableRuntimeDispatch for SettlementPermit {
    async fn admit(
        self: Box<Self>,
        _: DurableWorkEnvelope,
        _: CancellationToken,
    ) -> RuntimeAdapterAdmission {
        self.admissions.fetch_add(1, Ordering::SeqCst);
        let outcome = match self.outcome {
            SettlementAdapterOutcome::Unknown => RuntimeAdapterOutcome::AdmittedUnknown,
            SettlementAdapterOutcome::Success => {
                RuntimeAdapterOutcome::Terminal(DurableReceiverResult {
                    events: vec![MeshEvent::Completed {
                        summary: "hostile settlement success".into(),
                    }],
                    termination: DurableReceiverTermination::Success,
                })
            }
            SettlementAdapterOutcome::Interruption => {
                RuntimeAdapterOutcome::Terminal(DurableReceiverResult {
                    events: Vec::new(),
                    termination: DurableReceiverTermination::InputRequired {
                        message: "hostile settlement interruption".into(),
                    },
                })
            }
            SettlementAdapterOutcome::ConfirmedStopped => RuntimeAdapterOutcome::ConfirmedStopped,
        };
        let (sent, received) = tokio::sync::oneshot::channel();
        sent.send(outcome).unwrap();
        RuntimeAdapterAdmission::Admitted(RuntimeAdapterExecution::new(received))
    }
}

#[async_trait]
impl DurableRuntimeAdapter for SettlementAdapter {
    async fn prepare(&self) -> RuntimeAdapterPreparation {
        RuntimeAdapterPreparation::Ready(Box::new(SettlementPermit {
            outcome: self.outcome,
            admissions: Arc::clone(&self.admissions),
        }))
    }

    async fn cancel_durable(&self, _: &DurableDispatchCorrelation) -> RuntimeCancellationRequest {
        unreachable!("settlement begins only after the runtime has resolved")
    }
}

fn ordinary_dispatch_fixture(
    lease: &ReceiverLease,
    context_id: &str,
) -> (OutboxLease, DurableDispatchEnvelope) {
    let request = MeshRequest {
        protocol: "a2a-v1".into(),
        task_id: lease.task_id.clone(),
        context_id: context_id.into(),
        text: format!("exercise {context_id}"),
    };
    let outbox = OutboxLease {
        tenant_scope: lease.tenant_scope.clone(),
        outbox_id: 1,
        dispatch_id: lease.dispatch_id.clone(),
        task_id: lease.task_id.clone(),
        attempt_no: 1,
        max_attempts: 1,
        lease_owner: "ordinary-owner".into(),
        lease_token: "ordinary-sender".into(),
        lease_until: 10_000,
        request: request.clone(),
        ratification_required: false,
        execution_reservation: None,
    };
    let envelope = DurableDispatchEnvelope {
        tenant_scope: lease.tenant_scope.clone(),
        dispatch_id: lease.dispatch_id.clone(),
        payload_digest: content_digest(&serde_json::to_vec(&request).unwrap()),
        request,
        execution_reservation: None,
    };
    (outbox, envelope)
}

fn ordinary_authority(
    lease: &ReceiverLease,
    stage: OrdinaryStageGate,
    entered: Arc<Notify>,
    renewed: Arc<Notify>,
) -> Arc<RaceAuthority> {
    Arc::new(RaceAuthority {
        before_query_return: Mutex::new(None),
        begin_receives: Arc::new(AtomicUsize::new(0)),
        failure: Failure::Healthy,
        lease: lease.clone(),
        query_gate: false,
        context_gate: false,
        ordinary_stage_gate: Some(stage),
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered,
        renewed,
        release: Arc::new(Notify::new()),
    })
}

#[tokio::test]
async fn pending_begin_receive_deadline_is_post_receive_unresolved_without_admission() {
    let lease = super::tests::receiver_lease();
    let entered = Arc::new(Notify::new());
    let authority = ordinary_authority(
        &lease,
        OrdinaryStageGate::BeginReceive,
        Arc::clone(&entered),
        Arc::new(Notify::new()),
    );
    let admissions = Arc::new(AtomicUsize::new(0));
    let coordinator = Arc::new(DurableCoordinator::new(
        authority.clone(),
        DurableCoordinatorMode::Runtime(Arc::new(OrdinaryStageAdapter {
            admissions: Arc::clone(&admissions),
            entered: Arc::new(Notify::new()),
            outcome_release: None,
        })),
        InjectedClock::new(1),
        None,
    ));
    let (outbox, envelope) = ordinary_dispatch_fixture(&lease, "context-pending-receive");
    let running = Arc::clone(&coordinator);
    let dispatch = tokio::spawn(async move {
        running
            .dispatch_once(
                &outbox,
                envelope,
                "ordinary-receive",
                "replica",
                &CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("begin_receive was not entered");
    let result = tokio::time::timeout(Duration::from_secs(1), dispatch)
        .await
        .expect("pending begin_receive exceeded the coordinator budget")
        .unwrap();
    assert!(matches!(
        result,
        Err(DurableDispatchError::PostReceiveUnresolved)
    ));
    assert_eq!(authority.begin_receives.load(Ordering::SeqCst), 1);
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(authority.completion_calls.load(Ordering::SeqCst), 0);
    assert_eq!(authority.cancellation_queries.load(Ordering::SeqCst), 0);
    assert!(coordinator.active.lock().unwrap().is_empty());
}

#[tokio::test]
async fn pending_authoritative_replay_is_bounded_after_committed_loopback_completion() {
    let lease = super::tests::receiver_lease();
    let replay_entered = Arc::new(Notify::new());
    let authority = Arc::new(RaceAuthority {
        before_query_return: Mutex::new(None),
        begin_receives: Arc::new(AtomicUsize::new(0)),
        failure: Failure::ReplayPending,
        lease: lease.clone(),
        query_gate: false,
        context_gate: false,
        ordinary_stage_gate: None,
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered: Arc::clone(&replay_entered),
        renewed: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let coordinator = Arc::new(DurableCoordinator::new(
        authority.clone(),
        DurableCoordinatorMode::Loopback(DurableLoopbackEndpoint::new()),
        InjectedClock::new(1),
        None,
    ));
    let (outbox, envelope) = ordinary_dispatch_fixture(&lease, "context-pending-replay");
    let running = Arc::clone(&coordinator);
    let dispatch = tokio::spawn(async move {
        running
            .dispatch_once(
                &outbox,
                envelope,
                "authoritative-replay",
                "replica",
                &CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), replay_entered.notified())
        .await
        .expect("authoritative replay begin_receive was not entered");
    let result = tokio::time::timeout(Duration::from_secs(1), dispatch)
        .await
        .expect("authoritative replay exceeded the coordinator phase budget")
        .unwrap();
    assert!(matches!(
        result,
        Err(DurableDispatchError::PostReceiveUnresolved)
    ));
    assert_eq!(authority.begin_receives.load(Ordering::SeqCst), 2);
    assert_eq!(authority.completion_calls.load(Ordering::SeqCst), 1);
    assert!(coordinator.active.lock().unwrap().is_empty());
}

#[allow(clippy::too_many_lines)]
async fn pending_settlement_is_bounded(
    failure: Failure,
    outcome: SettlementAdapterOutcome,
    expected_admissions: usize,
    expected_queries: usize,
) {
    let lease = super::tests::receiver_lease();
    let settlement_entered = Arc::new(Notify::new());
    let settlement_dropped = Arc::new(Notify::new());
    let authority = Arc::new(RaceAuthority {
        before_query_return: Mutex::new(None),
        begin_receives: Arc::new(AtomicUsize::new(0)),
        failure,
        lease: lease.clone(),
        query_gate: false,
        context_gate: false,
        ordinary_stage_gate: None,
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered: Arc::clone(&settlement_entered),
        renewed: Arc::new(Notify::new()),
        release: Arc::clone(&settlement_dropped),
    });
    let admissions = Arc::new(AtomicUsize::new(0));
    let coordinator = Arc::new(DurableCoordinator::new(
        authority.clone(),
        DurableCoordinatorMode::TestLoopbackAdapter(Arc::new(SettlementAdapter {
            outcome,
            admissions: Arc::clone(&admissions),
        })),
        InjectedClock::new(1),
        None,
    ));
    let (outbox, envelope) = ordinary_dispatch_fixture(&lease, "context-pending-settlement");
    let running = Arc::clone(&coordinator);
    let dispatch = tokio::spawn(async move {
        running
            .dispatch_once(
                &outbox,
                envelope,
                "pending-settlement",
                "replica",
                &CancellationToken::new(),
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(1), settlement_entered.notified())
        .await
        .expect("hostile authority settlement future was not polled");
    let result = tokio::time::timeout(Duration::from_secs(2), dispatch)
        .await
        .expect("hostile authority settlement exceeded the coordinator phase budget")
        .unwrap();
    assert!(matches!(
        result,
        Err(DurableDispatchError::PostReceiveUnresolved)
    ));
    tokio::time::timeout(Duration::from_secs(1), settlement_dropped.notified())
        .await
        .expect("coordinator returned before dropping the settlement future");
    tokio::time::timeout(Duration::from_secs(1), coordinator.wait_for_idle())
        .await
        .expect("coordinator registry did not become idle")
        .expect("coordinator registry lock was poisoned");
    assert!(coordinator.active.lock().unwrap().is_empty());
    assert_eq!(authority.begin_receives.load(Ordering::SeqCst), 1);
    assert_eq!(authority.completion_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        authority.cancellation_queries.load(Ordering::SeqCst),
        expected_queries
    );
    assert_eq!(admissions.load(Ordering::SeqCst), expected_admissions);
}

#[tokio::test]
async fn admitted_unknown_cannot_commit_cancellation_with_authoritative_intent() {
    let lease = super::tests::receiver_lease();
    let authority = Arc::new(RaceAuthority {
        before_query_return: Mutex::new(None),
        begin_receives: Arc::new(AtomicUsize::new(0)),
        failure: Failure::CancellationSettlementPendingAfterStop,
        lease: lease.clone(),
        query_gate: false,
        context_gate: false,
        ordinary_stage_gate: None,
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered: Arc::new(Notify::new()),
        renewed: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let admissions = Arc::new(AtomicUsize::new(0));
    let coordinator = Arc::new(DurableCoordinator::new(
        authority.clone(),
        DurableCoordinatorMode::TestLoopbackAdapter(Arc::new(SettlementAdapter {
            outcome: SettlementAdapterOutcome::Unknown,
            admissions: Arc::clone(&admissions),
        })),
        InjectedClock::new(1),
        None,
    ));
    let (outbox, envelope) = ordinary_dispatch_fixture(&lease, "unknown-cancellation-intent");
    let result = coordinator
        .dispatch_once(
            &outbox,
            envelope,
            "unknown",
            "replica",
            &CancellationToken::new(),
        )
        .await;
    assert!(matches!(
        result,
        Err(DurableDispatchError::PostReceiveUnresolved)
    ));
    assert_eq!(admissions.load(Ordering::SeqCst), 1);
    assert_eq!(authority.cancellation_queries.load(Ordering::SeqCst), 1);
    assert!(
        authority
            .cancellation_requested(&lease.dispatch_id)
            .await
            .unwrap(),
        "intent must be authoritative after admission"
    );
    assert_eq!(authority.completion_calls.load(Ordering::SeqCst), 0);
    coordinator.wait_for_idle().await.unwrap();
    assert!(coordinator.active.lock().unwrap().is_empty());
}

#[tokio::test]
async fn persisted_remote_cancellation_supervises_pending_runtime_admission() {
    let lease = super::tests::receiver_lease();
    let authority = Arc::new(RaceAuthority {
        before_query_return: Mutex::new(None),
        begin_receives: Arc::new(AtomicUsize::new(0)),
        failure: Failure::RemoteCancellation,
        lease: lease.clone(),
        query_gate: false,
        context_gate: false,
        ordinary_stage_gate: None,
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered: Arc::new(Notify::new()),
        renewed: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let entered = Arc::new(Notify::new());
    let dropped = Arc::new(Notify::new());
    let cancellations = Arc::new(AtomicUsize::new(0));
    let coordinator = Arc::new(DurableCoordinator::new(
        authority,
        DurableCoordinatorMode::Runtime(Arc::new(PendingAdmissionAdapter {
            entered: Arc::clone(&entered),
            dropped: Arc::clone(&dropped),
            cancellations: Arc::clone(&cancellations),
        })),
        InjectedClock::new(1),
        None,
    ));
    let (outbox, envelope) = ordinary_dispatch_fixture(&lease, "pending-remote-cancellation");
    let owned_coordinator = Arc::clone(&coordinator);
    let task = tokio::spawn(async move {
        owned_coordinator
            .dispatch_once(
                &outbox,
                envelope,
                "pending-remote-cancellation",
                "replica-test",
                &CancellationToken::new(),
            )
            .await
    });
    entered.notified().await;
    let result = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("persisted cancellation must bound pending admission")
        .unwrap();
    assert!(matches!(
        result,
        Err(DurableDispatchError::PostReceiveUnresolved)
    ));
    dropped.notified().await;
    assert_eq!(cancellations.load(Ordering::SeqCst), 1);
    coordinator.wait_for_idle().await.unwrap();
}

#[tokio::test]
async fn persisted_remote_cancellation_stops_active_runtime_and_commits_canceled() {
    let lease = super::tests::receiver_lease();
    let authority = Arc::new(RaceAuthority {
        before_query_return: Mutex::new(None),
        begin_receives: Arc::new(AtomicUsize::new(0)),
        failure: Failure::RemoteCancellation,
        lease: lease.clone(),
        query_gate: false,
        context_gate: false,
        ordinary_stage_gate: None,
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered: Arc::new(Notify::new()),
        renewed: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let admitted = Arc::new(Notify::new());
    let cancellations = Arc::new(AtomicUsize::new(0));
    let adapter = Arc::new(RemoteCancellationAdapter {
        admitted: Arc::clone(&admitted),
        outcome: Arc::new(Mutex::new(None)),
        cancellations: Arc::clone(&cancellations),
    });
    let coordinator = Arc::new(DurableCoordinator::new(
        authority.clone(),
        DurableCoordinatorMode::Runtime(adapter),
        InjectedClock::new(1),
        None,
    ));
    let (outbox, envelope) = ordinary_dispatch_fixture(&lease, "remote-cancellation");
    let running = Arc::clone(&coordinator);
    let dispatch = tokio::spawn(async move {
        running
            .dispatch_once(
                &outbox,
                envelope,
                "remote-cancellation",
                "replica-a",
                &CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), admitted.notified())
        .await
        .expect("runtime was not admitted");
    let outcome = tokio::time::timeout(Duration::from_secs(2), dispatch)
        .await
        .expect("remote cancellation was not observed")
        .unwrap()
        .expect("remote cancellation did not settle authoritatively");
    assert!(matches!(outcome, DurableDispatchOutcome::Delivered(_)));
    assert_eq!(cancellations.load(Ordering::SeqCst), 1);
    assert_eq!(authority.completion_calls.load(Ordering::SeqCst), 1);
    assert_eq!(authority.begin_receives.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn cancellation_winning_after_terminal_precheck_retries_canceled_settlement() {
    let lease = super::tests::receiver_lease();
    let authority = Arc::new(RaceAuthority {
        before_query_return: Mutex::new(None),
        begin_receives: Arc::new(AtomicUsize::new(0)),
        failure: Failure::TerminalCancellationRace,
        lease: lease.clone(),
        query_gate: false,
        context_gate: false,
        ordinary_stage_gate: None,
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered: Arc::new(Notify::new()),
        renewed: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let coordinator = Arc::new(DurableCoordinator::new(
        authority.clone(),
        DurableCoordinatorMode::Loopback(DurableLoopbackEndpoint::new()),
        InjectedClock::new(1),
        None,
    ));
    let (outbox, envelope) = ordinary_dispatch_fixture(&lease, "terminal-cancel-race");
    let outcome = coordinator
        .dispatch_once(
            &outbox,
            envelope,
            "terminal-cancel-race",
            "replica-a",
            &CancellationToken::new(),
        )
        .await
        .expect("cancellation winner must settle and replay");
    assert!(matches!(outcome, DurableDispatchOutcome::Delivered(_)));
    assert_eq!(authority.cancellation_queries.load(Ordering::SeqCst), 3);
    assert_eq!(authority.completion_calls.load(Ordering::SeqCst), 2);
    assert_eq!(authority.begin_receives.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn coordinator_shutdown_aborts_and_reaps_retained_tasks() {
    let lease = super::tests::receiver_lease();
    let authority = ordinary_authority(
        &lease,
        OrdinaryStageGate::Context,
        Arc::new(Notify::new()),
        Arc::new(Notify::new()),
    );
    let coordinator = Arc::new(DurableCoordinator::new(
        authority,
        DurableCoordinatorMode::Runtime(Arc::new(OrdinaryStageAdapter {
            admissions: Arc::new(AtomicUsize::new(0)),
            entered: Arc::new(Notify::new()),
            outcome_release: None,
        })),
        InjectedClock::new(1),
        None,
    ));
    let correlation = DurableDispatchCorrelation::from_authority_parts(
        &lease.tenant_scope,
        &lease.dispatch_id,
        1,
        lease.lease_epoch,
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let reaped = Arc::new(Notify::new());
    let task_reaped = Arc::clone(&reaped);
    let task = tokio::spawn(async move {
        let _guard = PanicReapGuard(task_reaped);
        std::future::pending::<()>().await;
    });
    coordinator.active.lock().unwrap().insert(
        correlation,
        ActiveRuntime {
            cancellation,
            join: Some(task),
        },
    );

    coordinator
        .shutdown_active(Duration::from_millis(20))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), reaped.notified())
        .await
        .expect("retained coordinator task was not reaped");
    assert!(coordinator.active.lock().unwrap().is_empty());
}

#[tokio::test]
async fn canceling_coordinator_shutdown_reaps_tasks_after_registry_drain() {
    let lease = super::tests::receiver_lease();
    let authority = ordinary_authority(
        &lease,
        OrdinaryStageGate::Context,
        Arc::new(Notify::new()),
        Arc::new(Notify::new()),
    );
    let coordinator = Arc::new(DurableCoordinator::new(
        authority,
        DurableCoordinatorMode::Runtime(Arc::new(OrdinaryStageAdapter {
            admissions: Arc::new(AtomicUsize::new(0)),
            entered: Arc::new(Notify::new()),
            outcome_release: None,
        })),
        InjectedClock::new(1),
        None,
    ));
    let mut cancelled = Vec::new();
    let mut reaped = Vec::new();
    for index in 0..2 {
        let correlation = DurableDispatchCorrelation::from_authority_parts(
            &lease.tenant_scope,
            format!("{}-{index}", lease.dispatch_id),
            1,
            lease.lease_epoch,
        )
        .unwrap();
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task_reaped = Arc::new(Notify::new());
        reaped.push(Arc::clone(&task_reaped));
        let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
        cancelled.push(cancelled_rx);
        let task = tokio::spawn(async move {
            let _guard = PanicReapGuard(task_reaped);
            task_cancellation.cancelled().await;
            let _ = cancelled_tx.send(());
            std::future::pending::<()>().await;
        });
        coordinator.active.lock().unwrap().insert(
            correlation,
            ActiveRuntime {
                cancellation,
                join: Some(task),
            },
        );
    }

    let shutdown_coordinator = Arc::clone(&coordinator);
    let shutdown = tokio::spawn(async move {
        shutdown_coordinator
            .shutdown_active(Duration::from_secs(60))
            .await
    });
    for cancelled_rx in cancelled {
        tokio::time::timeout(Duration::from_secs(1), cancelled_rx)
            .await
            .expect("shutdown did not cancel every drained retained task")
            .unwrap();
    }
    shutdown.abort();
    let _ = shutdown.await;

    for reaped in reaped {
        tokio::time::timeout(Duration::from_secs(1), reaped.notified())
            .await
            .expect("canceling shutdown detached a drained coordinator task");
    }
    assert!(coordinator.active.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rejected_duplicate_cannot_remove_the_incumbent_correlation_owner() {
    let lease = super::tests::receiver_lease();
    let authority = ordinary_authority(
        &lease,
        OrdinaryStageGate::Context,
        Arc::new(Notify::new()),
        Arc::new(Notify::new()),
    );
    let coordinator = Arc::new(DurableCoordinator::new(
        authority,
        DurableCoordinatorMode::Runtime(Arc::new(OrdinaryStageAdapter {
            admissions: Arc::new(AtomicUsize::new(0)),
            entered: Arc::new(Notify::new()),
            outcome_release: None,
        })),
        InjectedClock::new(1),
        None,
    ));
    let correlation = DurableDispatchCorrelation::from_authority_parts(
        &lease.tenant_scope,
        &lease.dispatch_id,
        1,
        lease.lease_epoch,
    )
    .unwrap();
    coordinator.retain_test_runtime(
        correlation.clone(),
        CancellationToken::new(),
        tokio::spawn(std::future::pending()),
    );

    let duplicate_coordinator = Arc::clone(&coordinator);
    let duplicate_correlation = correlation.clone();
    let (_registered, registration) = tokio::sync::oneshot::channel::<()>();
    let duplicate = tokio::spawn(async move {
        if registration.await.is_err() {
            return;
        }
        let _cleanup = ActiveRuntimeCleanup {
            coordinator: duplicate_coordinator,
            correlation: duplicate_correlation,
        };
        std::future::pending::<()>().await;
    });
    duplicate.abort();
    let _ = duplicate.await;

    assert!(
        coordinator
            .active
            .lock()
            .unwrap()
            .contains_key(&correlation)
    );
    coordinator
        .shutdown_active(Duration::from_millis(20))
        .await
        .unwrap();
}

#[tokio::test]
async fn pending_success_settlement_is_bounded_without_authoritative_replay() {
    pending_settlement_is_bounded(
        Failure::SuccessSettlementPending,
        SettlementAdapterOutcome::Success,
        1,
        3,
    )
    .await;
}

#[tokio::test]
async fn pending_interruption_settlement_is_bounded_without_authoritative_replay() {
    pending_settlement_is_bounded(
        Failure::InterruptionSettlementPending,
        SettlementAdapterOutcome::Interruption,
        1,
        3,
    )
    .await;
}

#[tokio::test]
async fn pending_requested_cancellation_settlement_is_bounded_before_admission() {
    pending_settlement_is_bounded(
        Failure::CancellationSettlementPendingBeforeAdmission,
        SettlementAdapterOutcome::ConfirmedStopped,
        0,
        1,
    )
    .await;
}

#[tokio::test]
async fn terminal_proposal_racing_authoritative_cancellation_uses_canceled_settlement() {
    pending_settlement_is_bounded(
        Failure::CancellationSettlementPendingAfterStop,
        SettlementAdapterOutcome::Success,
        1,
        2,
    )
    .await;
}

#[tokio::test]
async fn pending_confirmed_stop_settlement_is_bounded_without_authoritative_replay() {
    pending_settlement_is_bounded(
        Failure::CancellationSettlementPendingAfterStop,
        SettlementAdapterOutcome::ConfirmedStopped,
        1,
        2,
    )
    .await;
}

#[tokio::test]
async fn pending_runtime_authority_context_deadline_keeps_healthy_receiver_unresolved() {
    let lease = super::tests::receiver_lease();
    let entered = Arc::new(Notify::new());
    let renewed = Arc::new(Notify::new());
    let authority = ordinary_authority(
        &lease,
        OrdinaryStageGate::Context,
        Arc::clone(&entered),
        Arc::clone(&renewed),
    );
    let admissions = Arc::new(AtomicUsize::new(0));
    let coordinator = Arc::new(DurableCoordinator::new(
        authority.clone(),
        DurableCoordinatorMode::Runtime(Arc::new(OrdinaryStageAdapter {
            admissions: Arc::clone(&admissions),
            entered: Arc::new(Notify::new()),
            outcome_release: None,
        })),
        InjectedClock::new(1),
        None,
    ));
    let (outbox, envelope) = ordinary_dispatch_fixture(&lease, "context-pending-authority");
    let running = Arc::clone(&coordinator);
    let dispatch = tokio::spawn(async move {
        running
            .dispatch_once(
                &outbox,
                envelope,
                "ordinary-context",
                "replica",
                &CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("runtime authority context load was not entered");
    tokio::time::timeout(Duration::from_secs(1), renewed.notified())
        .await
        .expect("healthy receiver did not renew during pending context load");
    let result = tokio::time::timeout(Duration::from_secs(1), dispatch)
        .await
        .expect("pending runtime authority context exceeded the coordinator budget")
        .unwrap();
    assert!(matches!(
        result,
        Err(DurableDispatchError::PostReceiveUnresolved)
    ));
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(authority.completion_calls.load(Ordering::SeqCst), 0);
    assert!(coordinator.active.lock().unwrap().is_empty());
}

#[tokio::test]
async fn pending_final_cancellation_query_deadline_keeps_healthy_receiver_unresolved() {
    let lease = super::tests::receiver_lease();
    let query_entered = Arc::new(Notify::new());
    let renewed = Arc::new(Notify::new());
    let authority = ordinary_authority(
        &lease,
        OrdinaryStageGate::CancellationQuery,
        Arc::clone(&query_entered),
        Arc::clone(&renewed),
    );
    let admissions = Arc::new(AtomicUsize::new(0));
    let coordinator = Arc::new(DurableCoordinator::new(
        authority.clone(),
        DurableCoordinatorMode::Runtime(Arc::new(OrdinaryStageAdapter {
            admissions: Arc::clone(&admissions),
            entered: Arc::new(Notify::new()),
            outcome_release: None,
        })),
        InjectedClock::new(1),
        None,
    ));
    let (outbox, envelope) = ordinary_dispatch_fixture(&lease, "context-pending-final-query");
    let running = Arc::clone(&coordinator);
    let dispatch = tokio::spawn(async move {
        running
            .dispatch_once(
                &outbox,
                envelope,
                "ordinary-final-query",
                "replica",
                &CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), query_entered.notified())
        .await
        .expect("final pre-admission cancellation query was not entered");
    tokio::time::timeout(Duration::from_secs(1), renewed.notified())
        .await
        .expect("healthy receiver did not renew during the pending cancellation query");
    let result = tokio::time::timeout(Duration::from_secs(1), dispatch)
        .await
        .expect("pending final cancellation query exceeded the coordinator budget")
        .unwrap();
    assert!(matches!(
        result,
        Err(DurableDispatchError::PostReceiveUnresolved)
    ));
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(authority.cancellation_queries.load(Ordering::SeqCst), 1);
    assert_eq!(authority.completion_calls.load(Ordering::SeqCst), 0);
    assert!(coordinator.active.lock().unwrap().is_empty());
}

#[tokio::test]
async fn pending_prepare_deadline_is_coordinator_owned_before_receive() {
    let lease = super::tests::receiver_lease();
    let begin_receives = Arc::new(AtomicUsize::new(0));
    let authority = Arc::new(RaceAuthority {
        before_query_return: Mutex::new(None),
        begin_receives: Arc::clone(&begin_receives),
        failure: Failure::Owner,
        lease: lease.clone(),
        query_gate: false,
        context_gate: false,
        ordinary_stage_gate: None,
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered: Arc::new(Notify::new()),
        renewed: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let entered = Arc::new(Notify::new());
    let dropped = Arc::new(Notify::new());
    let adapter = Arc::new(PendingPrepareAdapter {
        entered: Arc::clone(&entered),
        dropped: Arc::clone(&dropped),
    });
    let coordinator = Arc::new(DurableCoordinator::new(
        authority,
        DurableCoordinatorMode::Runtime(adapter),
        InjectedClock::new(1),
        None,
    ));
    let request = MeshRequest {
        protocol: "a2a-v1".into(),
        task_id: lease.task_id.clone(),
        context_id: "context-pending-prepare".into(),
        text: "pending prepare".into(),
    };
    let outbox = OutboxLease {
        tenant_scope: lease.tenant_scope.clone(),
        outbox_id: 1,
        dispatch_id: lease.dispatch_id.clone(),
        task_id: lease.task_id,
        attempt_no: 1,
        max_attempts: 1,
        lease_owner: "owner".into(),
        lease_token: "sender".into(),
        lease_until: 10_000,
        request: request.clone(),
        ratification_required: false,
        execution_reservation: None,
    };
    let envelope = DurableDispatchEnvelope {
        tenant_scope: lease.tenant_scope,
        dispatch_id: lease.dispatch_id,
        payload_digest: content_digest(&serde_json::to_vec(&request).unwrap()),
        request,
        execution_reservation: None,
    };
    let owner = CancellationToken::new();
    let running = Arc::clone(&coordinator);
    let task = tokio::spawn(async move {
        running
            .dispatch_once(&outbox, envelope, "generation", "replica", &owner)
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("prepare was not polled");
    let result = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("healthy receiver cannot make pending prepare unbounded")
        .unwrap();
    assert!(matches!(result, Ok(DurableDispatchOutcome::Busy)));
    tokio::time::timeout(Duration::from_secs(1), dropped.notified())
        .await
        .expect("coordinator returned before dropping prepare future");
    assert_eq!(begin_receives.load(Ordering::SeqCst), 0);
    assert!(coordinator.active.lock().unwrap().is_empty());
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn admission_panic_reaps_runtime_and_releases_exact_correlation() {
    let lease = super::tests::receiver_lease();
    let authority = Arc::new(RaceAuthority {
        before_query_return: Mutex::new(None),
        begin_receives: Arc::new(AtomicUsize::new(0)),
        failure: Failure::Owner,
        lease: lease.clone(),
        query_gate: false,
        context_gate: false,
        ordinary_stage_gate: None,
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered: Arc::new(Notify::new()),
        renewed: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let admissions = Arc::new(AtomicUsize::new(0));
    let reaped = Arc::new(Notify::new());
    let adapter = Arc::new(PanicOnceAdapter {
        admissions: Arc::clone(&admissions),
        reaped: Arc::clone(&reaped),
    });
    let coordinator = Arc::new(DurableCoordinator::new(
        authority,
        DurableCoordinatorMode::Runtime(adapter),
        InjectedClock::new(1),
        None,
    ));
    let build = || {
        let request = MeshRequest {
            protocol: "a2a-v1".into(),
            task_id: lease.task_id.clone(),
            context_id: "context-admission-panic".into(),
            text: "panic once".into(),
        };
        (
            OutboxLease {
                tenant_scope: lease.tenant_scope.clone(),
                outbox_id: 1,
                dispatch_id: lease.dispatch_id.clone(),
                task_id: lease.task_id.clone(),
                attempt_no: 1,
                max_attempts: 1,
                lease_owner: "owner".into(),
                lease_token: "sender".into(),
                lease_until: 10_000,
                request: request.clone(),
                ratification_required: false,
                execution_reservation: None,
            },
            DurableDispatchEnvelope {
                tenant_scope: lease.tenant_scope.clone(),
                dispatch_id: lease.dispatch_id.clone(),
                payload_digest: content_digest(&serde_json::to_vec(&request).unwrap()),
                request,
                execution_reservation: None,
            },
        )
    };
    let (first_outbox, first_envelope) = build();
    let first = tokio::time::timeout(
        Duration::from_secs(1),
        coordinator.dispatch_once(
            &first_outbox,
            first_envelope,
            "generation",
            "replica",
            &CancellationToken::new(),
        ),
    )
    .await
    .expect("panicking runtime task was not reaped");
    assert!(matches!(
        first,
        Err(DurableDispatchError::PostReceiveUnresolved)
    ));
    tokio::time::timeout(Duration::from_secs(1), reaped.notified())
        .await
        .expect("panicking permit guard was not dropped");
    assert!(
        coordinator.active.lock().unwrap().is_empty(),
        "panicking child retained exact correlation"
    );

    let (second_outbox, second_envelope) = build();
    let second = coordinator
        .dispatch_once(
            &second_outbox,
            second_envelope,
            "generation",
            "replica",
            &CancellationToken::new(),
        )
        .await;
    assert!(matches!(
        second,
        Err(DurableDispatchError::PostReceiveUnresolved)
    ));
    assert_eq!(
        admissions.load(Ordering::SeqCst),
        2,
        "same correlation was not admitted after panic cleanup"
    );
    assert!(coordinator.active.lock().unwrap().is_empty());
}

#[derive(Clone, Copy)]
enum HostileCancellation {
    Pending,
    Requested,
}

struct HostileAdapter {
    entered: Arc<Notify>,
    admission_dropped: Arc<Notify>,
    execution_reaped: Arc<Notify>,
    admission_pending: bool,
    cancellation: HostileCancellation,
}

struct HostilePermit(Arc<HostileAdapter>);

struct AdmissionGuard(Arc<Notify>);

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

#[async_trait]
impl PreparedDurableRuntimeDispatch for HostilePermit {
    async fn admit(
        self: Box<Self>,
        _: DurableWorkEnvelope,
        _: CancellationToken,
    ) -> RuntimeAdapterAdmission {
        let _guard = AdmissionGuard(Arc::clone(&self.0.admission_dropped));
        self.0.entered.notify_one();
        if self.0.admission_pending {
            std::future::pending::<()>().await;
        }
        let (mut sent, received) = tokio::sync::oneshot::channel();
        let reaped = Arc::clone(&self.0.execution_reaped);
        tokio::spawn(async move {
            sent.closed().await;
            reaped.notify_one();
        });
        RuntimeAdapterAdmission::Admitted(RuntimeAdapterExecution::new(received))
    }
}

#[async_trait]
impl DurableRuntimeAdapter for HostileAdapter {
    async fn prepare(&self) -> RuntimeAdapterPreparation {
        unreachable!("tests call run_admitted at the prepared seam")
    }

    async fn cancel_durable(&self, _: &DurableDispatchCorrelation) -> RuntimeCancellationRequest {
        match self.cancellation {
            HostileCancellation::Pending => std::future::pending().await,
            HostileCancellation::Requested => RuntimeCancellationRequest::Requested,
        }
    }
}

#[derive(Default)]
struct HoldingAdapter {
    active: Mutex<HashMap<DurableDispatchCorrelation, CancellationToken>>,
    canceled: Mutex<Vec<DurableDispatchCorrelation>>,
    changed: Notify,
}

struct HoldingPermit(Arc<HoldingAdapter>);

#[async_trait]
impl PreparedDurableRuntimeDispatch for HoldingPermit {
    async fn admit(
        self: Box<Self>,
        envelope: DurableWorkEnvelope,
        cancellation: CancellationToken,
    ) -> RuntimeAdapterAdmission {
        let correlation = envelope.correlation().clone();
        self.0
            .active
            .lock()
            .unwrap()
            .insert(correlation.clone(), cancellation.clone());
        self.0.changed.notify_waiters();
        let adapter = Arc::clone(&self.0);
        let (sent, received) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            cancellation.cancelled().await;
            adapter.canceled.lock().unwrap().push(correlation.clone());
            adapter.active.lock().unwrap().remove(&correlation);
            adapter.changed.notify_waiters();
            let _ = sent.send(RuntimeAdapterOutcome::AdmittedUnknown);
        });
        RuntimeAdapterAdmission::Admitted(RuntimeAdapterExecution::new(received))
    }
}

#[async_trait]
impl DurableRuntimeAdapter for Arc<HoldingAdapter> {
    async fn prepare(&self) -> RuntimeAdapterPreparation {
        RuntimeAdapterPreparation::Ready(Box::new(HoldingPermit(Arc::clone(self))))
    }

    async fn cancel_durable(
        &self,
        correlation: &DurableDispatchCorrelation,
    ) -> RuntimeCancellationRequest {
        if let Some(cancel) = self.active.lock().unwrap().get(correlation).cloned() {
            cancel.cancel();
            RuntimeCancellationRequest::Requested
        } else {
            RuntimeCancellationRequest::NotActive
        }
    }
}

struct RacePermit(Arc<RaceAdapter>);
#[async_trait]
impl PreparedDurableRuntimeDispatch for RacePermit {
    async fn admit(
        self: Box<Self>,
        _: DurableWorkEnvelope,
        cancellation: CancellationToken,
    ) -> RuntimeAdapterAdmission {
        self.0.admissions.fetch_add(1, Ordering::SeqCst);
        self.0.entered.notify_one();
        let (sent, received) = tokio::sync::oneshot::channel();
        // Admission already owns execution, but its acknowledgement is withheld.
        cancellation.cancelled().await;
        sent.send(RuntimeAdapterOutcome::ConfirmedStopped).unwrap();
        RuntimeAdapterAdmission::Admitted(RuntimeAdapterExecution::new(received))
    }
}
#[async_trait]
impl DurableRuntimeAdapter for Arc<RaceAdapter> {
    async fn prepare(&self) -> RuntimeAdapterPreparation {
        RuntimeAdapterPreparation::Ready(Box::new(RacePermit(Arc::clone(self))))
    }
    async fn cancel_durable(&self, _: &DurableDispatchCorrelation) -> RuntimeCancellationRequest {
        RuntimeCancellationRequest::Unknown
    }
}

#[allow(clippy::too_many_lines)]
async fn hostile_run(
    admission_pending: bool,
    cancellation_kind: HostileCancellation,
    cancel_owner: bool,
) {
    let lease = super::tests::receiver_lease();
    let owner = CancellationToken::new();
    let cancellation = CancellationToken::new();
    let mut renewal = None;
    let authority = Arc::new(RaceAuthority {
        before_query_return: Mutex::new(None),
        begin_receives: Arc::new(AtomicUsize::new(0)),
        failure: Failure::Owner,
        lease: lease.clone(),
        query_gate: false,
        context_gate: false,
        ordinary_stage_gate: None,
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered: Arc::new(Notify::new()),
        renewed: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let entered = Arc::new(Notify::new());
    let admission_dropped = Arc::new(Notify::new());
    let execution_reaped = Arc::new(Notify::new());
    let adapter = Arc::new(HostileAdapter {
        entered: Arc::clone(&entered),
        admission_dropped: Arc::clone(&admission_dropped),
        execution_reaped: Arc::clone(&execution_reaped),
        admission_pending,
        cancellation: cancellation_kind,
    });
    let coordinator = Arc::new(DurableCoordinator::new(
        authority.clone(),
        DurableCoordinatorMode::Runtime(adapter.clone()),
        InjectedClock::new(1),
        None,
    ));
    let request = MeshRequest {
        protocol: "a2a-v1".into(),
        task_id: lease.task_id.clone(),
        context_id: "context-hostile".into(),
        text: "hostile".into(),
    };
    let outbox = OutboxLease {
        tenant_scope: lease.tenant_scope.clone(),
        outbox_id: 1,
        dispatch_id: lease.dispatch_id.clone(),
        task_id: lease.task_id.clone(),
        attempt_no: 1,
        max_attempts: 1,
        lease_owner: "owner".into(),
        lease_token: "sender".into(),
        lease_until: 10_000,
        request: request.clone(),
        ratification_required: false,
        execution_reservation: None,
    };
    let envelope = DurableDispatchEnvelope {
        tenant_scope: lease.tenant_scope.clone(),
        dispatch_id: lease.dispatch_id.clone(),
        payload_digest: content_digest(&serde_json::to_vec(&request).unwrap()),
        request,
        execution_reservation: None,
    };
    let context = authority
        .load_runtime_authority_context(&outbox, &lease, 1)
        .await
        .unwrap();
    let running = Arc::clone(&coordinator);
    let task_owner = owner.clone();
    let task = tokio::spawn(async move {
        running
            .run_admitted(
                Box::new(HostilePermit(adapter)),
                context,
                &lease,
                envelope,
                "generation",
                "replica",
                &task_owner,
                &cancellation,
                &mut renewal,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("hostile adapter was not entered");
    if cancel_owner {
        owner.cancel();
    }
    let result = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("coordinator did not enforce its supervision bounds")
        .unwrap();
    assert!(matches!(
        result,
        Err(DurableDispatchError::PostReceiveUnresolved)
    ));
    let reaped = if admission_pending {
        admission_dropped.notified()
    } else {
        execution_reaped.notified()
    };
    tokio::time::timeout(Duration::from_secs(1), reaped)
        .await
        .expect("coordinator returned before dropping the phase-owned hostile future");
}

#[tokio::test]
async fn owner_cancellation_bounds_an_already_polled_pending_admission() {
    hostile_run(true, HostileCancellation::Requested, true).await;
}

#[tokio::test]
async fn permanently_pending_cancel_durable_is_bounded_and_reaped() {
    hostile_run(false, HostileCancellation::Pending, true).await;
}

#[tokio::test]
async fn requested_cancellation_with_pending_execution_is_bounded_and_reaped() {
    hostile_run(false, HostileCancellation::Requested, true).await;
}

#[tokio::test]
async fn pending_admission_deadline_is_coordinator_owned_after_receive() {
    hostile_run(true, HostileCancellation::Requested, false).await;
}

#[tokio::test]
async fn pending_execution_deadline_is_coordinator_owned_after_receive() {
    hostile_run(false, HostileCancellation::Requested, false).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn coordinator_registry_keys_cancellation_by_full_correlation() {
    let authority = Arc::new(RaceAuthority {
        before_query_return: Mutex::new(None),
        begin_receives: Arc::new(AtomicUsize::new(0)),
        failure: Failure::Owner,
        lease: super::tests::receiver_lease(),
        query_gate: false,
        context_gate: false,
        ordinary_stage_gate: None,
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered: Arc::new(Notify::new()),
        renewed: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let adapter = Arc::new(HoldingAdapter::default());
    let coordinator = Arc::new(DurableCoordinator::new(
        authority,
        DurableCoordinatorMode::Runtime(Arc::new(adapter.clone())),
        InjectedClock::new(1),
        None,
    ));
    let build = |tenant: &str, task: &str, outbox_id: i64| {
        let request = MeshRequest {
            protocol: "a2a-v1".into(),
            task_id: task.into(),
            context_id: format!("context-{tenant}"),
            text: "hold".into(),
        };
        let outbox = OutboxLease {
            tenant_scope: tenant.into(),
            outbox_id,
            dispatch_id: "shared-dispatch".into(),
            task_id: task.into(),
            attempt_no: 1,
            max_attempts: 1,
            lease_owner: "owner".into(),
            lease_token: format!("sender-{tenant}"),
            lease_until: 10_000,
            request: request.clone(),
            ratification_required: false,
            execution_reservation: None,
        };
        let envelope = DurableDispatchEnvelope {
            tenant_scope: tenant.into(),
            dispatch_id: "shared-dispatch".into(),
            payload_digest: content_digest(&serde_json::to_vec(&request).unwrap()),
            request,
            execution_reservation: None,
        };
        (outbox, envelope)
    };
    let (outbox_a, envelope_a) = build("tenant-a", "task-a", 1);
    let (outbox_b, envelope_b) = build("tenant-b", "task-b", 2);
    let first =
        DurableDispatchCorrelation::from_authority_parts("tenant-a", "shared-dispatch", 1, 7)
            .unwrap();
    let second =
        DurableDispatchCorrelation::from_authority_parts("tenant-b", "shared-dispatch", 1, 11)
            .unwrap();
    let owner_a = CancellationToken::new();
    let owner_b = CancellationToken::new();
    let running_a = Arc::clone(&coordinator);
    let task_a = tokio::spawn(async move {
        running_a
            .dispatch_once(&outbox_a, envelope_a, "generation-a", "replica", &owner_a)
            .await
    });
    let running_b = Arc::clone(&coordinator);
    let task_b = tokio::spawn(async move {
        running_b
            .dispatch_once(&outbox_b, envelope_b, "generation-b", "replica", &owner_b)
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if adapter.active.lock().unwrap().len() == 2 {
                break;
            }
            adapter.changed.notified().await;
        }
    })
    .await
    .expect("both full correlations were not concurrently admitted");
    assert!(adapter.active.lock().unwrap().contains_key(&first));
    assert!(adapter.active.lock().unwrap().contains_key(&second));

    coordinator.signal_cancel(&first);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if adapter.canceled.lock().unwrap().contains(&first) {
                break;
            }
            adapter.changed.notified().await;
        }
    })
    .await
    .expect("target did not observe cancellation");
    assert_eq!(
        adapter.canceled.lock().unwrap().as_slice(),
        std::slice::from_ref(&first)
    );
    assert!(
        adapter.active.lock().unwrap().contains_key(&second),
        "same dispatch ID in a distinct correlation observed foreign cancellation"
    );
    assert!(matches!(
        task_a.await.unwrap(),
        Err(DurableDispatchError::PostReceiveUnresolved)
    ));

    coordinator.signal_cancel(&second);
    assert!(matches!(
        task_b.await.unwrap(),
        Err(DurableDispatchError::PostReceiveUnresolved)
    ));
    assert!(coordinator.active.lock().unwrap().is_empty());
}

#[allow(clippy::too_many_lines)] // Keep loss injection, first poll, and zero-admission assertions together.
async fn first_poll_loss(failure: Failure) {
    let lease = super::tests::receiver_lease();
    let owner = CancellationToken::new();
    let cancellation = CancellationToken::new();
    let (status, latest) = tokio::sync::watch::channel(Ok(lease.clone()));
    let _keep_status_open = status.clone();
    let mut renewal = Some(ReceiverRenewal {
        cancel: CancellationToken::new(),
        latest,
        join: None,
    });
    let injected = Arc::new(AtomicUsize::new(0));
    let injection_count = Arc::clone(&injected);
    let lost_token = match failure {
        Failure::Owner => owner.clone(),
        Failure::Runtime => cancellation.clone(),
        Failure::Stale => CancellationToken::new(),
        _ => panic!("unsupported first-poll loss"),
    };
    let authority = Arc::new(RaceAuthority {
        before_query_return: Mutex::new(Some(Box::new(move || {
            injection_count.fetch_add(1, Ordering::SeqCst);
            if matches!(failure, Failure::Stale) {
                status.send(Err(())).unwrap();
            } else {
                lost_token.cancel();
            }
        }))),
        begin_receives: Arc::new(AtomicUsize::new(0)),
        failure,
        lease: lease.clone(),
        query_gate: false,
        context_gate: false,
        ordinary_stage_gate: None,
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered: Arc::new(Notify::new()),
        renewed: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let adapter = Arc::new(RaceAdapter {
        entered: Arc::new(Notify::new()),
        admissions: Arc::new(AtomicUsize::new(0)),
    });
    let coordinator = DurableCoordinator::new(
        authority.clone(),
        DurableCoordinatorMode::Runtime(Arc::new(adapter.clone())),
        InjectedClock::new(1),
        None,
    );
    let request = MeshRequest {
        protocol: "a2a-v1".into(),
        task_id: lease.task_id.clone(),
        context_id: "context-first-poll".into(),
        text: "race".into(),
    };
    let outbox = OutboxLease {
        tenant_scope: lease.tenant_scope.clone(),
        outbox_id: 1,
        dispatch_id: lease.dispatch_id.clone(),
        task_id: lease.task_id.clone(),
        attempt_no: 1,
        max_attempts: 1,
        lease_owner: "owner".into(),
        lease_token: "sender".into(),
        lease_until: 10000,
        request: request.clone(),
        ratification_required: false,
        execution_reservation: None,
    };
    let envelope = DurableDispatchEnvelope {
        tenant_scope: lease.tenant_scope.clone(),
        dispatch_id: lease.dispatch_id.clone(),
        payload_digest: content_digest(&serde_json::to_vec(&request).unwrap()),
        request,
        execution_reservation: None,
    };
    let context = authority
        .load_runtime_authority_context(&outbox, &lease, 1)
        .await
        .unwrap();
    // No yield between the final query's loss injection and the admission select.
    let result = coordinator
        .run_admitted(
            Box::new(RacePermit(adapter.clone())),
            context,
            &lease,
            envelope,
            "generation",
            "replica",
            &owner,
            &cancellation,
            &mut renewal,
        )
        .await;
    assert_eq!(
        injected.load(Ordering::SeqCst),
        1,
        "loss injector did not fire"
    );
    assert!(cancellation.is_cancelled());
    assert!(matches!(
        result,
        Err(DurableDispatchError::FatalRenewal | DurableDispatchError::PostReceiveUnresolved)
    ));
    assert_eq!(
        adapter.admissions.load(Ordering::SeqCst),
        0,
        "observed loss must not first-poll admission"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn owner_loss_before_first_poll_never_admits() {
    first_poll_loss(Failure::Owner).await;
}

#[tokio::test(flavor = "current_thread")]
async fn receiver_loss_before_first_poll_never_admits() {
    first_poll_loss(Failure::Stale).await;
}

#[tokio::test(flavor = "current_thread")]
async fn runtime_loss_before_first_poll_never_admits() {
    first_poll_loss(Failure::Runtime).await;
}

#[allow(clippy::too_many_lines)] // One owned race lifecycle: gate, inject loss, release, and prove reap.
async fn gated_stage_loss(failure: Failure, stage: u8) {
    let query_gate = stage == 1;
    let context_gate = stage == 0;
    let lease = super::tests::receiver_lease();
    let entered = Arc::new(Notify::new());
    let renewed = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let admissions = Arc::new(AtomicUsize::new(0));
    let authority = Arc::new(RaceAuthority {
        before_query_return: Mutex::new(None),
        begin_receives: Arc::new(AtomicUsize::new(0)),
        failure,
        lease: lease.clone(),
        query_gate,
        context_gate,
        ordinary_stage_gate: None,
        cancellation_queries: AtomicUsize::new(0),
        completion_calls: AtomicUsize::new(0),
        entered: Arc::clone(&entered),
        renewed: Arc::clone(&renewed),
        release: Arc::clone(&release),
    });
    let mut worker_owner = None;
    let mut channel = None;
    let alive = Arc::new(AtomicUsize::new(0));
    let adapter: Arc<dyn DurableRuntimeAdapter> = if matches!(failure, Failure::StarvedWorker) {
        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("race-worker"));
        let runtime = Arc::new(smesh_runtime::SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let (dispatcher, worker) = RuntimeWorker::spawn_with_config(
            runtime,
            "race-worker",
            UncooperativeProcessor {
                entered: Arc::clone(&entered),
                admissions: Arc::clone(&admissions),
                alive: Arc::clone(&alive),
            },
            RuntimeWorkerConfig {
                command_capacity: 1,
                max_active_tasks: 2,
                cancel_grace: Duration::from_millis(100),
            },
        )
        .await
        .unwrap();
        worker_owner = Some(worker);
        channel = Some(dispatcher.clone());
        Arc::new(dispatcher)
    } else {
        Arc::new(Arc::new(RaceAdapter {
            entered: Arc::clone(&entered),
            admissions: Arc::clone(&admissions),
        }))
    };
    let coordinator = Arc::new(DurableCoordinator::new(
        authority,
        DurableCoordinatorMode::Runtime(adapter),
        InjectedClock::new(1),
        None,
    ));
    let request = MeshRequest {
        protocol: "a2a-v1".into(),
        task_id: lease.task_id.clone(),
        context_id: "context-race".into(),
        text: "race".into(),
    };
    let outbox = OutboxLease {
        tenant_scope: lease.tenant_scope.clone(),
        outbox_id: 1,
        dispatch_id: lease.dispatch_id.clone(),
        task_id: lease.task_id.clone(),
        attempt_no: 1,
        max_attempts: 1,
        lease_owner: "owner".into(),
        lease_token: "sender".into(),
        lease_until: 10000,
        request: request.clone(),
        ratification_required: false,
        execution_reservation: None,
    };
    let envelope = DurableDispatchEnvelope {
        tenant_scope: lease.tenant_scope.clone(),
        dispatch_id: lease.dispatch_id.clone(),
        payload_digest: content_digest(&serde_json::to_vec(&request).unwrap()),
        request,
        execution_reservation: None,
    };
    let owner = CancellationToken::new();
    let correlation = DurableDispatchCorrelation::from_authority_parts(
        &lease.tenant_scope,
        &lease.dispatch_id,
        outbox.attempt_no,
        lease.lease_epoch,
    )
    .unwrap();
    let driver_owner = owner.clone();
    let running = Arc::clone(&coordinator);
    let mut task = tokio::spawn(async move {
        running
            .dispatch_once(&outbox, envelope, "generation", "replica", &owner)
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .expect("stage was not entered");
    let competing_permit = if let Some(channel) = &channel {
        let RuntimeAdapterPreparation::Ready(permit) = channel.prepare().await else {
            panic!("second prepared data slot unavailable");
        };
        Some(permit)
    } else {
        None
    };
    let token = coordinator
        .active
        .lock()
        .unwrap()
        .get(&correlation)
        .unwrap()
        .cancellation
        .clone();
    match failure {
        Failure::Owner => driver_owner.cancel(),
        Failure::Runtime => coordinator.signal_cancel(&correlation),
        Failure::DriverDrop => {
            task.abort();
            let _ = (&mut task).await;
        }
        _ => {
            // This is the real ReceiverRenewal::start timer and authority future.
            tokio::time::timeout(Duration::from_secs(25), renewed.notified())
                .await
                .expect("real renewal never ran");
        }
    }
    tokio::time::timeout(Duration::from_secs(7), token.cancelled())
        .await
        .expect("receiver loss did not supervise the in-flight stage");
    release.notify_one();
    if matches!(failure, Failure::DriverDrop) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !coordinator.active.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("forced driver shutdown discarded its cleanup owner");
    } else {
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("owned lifecycle was not reaped")
            .unwrap();
        assert!(matches!(
            result,
            Err(DurableDispatchError::FatalRenewal | DurableDispatchError::PostReceiveUnresolved)
        ));
    }
    assert_eq!(
        admissions.load(Ordering::SeqCst),
        usize::from(stage == 2),
        "stale query result admitted new execution"
    );
    assert!(
        coordinator.active.lock().unwrap().is_empty(),
        "correlation survived actual reap"
    );
    if let Some(worker) = worker_owner {
        assert_eq!(
            alive.load(Ordering::SeqCst),
            0,
            "coordinator discarded correlation before processor destruction"
        );
        worker.shutdown().await.unwrap();
    }
    drop(competing_permit);
}

#[tokio::test]
async fn real_renewal_stale_error_timeout_supervise_query_and_admission() {
    tokio::join!(
        gated_stage_loss(Failure::Stale, 1),
        gated_stage_loss(Failure::Error, 1),
        gated_stage_loss(Failure::Timeout, 1),
        gated_stage_loss(Failure::Stale, 2),
        gated_stage_loss(Failure::Error, 2),
        gated_stage_loss(Failure::Timeout, 2),
        gated_stage_loss(Failure::Stale, 0),
        gated_stage_loss(Failure::Error, 0),
        gated_stage_loss(Failure::Timeout, 0),
    );
}

#[tokio::test]
async fn owner_runtime_and_forced_driver_cancellation_retain_every_stage() {
    for failure in [Failure::Owner, Failure::Runtime, Failure::DriverDrop] {
        for stage in 0..3 {
            gated_stage_loss(failure, stage).await;
        }
    }
}

struct UncooperativeProcessor {
    entered: Arc<Notify>,
    admissions: Arc<AtomicUsize>,
    alive: Arc<AtomicUsize>,
}
struct LiveProcessor(Arc<AtomicUsize>);
impl Drop for LiveProcessor {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
#[async_trait]
impl RuntimeTaskProcessor for UncooperativeProcessor {
    async fn process(
        &self,
        _: RuntimeTask,
        _: CancellationToken,
        _: RuntimeEventSink,
    ) -> Result<(), DispatchError> {
        self.alive.fetch_add(1, Ordering::SeqCst);
        let _live = LiveProcessor(Arc::clone(&self.alive));
        self.admissions.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        std::future::pending().await
    }
}
#[tokio::test]
async fn real_receiver_loss_reaps_worker_with_prepared_data_slot_held() {
    gated_stage_loss(Failure::StarvedWorker, 2).await;
}
