//! Gateway-owned, joinable secure callback delivery worker.

#![allow(
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::single_match_else,
    clippy::too_many_lines
)]

use std::{fmt, panic::AssertUnwindSafe, sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::FutureExt as _;
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use crate::{
    CallbackAuthority, CallbackDeliveryCategory, CallbackDeliveryDisposition,
    CallbackDeliveryState, CallbackFailCommand, CallbackLease, DeliveryClaimCommand,
    DurableAuthority, LeaseDurationMillis, QuotaPolicy, QuotaSubject,
    push::{
        CallbackResponse, CallbackTransportError, DeliveryDisposition, PushEnrollment, PushPolicy,
        PushReadiness, SecureCallbackTransport,
    },
};

#[async_trait]
pub trait CallbackAttemptSender: Send + Sync {
    async fn send(
        &self,
        enrollment: &PushEnrollment,
        lease: &CallbackLease,
        database_timestamp_seconds: u64,
    ) -> Result<CallbackResponse, CallbackTransportError>;
}

pub struct SecureCallbackSender {
    transport: SecureCallbackTransport,
    max_response_bytes: usize,
}

impl SecureCallbackSender {
    #[must_use]
    pub const fn new(transport: SecureCallbackTransport, max_response_bytes: usize) -> Self {
        Self {
            transport,
            max_response_bytes,
        }
    }
}

#[async_trait]
impl CallbackAttemptSender for SecureCallbackSender {
    async fn send(
        &self,
        enrollment: &PushEnrollment,
        lease: &CallbackLease,
        database_timestamp_seconds: u64,
    ) -> Result<CallbackResponse, CallbackTransportError> {
        self.transport
            .send_enrollment(
                enrollment,
                lease.fence().event_id(),
                database_timestamp_seconds,
                u32::from(lease.attempt()),
                lease.payload(),
                self.max_response_bytes,
            )
            .await
    }
}

#[must_use]
pub fn callback_quota_semantic_id(event_id: &str, config_id: &str, attempt: u16) -> String {
    let digest = crate::content_digest(
        format!("callback-delivery/v1\0{event_id}\0{config_id}\0{attempt}").as_bytes(),
    );
    format!("callback-quota-{}", &digest[7..39])
}

/// Deterministic HTTP/1.1 request accounting policy: request line, every
/// application-controlled header including CRLF delimiters, content length,
/// and exact payload bytes. Transport-added framing is deliberately excluded.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn callback_request_accounted_bytes(
    target: &str,
    endpoint_id: &str,
    event_id: &str,
    timestamp: u64,
    attempt: u16,
    key_generation: &str,
    payload_bytes: usize,
) -> Option<u64> {
    let url = url::Url::parse(target).ok()?;
    let host = url.host_str()?;
    let authority = format!("{host}:{}", url.port_or_known_default()?);
    let path = url.path();
    let digest_value_len = "sha-256=::".len() + 44;
    let signature_len = "v1,hmac-sha256=".len() + 43;
    let mut total = format!("POST {path} HTTP/1.1\r\n").len();
    for (name, value_len) in [
        ("host", authority.len()),
        ("content-type", "application/a2a+json".len()),
        ("content-digest", digest_value_len),
        ("x-smesh-callback-version", 1),
        ("x-smesh-callback-event-id", event_id.len()),
        ("x-smesh-callback-endpoint-id", endpoint_id.len()),
        ("x-smesh-callback-timestamp", timestamp.to_string().len()),
        ("x-smesh-callback-attempt", attempt.to_string().len()),
        ("x-smesh-callback-key-generation", key_generation.len()),
        ("x-smesh-callback-signature", signature_len),
        ("idempotency-key", event_id.len()),
        ("content-length", payload_bytes.to_string().len()),
    ] {
        total = total.checked_add(name.len() + 2 + value_len + 2)?;
    }
    total = total.checked_add(2)?.checked_add(payload_bytes)?;
    u64::try_from(total).ok()
}

#[derive(Clone)]
pub struct ProductionCallbackQuotaAuthority {
    authority: Arc<dyn DurableAuthority>,
    policy: Arc<QuotaPolicy>,
}

impl ProductionCallbackQuotaAuthority {
    #[must_use]
    pub fn new(authority: Arc<dyn DurableAuthority>, policy: Arc<QuotaPolicy>) -> Self {
        Self { authority, policy }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackQuotaDecision {
    Reserved,
    Exhausted { retry_after_millis: u64 },
    Unavailable,
}

/// Durable `PublicEgress` accounting seam. Production implementations must bind
/// the stable event id and exact serialized bytes idempotently before network.
#[async_trait]
pub trait CallbackQuotaAuthority: Send + Sync {
    async fn reserve_public_egress(
        &self,
        lease: &CallbackLease,
        exact_bytes: u64,
        database_millis: i64,
    ) -> CallbackQuotaDecision;
}

#[async_trait]
impl CallbackQuotaAuthority for ProductionCallbackQuotaAuthority {
    async fn reserve_public_egress(
        &self,
        lease: &CallbackLease,
        exact_bytes: u64,
        database_millis: i64,
    ) -> CallbackQuotaDecision {
        let subject = match QuotaSubject::new(
            lease.fence().tenant_scope(),
            lease.owner_account_id(),
            lease.principal_scope(),
        ) {
            Ok(value) => value,
            Err(_) => return CallbackQuotaDecision::Unavailable,
        };
        let semantic_id = callback_quota_semantic_id(
            lease.fence().event_id(),
            lease.config_id(),
            lease.attempt(),
        );
        let intent = match self
            .policy
            .egress_intent(&subject, &semantic_id, exact_bytes, 1)
        {
            Ok(value) => value,
            Err(_) => return CallbackQuotaDecision::Unavailable,
        };
        match self
            .authority
            .charge_quota_egress(&intent, database_millis)
            .await
        {
            Ok(()) => CallbackQuotaDecision::Reserved,
            Err(error) if error.code == a2a::error_code::QUOTA_EXCEEDED => {
                CallbackQuotaDecision::Exhausted {
                    retry_after_millis: 1_000,
                }
            }
            Err(_) => CallbackQuotaDecision::Unavailable,
        }
    }
}

pub trait CallbackJitter: Send + Sync {
    fn sample(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct SystemCallbackJitter;
impl CallbackJitter for SystemCallbackJitter {
    fn sample(&self) -> u64 {
        rand::random()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CallbackWorkerError {
    #[error("callback worker configuration is invalid")]
    InvalidConfiguration,
    #[error("callback worker task failed")]
    Join,
    #[error("callback worker shutdown exceeded its deadline")]
    ShutdownTimeout,
    #[error("callback worker initial authority cycle timed out")]
    InitialCycleTimeout,
    #[error("callback authority remained unavailable")]
    AuthorityUnavailable,
}

pub struct CallbackWorkerHandle {
    stop: CancellationToken,
    tasks: Vec<Option<tokio::task::JoinHandle<Result<(), ()>>>>,
    readiness: Arc<PushReadiness>,
}

impl fmt::Debug for CallbackWorkerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallbackWorkerHandle")
            .field("task_count", &self.tasks.len())
            .finish_non_exhaustive()
    }
}

impl CallbackWorkerHandle {
    pub fn spawn(
        authority: Arc<dyn CallbackAuthority>,
        policy: Arc<PushPolicy>,
        sender: Arc<dyn CallbackAttemptSender>,
        quota: Arc<dyn CallbackQuotaAuthority>,
        jitter: Arc<dyn CallbackJitter>,
        owner_prefix: &str,
        readiness: Arc<PushReadiness>,
    ) -> Result<Self, CallbackWorkerError> {
        Self::spawn_with_telemetry(
            authority,
            policy,
            sender,
            quota,
            jitter,
            owner_prefix,
            readiness,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn spawn_with_telemetry(
        authority: Arc<dyn CallbackAuthority>,
        policy: Arc<PushPolicy>,
        sender: Arc<dyn CallbackAttemptSender>,
        quota: Arc<dyn CallbackQuotaAuthority>,
        jitter: Arc<dyn CallbackJitter>,
        owner_prefix: &str,
        readiness: Arc<PushReadiness>,
        telemetry: Option<crate::telemetry::TelemetryHandle>,
    ) -> Result<Self, CallbackWorkerError> {
        if !policy.enabled()
            || owner_prefix.is_empty()
            || owner_prefix.len() > 96
            || !owner_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(CallbackWorkerError::InvalidConfiguration);
        }
        if !readiness.configure_workers(policy.worker_count()) {
            return Err(CallbackWorkerError::InvalidConfiguration);
        }
        let stop = CancellationToken::new();
        let mut tasks = Vec::with_capacity(usize::from(policy.worker_count()));
        for index in 0..policy.worker_count() {
            let context = WorkerContext {
                authority: Arc::clone(&authority),
                policy: Arc::clone(&policy),
                sender: Arc::clone(&sender),
                quota: Arc::clone(&quota),
                jitter: Arc::clone(&jitter),
                owner: format!("{owner_prefix}-{index}"),
                stop: stop.clone(),
                readiness: Arc::clone(&readiness),
                telemetry: telemetry.clone(),
            };
            let worker_stop = stop.clone();
            let worker_readiness = Arc::clone(&readiness);
            let worker_telemetry = telemetry.clone();
            tasks.push(Some(tokio::spawn(async move {
                let outcome = AssertUnwindSafe(context.run()).catch_unwind().await;
                if outcome.is_err() {
                    worker_readiness.mark_fatal();
                    worker_state_telemetry(worker_telemetry.as_ref(), "failed", "worker_panic");
                    eprintln!("smesh.callback.worker_failed category=panic");
                    Err(())
                } else if !worker_stop.is_cancelled() {
                    worker_readiness.mark_fatal();
                    worker_state_telemetry(worker_telemetry.as_ref(), "failed", "unexpected_exit");
                    eprintln!("smesh.callback.worker_failed category=unexpected_exit");
                    Err(())
                } else {
                    worker_state_telemetry(worker_telemetry.as_ref(), "ok", "shutdown");
                    Ok(())
                }
            })));
        }
        Ok(Self {
            stop,
            tasks,
            readiness,
        })
    }

    #[must_use]
    pub fn readiness(&self) -> &Arc<PushReadiness> {
        &self.readiness
    }

    pub async fn wait_initial_cycle(&self, deadline: Duration) -> Result<(), CallbackWorkerError> {
        tokio::time::timeout(deadline, async {
            loop {
                if self.readiness.is_ready() {
                    return Ok(());
                }
                if self.readiness.is_fatal() {
                    return Err(CallbackWorkerError::AuthorityUnavailable);
                }
                if self
                    .tasks
                    .iter()
                    .flatten()
                    .any(tokio::task::JoinHandle::is_finished)
                {
                    self.readiness.mark_fatal();
                    return Err(CallbackWorkerError::Join);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| CallbackWorkerError::InitialCycleTimeout)?
    }

    pub async fn shutdown(mut self, deadline: Duration) -> Result<(), CallbackWorkerError> {
        self.stop.cancel();
        let expires = tokio::time::Instant::now() + deadline;
        let mut first_error = None;
        let mut timed_out = false;
        for task_slot in &mut self.tasks {
            let Some(task) = task_slot.as_mut() else {
                continue;
            };
            match tokio::time::timeout_at(expires, &mut *task).await {
                Ok(Ok(Ok(()))) => {
                    task_slot.take();
                }
                Ok(_) => {
                    task_slot.take();
                    if first_error.is_none() {
                        first_error = Some(CallbackWorkerError::Join);
                    }
                }
                Err(_) => {
                    timed_out = true;
                    break;
                }
            }
        }
        if timed_out {
            for task in self.tasks.iter().flatten() {
                task.abort();
            }
            for task_slot in &mut self.tasks {
                if let Some(mut task) = task_slot.take() {
                    let _ = (&mut task).await;
                }
            }
            eprintln!("smesh.callback.worker_shutdown outcome=timeout");
            return Err(CallbackWorkerError::ShutdownTimeout);
        }
        eprintln!(
            "smesh.callback.worker_shutdown outcome={}",
            if first_error.is_some() {
                "failed"
            } else {
                "joined"
            }
        );
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for CallbackWorkerHandle {
    fn drop(&mut self) {
        self.stop.cancel();
        for task in self.tasks.iter().flatten() {
            task.abort();
        }
        let tasks: Vec<_> = std::mem::take(&mut self.tasks)
            .into_iter()
            .flatten()
            .collect();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                for task in tasks {
                    let _ = task.await;
                }
            });
        } else if !tasks.is_empty() {
            std::thread::spawn(move || {
                if let Ok(runtime) = tokio::runtime::Builder::new_current_thread().build() {
                    runtime.block_on(async move {
                        for task in tasks {
                            let _ = task.await;
                        }
                    });
                }
            });
        }
    }
}

fn worker_state_telemetry(
    telemetry: Option<&crate::telemetry::TelemetryHandle>,
    outcome: &'static str,
    reason: &'static str,
) {
    let Some(telemetry) = telemetry else { return };
    let attributes = [
        crate::telemetry::Attribute::new(crate::telemetry::AttributeKey::Outcome, outcome),
        crate::telemetry::Attribute::new(crate::telemetry::AttributeKey::Reason, reason),
        crate::telemetry::Attribute::new(
            crate::telemetry::AttributeKey::Operation,
            "callback_worker",
        ),
        crate::telemetry::Attribute::new(crate::telemetry::AttributeKey::Worker, "callback"),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>();
    if let Ok(attributes) = attributes
        && let Ok(record) = crate::telemetry::TelemetryRecord::log(
            crate::telemetry::EventName::WorkerState,
            attributes,
        )
    {
        let _ = telemetry.try_emit(record);
    }
}

struct WorkerContext {
    authority: Arc<dyn CallbackAuthority>,
    policy: Arc<PushPolicy>,
    sender: Arc<dyn CallbackAttemptSender>,
    quota: Arc<dyn CallbackQuotaAuthority>,
    jitter: Arc<dyn CallbackJitter>,
    owner: String,
    stop: CancellationToken,
    readiness: Arc<PushReadiness>,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
}

impl WorkerContext {
    async fn run(self) {
        let lease_duration = match i64::try_from(self.policy.claim_lease_ms())
            .ok()
            .and_then(|value| LeaseDurationMillis::new(value).ok())
        {
            Some(value) => value,
            None => {
                self.readiness.mark_fatal();
                return;
            }
        };
        let claim =
            match DeliveryClaimCommand::new(&self.owner, lease_duration, self.policy.claim_batch())
            {
                Ok(value) => value,
                Err(_) => {
                    self.readiness.mark_fatal();
                    return;
                }
            };
        let mut consecutive_authority_errors = 0_u8;
        let mut completed_initial_cycle = false;
        loop {
            if self.stop.is_cancelled() {
                return;
            }
            match self
                .authority
                .claim_callback_deliveries(claim.clone())
                .await
            {
                Ok(leases) => {
                    consecutive_authority_errors = 0;
                    if !completed_initial_cycle {
                        completed_initial_cycle = true;
                        self.readiness.mark_worker_ready();
                        worker_state_telemetry(self.telemetry.as_ref(), "ok", "ready");
                    }
                    #[cfg(debug_assertions)]
                    if self.owner.ends_with("-0")
                        && std::env::var("SMESH_TEST_PUSH_WORKER_FATAL").as_deref() == Ok("1")
                    {
                        while !self.readiness.is_ready() {
                            tokio::select! {
                                () = self.stop.cancelled() => return,
                                () = tokio::task::yield_now() => {}
                            }
                        }
                        tokio::select! {
                            () = self.stop.cancelled() => return,
                            () = tokio::time::sleep(Duration::from_secs(2)) => {
                                panic!("injected callback worker panic after readiness");
                            }
                        }
                    }
                    if leases.is_empty() {
                        tokio::select! {
                            () = self.stop.cancelled() => return,
                            () = tokio::time::sleep(Duration::from_millis(100)) => {}
                        }
                    }
                    for lease in leases {
                        if self.stop.is_cancelled() {
                            return;
                        }
                        self.delivery_telemetry("callback_delivery_attempted", "claim");
                        self.process(lease, lease_duration).await;
                    }
                }
                Err(_) => {
                    consecutive_authority_errors = consecutive_authority_errors.saturating_add(1);
                    if consecutive_authority_errors >= 5 {
                        self.readiness.mark_fatal();
                        return;
                    }
                    tokio::select! {
                        () = self.stop.cancelled() => return,
                        () = tokio::time::sleep(Duration::from_millis(200)) => {}
                    }
                }
            }
        }
    }

    async fn process(&self, lease: CallbackLease, lease_duration: LeaseDurationMillis) {
        let enrollment = match self.policy.enrollment(
            lease.fence().tenant_scope(),
            lease.enrollment_id(),
            lease.canonical_url(),
        ) {
            Ok(value)
                if u64::from(lease.attempt()) <= u64::from(self.policy.max_attempts())
                    && lease.enrollment_generation() == self.policy.policy_revision() =>
            {
                value
            }
            _ => {
                let _ = self.authority.revoke_callback_delivery(lease.fence()).await;
                return;
            }
        };
        if enrollment.endpoint_id() != lease.enrollment_id() {
            let _ = self.authority.revoke_callback_delivery(lease.fence()).await;
            return;
        }
        if crate::content_digest(lease.payload()) != lease.payload_digest() {
            self.fail(
                &lease,
                CallbackDeliveryDisposition::Dead,
                CallbackDeliveryCategory::Payload,
                None,
            )
            .await;
            return;
        }
        // Renew first to obtain authoritative database time and fence config
        // deletion before quota accounting or any DNS/connect work.
        let renewed = self
            .authority
            .renew_callback_delivery(lease.fence(), lease_duration)
            .await;
        let Ok(Some(lease_until)) = renewed else {
            return;
        };
        let db_now_ms = lease_until.saturating_sub(lease_duration.get());
        if db_now_ms >= lease.expires_at() {
            self.fail(
                &lease,
                CallbackDeliveryDisposition::Dead,
                CallbackDeliveryCategory::Policy,
                None,
            )
            .await;
            return;
        }
        let timestamp = u64::try_from(db_now_ms.max(0) / 1_000).unwrap_or(0);
        let exact_bytes = match callback_request_accounted_bytes(
            lease.canonical_url(),
            lease.enrollment_id(),
            lease.fence().event_id(),
            timestamp,
            lease.attempt(),
            enrollment.key_generation(),
            lease.payload().len(),
        ) {
            Some(value) => value,
            None => {
                self.fail(
                    &lease,
                    CallbackDeliveryDisposition::Dead,
                    CallbackDeliveryCategory::Payload,
                    None,
                )
                .await;
                return;
            }
        };
        match self
            .quota
            .reserve_public_egress(&lease, exact_bytes, db_now_ms)
            .await
        {
            CallbackQuotaDecision::Reserved => {}
            CallbackQuotaDecision::Exhausted { retry_after_millis } => {
                self.retry_or_dead_at(
                    &lease,
                    CallbackDeliveryCategory::Policy,
                    Some(retry_after_millis),
                    db_now_ms,
                )
                .await;
                return;
            }
            CallbackQuotaDecision::Unavailable => {
                self.retry_or_dead_at(&lease, CallbackDeliveryCategory::Policy, None, db_now_ms)
                    .await;
                return;
            }
        }
        // Re-evaluate both immutable policy and the durable active fence after
        // quota accounting, immediately before the sender can perform DNS.
        let Ok(enrollment) = self.policy.enrollment(
            lease.fence().tenant_scope(),
            lease.enrollment_id(),
            lease.canonical_url(),
        ) else {
            let _ = self.authority.revoke_callback_delivery(lease.fence()).await;
            return;
        };
        if !matches!(
            self.authority
                .validate_callback_delivery_fence(lease.fence(), lease_duration)
                .await,
            Ok(true)
        ) {
            return;
        }
        let send = self.sender.send(enrollment, &lease, timestamp);
        tokio::pin!(send);
        let renew_every = Duration::from_millis(
            u64::try_from(lease_duration.get())
                .unwrap_or(1_000)
                .saturating_div(3)
                .max(1),
        );
        let outcome = loop {
            tokio::select! {
                result = &mut send => break Some(result),
                () = self.stop.cancelled() => break None,
                () = tokio::time::sleep(renew_every) => {
                    if !matches!(self.authority.renew_callback_delivery(lease.fence(), lease_duration).await, Ok(Some(_))) {
                        break None;
                    }
                }
            }
        };
        match outcome {
            Some(Ok(response)) if response.disposition() == DeliveryDisposition::Delivered => {
                callback_production_checkpoint("after_http_2xx_before_authority_commit");
                if matches!(
                    self.authority.commit_callback_delivery(lease.fence()).await,
                    Ok(true)
                ) {
                    self.delivery_telemetry("callback_delivered", "committed");
                }
            }
            Some(Ok(response)) if response.disposition() == DeliveryDisposition::Retry => {
                self.retry_or_dead(
                    &lease,
                    CallbackDeliveryCategory::Http,
                    response
                        .retry_after_seconds()
                        .map(|seconds| seconds.saturating_mul(1_000)),
                )
                .await;
            }
            Some(Ok(_)) => {
                self.fail(
                    &lease,
                    CallbackDeliveryDisposition::Dead,
                    CallbackDeliveryCategory::Http,
                    None,
                )
                .await;
            }
            Some(Err(error)) => {
                let (category, permanent) = transport_category(error);
                if permanent {
                    self.fail(&lease, CallbackDeliveryDisposition::Dead, category, None)
                        .await;
                } else {
                    self.retry_or_dead(&lease, category, None).await;
                }
            }
            None => {
                // Shutdown or renewal cancellation leaves the durable lease
                // fenced; another replica reclaims it after database expiry.
            }
        }
    }

    async fn retry_or_dead(
        &self,
        lease: &CallbackLease,
        category: CallbackDeliveryCategory,
        requested_delay: Option<u64>,
    ) {
        let Ok(db_now) = self.authority.callback_database_time().await else {
            return;
        };
        self.retry_or_dead_at(lease, category, requested_delay, db_now)
            .await;
    }

    async fn retry_or_dead_at(
        &self,
        lease: &CallbackLease,
        category: CallbackDeliveryCategory,
        requested_delay: Option<u64>,
        db_now: i64,
    ) {
        let retry = self.policy.retry_policy();
        let next_attempt = lease.attempt().saturating_add(1);
        if next_attempt > self.policy.max_attempts() {
            self.fail(lease, CallbackDeliveryDisposition::Dead, category, None)
                .await;
            return;
        }
        let delay = match retry.clamp_delay_ms(requested_delay, next_attempt, self.jitter.sample())
        {
            Some(delay) => delay,
            None => {
                self.fail(lease, CallbackDeliveryDisposition::Dead, category, None)
                    .await;
                return;
            }
        };
        let retry_at = db_now.saturating_add(i64::try_from(delay).unwrap_or(i64::MAX));
        if retry_at >= lease.expires_at() {
            self.fail(lease, CallbackDeliveryDisposition::Dead, category, None)
                .await;
            return;
        }
        self.fail(
            lease,
            CallbackDeliveryDisposition::Retry,
            category,
            Some(retry_at),
        )
        .await;
    }

    async fn fail(
        &self,
        lease: &CallbackLease,
        disposition: CallbackDeliveryDisposition,
        category: CallbackDeliveryCategory,
        retry_at: Option<i64>,
    ) {
        let digest = failure_digest(category);
        if let Ok(command) = CallbackFailCommand::new(
            lease.fence().clone(),
            disposition,
            category,
            digest,
            retry_at,
        ) {
            let state: Result<CallbackDeliveryState, _> =
                self.authority.fail_callback_delivery(command).await;
            if state.is_ok() {
                self.delivery_telemetry(
                    if matches!(disposition, CallbackDeliveryDisposition::Retry) {
                        "callback_retry_scheduled"
                    } else {
                        "callback_dead"
                    },
                    if matches!(disposition, CallbackDeliveryDisposition::Retry) {
                        "unavailable"
                    } else {
                        "permanent"
                    },
                );
            }
        }
    }

    fn delivery_telemetry(&self, operation: &'static str, reason: &'static str) {
        let Some(telemetry) = &self.telemetry else {
            return;
        };
        telemetry.durable_event(
            crate::telemetry::EventName::PushDelivery,
            "ok",
            reason,
            operation,
            None,
            None,
            None,
        );
        let attributes = [
            crate::telemetry::Attribute::new(crate::telemetry::AttributeKey::Outcome, "ok"),
            crate::telemetry::Attribute::new(crate::telemetry::AttributeKey::Operation, operation),
            crate::telemetry::Attribute::new(crate::telemetry::AttributeKey::Reason, reason),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>();
        if let Ok(attributes) = attributes
            && let Ok(point) = crate::telemetry::MetricPoint::new(
                crate::telemetry::MetricName::PushDelivery,
                1,
                attributes,
            )
        {
            let _ = telemetry.try_emit(crate::telemetry::TelemetryRecord::metric(point));
        }
    }
}

/// Debug-only process crash cut after an externally accepted effect and before
/// the durable delivery fence commits. Release builds contain only a no-op.
fn callback_production_checkpoint(checkpoint: &str) {
    #[cfg(debug_assertions)]
    {
        use std::io::{BufRead as _, Write as _};
        if std::env::var("SMESH_TEST_PUSH_CHECKPOINT").as_deref() != Ok(checkpoint) {
            return;
        }
        println!("SMESH_PUSH_CHECKPOINT READY {checkpoint}");
        std::io::stdout().flush().expect("push checkpoint flush");
        let mut release = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut release)
            .expect("push checkpoint GO read");
        assert_eq!(release.trim_end(), format!("GO {checkpoint}"));
    }
    #[cfg(not(debug_assertions))]
    let _ = checkpoint;
}

fn transport_category(error: CallbackTransportError) -> (CallbackDeliveryCategory, bool) {
    match error {
        CallbackTransportError::DnsUnsafe => (CallbackDeliveryCategory::Dns, true),
        CallbackTransportError::DnsUnavailable => (CallbackDeliveryCategory::Dns, false),
        CallbackTransportError::Tls => (CallbackDeliveryCategory::Tls, true),
        CallbackTransportError::Configuration => (CallbackDeliveryCategory::Policy, true),
        CallbackTransportError::Timeout => (CallbackDeliveryCategory::Timeout, false),
        CallbackTransportError::Connect | CallbackTransportError::Reset => {
            (CallbackDeliveryCategory::Transport, false)
        }
        CallbackTransportError::ResponseTooLarge => (CallbackDeliveryCategory::Http, true),
    }
}

fn failure_digest(category: CallbackDeliveryCategory) -> String {
    let label = match category {
        CallbackDeliveryCategory::Transport => "transport",
        CallbackDeliveryCategory::Dns => "dns",
        CallbackDeliveryCategory::Tls => "tls",
        CallbackDeliveryCategory::Timeout => "timeout",
        CallbackDeliveryCategory::Http => "http",
        CallbackDeliveryCategory::Policy => "policy",
        CallbackDeliveryCategory::Payload => "payload",
    };
    let digest = Sha256::digest(format!("smesh-callback-failure/v1:{label}").as_bytes());
    format!("sha256:{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ScriptedAuthority {
        calls: [AtomicUsize; 3],
        first_cycles: AtomicUsize,
        active_claims: AtomicUsize,
    }

    struct ActiveClaim<'a>(&'a AtomicUsize);
    impl Drop for ActiveClaim<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl ScriptedAuthority {
        fn unavailable<T>() -> Result<T, a2a::A2AError> {
            Err(a2a::A2AError::internal("scripted callback authority"))
        }
    }

    #[async_trait]
    impl CallbackAuthority for ScriptedAuthority {
        fn callback_capabilities(&self) -> crate::CallbackCapabilities {
            crate::CallbackCapabilities::sqlite_conformance()
        }
        fn callback_readiness(&self) -> crate::CallbackReadiness {
            crate::CallbackReadiness::Ready
        }
        fn callback_policy_snapshot(&self) -> Option<Arc<crate::CallbackPolicySnapshot>> {
            None
        }
        async fn callback_database_time(&self) -> Result<i64, a2a::A2AError> {
            Self::unavailable()
        }
        async fn resolve_callback_enrollment(
            &self,
            _: &crate::OwnedTaskScope,
            _: &str,
        ) -> Result<Option<crate::CallbackEnrollmentBinding>, a2a::A2AError> {
            Self::unavailable()
        }
        async fn create_callback_config(
            &self,
            _: crate::ConfigCreateCommand,
        ) -> Result<crate::CallbackConfig, a2a::A2AError> {
            Self::unavailable()
        }
        async fn get_callback_config(
            &self,
            _: crate::ConfigGetCommand,
        ) -> Result<Option<crate::CallbackConfig>, a2a::A2AError> {
            Self::unavailable()
        }
        async fn list_callback_configs(
            &self,
            _: crate::ConfigListCommand,
        ) -> Result<crate::CallbackConfigPage, a2a::A2AError> {
            Self::unavailable()
        }
        async fn delete_callback_config(
            &self,
            _: crate::ConfigDeleteCommand,
        ) -> Result<crate::CallbackDeleteOutcome, a2a::A2AError> {
            Self::unavailable()
        }
        async fn claim_callback_deliveries(
            &self,
            command: DeliveryClaimCommand,
        ) -> Result<Vec<CallbackLease>, a2a::A2AError> {
            let index = command
                .owner()
                .rsplit('-')
                .next()
                .and_then(|value| value.parse::<usize>().ok())
                .expect("worker index");
            let call = self.calls[index].fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                self.first_cycles.fetch_add(1, Ordering::SeqCst);
                return Ok(Vec::new());
            }
            self.active_claims.fetch_add(1, Ordering::SeqCst);
            let _active = ActiveClaim(&self.active_claims);
            if index == 0 {
                while self.first_cycles.load(Ordering::SeqCst) != 3 {
                    tokio::task::yield_now().await;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                panic!("scripted callback worker panic");
            }
            futures::future::pending().await
        }
        async fn renew_callback_delivery(
            &self,
            _: &crate::DeliveryFence,
            _: LeaseDurationMillis,
        ) -> Result<Option<i64>, a2a::A2AError> {
            Self::unavailable()
        }
        async fn commit_callback_delivery(
            &self,
            _: &crate::DeliveryFence,
        ) -> Result<bool, a2a::A2AError> {
            Self::unavailable()
        }
        async fn fail_callback_delivery(
            &self,
            _: CallbackFailCommand,
        ) -> Result<CallbackDeliveryState, a2a::A2AError> {
            Self::unavailable()
        }
        async fn revoke_callback_delivery(
            &self,
            _: &crate::DeliveryFence,
        ) -> Result<CallbackDeliveryState, a2a::A2AError> {
            Self::unavailable()
        }
    }

    struct UnusedSender;
    #[async_trait]
    impl CallbackAttemptSender for UnusedSender {
        async fn send(
            &self,
            _: &PushEnrollment,
            _: &CallbackLease,
            _: u64,
        ) -> Result<CallbackResponse, CallbackTransportError> {
            panic!("no scripted deliveries")
        }
    }
    struct UnusedQuota;
    #[async_trait]
    impl CallbackQuotaAuthority for UnusedQuota {
        async fn reserve_public_egress(
            &self,
            _: &CallbackLease,
            _: u64,
            _: i64,
        ) -> CallbackQuotaDecision {
            panic!("no scripted deliveries")
        }
    }

    fn three_worker_policy() -> PushPolicy {
        PushPolicy::parse_bytes(
            br#"
schema = "smesh-push/1"
enabled = true
policy_id = "worker-supervision"
policy_revision = 1
policy_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
max_pending = 10
max_configs_per_task = 2
max_configs_per_tenant = 10
worker_count = 3
claim_batch = 1
claim_lease_ms = 1000
dns_timeout_ms = 100
max_dns_answers = 2
connect_timeout_ms = 100
request_timeout_ms = 100
max_response_bytes = 1024
max_attempts = 2
base_retry_ms = 10
max_retry_ms = 20
max_delivery_age_ms = 1000
[[enrollments]]
tenant = "tenant-a"
endpoint_id = "endpoint"
url = "https://example.com:443/events"
event = "terminal"
auth = "hmac-sha256"
key_generation = "one"
secret_file = "/not/read/by-parse"
"#,
        )
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn panic_after_all_workers_ready_is_fatal_and_timeout_reaps_every_task() {
        let authority = Arc::new(ScriptedAuthority {
            calls: std::array::from_fn(|_| AtomicUsize::new(0)),
            first_cycles: AtomicUsize::new(0),
            active_claims: AtomicUsize::new(0),
        });
        let readiness = Arc::new(PushReadiness::new());
        let (telemetry, records) =
            crate::telemetry::TelemetryHandle::multisignal_capture_for_test(32, 0.0);
        let authority_trait: Arc<dyn CallbackAuthority> = authority.clone();
        let worker = CallbackWorkerHandle::spawn_with_telemetry(
            authority_trait,
            Arc::new(three_worker_policy()),
            Arc::new(UnusedSender),
            Arc::new(UnusedQuota),
            Arc::new(SystemCallbackJitter),
            "supervised",
            Arc::clone(&readiness),
            Some(telemetry),
        )
        .unwrap();
        worker
            .wait_initial_cycle(Duration::from_secs(1))
            .await
            .unwrap();
        assert!(readiness.is_ready());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !readiness.is_fatal() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            worker.shutdown(Duration::from_millis(50)).await,
            Err(CallbackWorkerError::ShutdownTimeout)
        ));
        assert_eq!(authority.active_claims.load(Ordering::SeqCst), 0);
        let captured: Vec<_> = records.try_iter().collect();
        assert!(captured.iter().any(|record| {
            record.name() == crate::telemetry::EventName::WorkerState.as_str()
                && record
                    .attributes()
                    .iter()
                    .any(|attribute| attribute.value() == "worker_panic")
        }));
    }
}
