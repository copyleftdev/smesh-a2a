use std::collections::HashSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use a2a::{
    AgentCard, CancelTaskRequest, GetTaskRequest, Message, Part, Role, SendMessageRequest,
    SendMessageResponse, StreamResponse, SubscribeToTaskRequest, TRANSPORT_PROTOCOL_HTTP_JSON,
    TRANSPORT_PROTOCOL_JSONRPC, Task, TaskState,
};
use a2a_client::agent_card::AgentCardResolver;
use a2a_client::jsonrpc::JsonRpcTransportFactory;
use a2a_client::rest::RestTransportFactory;
use a2a_client::{A2AClient, A2AClientFactory, Transport};
use futures::StreamExt as _;
use futures::future::join_all;

use crate::lifeline_failure::verify_lifeline_failure_events;
use crate::{
    LifelineFailureEvent, LifelineFailureEventKind, LifelineFailureTrace,
    LifelineFailureTransition, LifelineTeamFailureMode,
};

pub const LIFELINE_DIRECTOR_SCHEMA_VERSION: &str = "1.0.0";
const LIFELINE_DIRECTOR_EVIDENCE_DISCLAIMER: &str = "Fictional loopback evidence only; not authorization, medical advice, clinical validation, or evidence of trust.";
const APPROVED_DIRECTOR_MANIFEST: &str = include_str!("../deploy/lifeline-director.json");

#[derive(Debug, Error)]
pub enum LifelineDirectorError {
    #[error("director manifest JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("director manifest invariant failed: {0}")]
    Invariant(String),
    #[error("director gateway {gateway_id} discovery failed")]
    Discovery { gateway_id: String },
    #[error("director operation {operation_id} failed")]
    Operation { operation_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineDirectorManifest {
    schema_version: String,
    fictional: bool,
    run_id: String,
    root_context_id: String,
    gateways: Vec<LifelineDirectorGateway>,
    operations: Vec<LifelineDirectorOperation>,
    review: LifelineDirectorReview,
    logistics: LifelineDirectorLogistics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineDirectorGateway {
    id: String,
    discovery_url: String,
    expected_organization: String,
    expected_skill_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineDirectorOperation {
    id: String,
    gateway_id: String,
    path: LifelineDirectorPath,
    prompt: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifelineDirectorPath {
    SyncJsonrpc,
    SyncRest,
    StreamReconnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineDirectorReview {
    gateway_id: String,
    path: LifelineDirectorPath,
    prompt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineDirectorLogistics {
    primary_gateway_id: String,
    fallback_gateway_id: String,
}

pub struct LifelineResponseDirector {
    manifest: LifelineDirectorManifest,
}

#[derive(Debug, Clone)]
pub struct ResolvedLifelineGateway {
    gateway_id: String,
    discovery_url: String,
    card: AgentCard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineDirectorRun {
    schema_version: String,
    fictional: bool,
    disclaimer: String,
    run_id: String,
    root_context_id: String,
    discovered_gateways: Vec<LifelineDirectorDiscoveryReceipt>,
    discovery_failures: Vec<LifelineDirectorDiscoveryFailure>,
    initial_operations: Vec<LifelineDirectorOperationReceipt>,
    fallback_operation: Option<LifelineDirectorOperationReceipt>,
    review: Option<LifelineDirectorOperationReceipt>,
    captured_message_ids: Vec<String>,
    captured_task_ids: Vec<String>,
    captured_artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineFailureScenarioRun {
    schema_version: String,
    root_context_id: String,
    primary_task_id: String,
    fallback_task_id: String,
    fallback_context_id: String,
    fallback_replaces_task_id: String,
    primary_final_state: String,
    primary_attempts: usize,
    fallback_attempts: usize,
    sibling_dispatches: usize,
    root_context_restarts: usize,
    director_run: LifelineDirectorRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LifelineDirectorDiscoveryReceipt {
    gateway_id: String,
    discovery_url: String,
    provider_organization: String,
    skill_ids: Vec<String>,
    interfaces: Vec<LifelineDirectorInterfaceReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LifelineDirectorInterfaceReceipt {
    url: String,
    protocol_binding: String,
    protocol_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LifelineDirectorDiscoveryFailure {
    gateway_id: String,
    outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineDirectorOperationReceipt {
    operation_id: String,
    gateway_id: String,
    binding: String,
    message_id: String,
    observed_message_ids: Vec<String>,
    observed_task_ids: Vec<String>,
    task_id: String,
    context_id: String,
    terminal_state: TaskState,
    artifact_ids: Vec<String>,
    observations: Vec<LifelineDirectorObservation>,
    replaces_task_id: Option<String>,
    reference_task_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum LifelineDirectorObservation {
    Streaming,
    GetTask,
    Subscribe,
    Cancel,
}

type OfficialA2AClient = A2AClient<Box<dyn Transport>>;

impl LifelineDirectorManifest {
    /// Parses and validates the closed local Response Director manifest.
    ///
    /// # Errors
    /// Returns an error when the JSON or a manifest invariant is invalid.
    pub fn from_json(input: &str) -> Result<Self, LifelineDirectorError> {
        if input.len() > 64 * 1024 {
            return Err(invariant("manifest exceeds 64 KiB"));
        }
        let manifest: Self = serde_json::from_str(input)?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), LifelineDirectorError> {
        require(
            self.schema_version == LIFELINE_DIRECTOR_SCHEMA_VERSION,
            "unsupported schemaVersion",
        )?;
        require(self.fictional, "director run must be explicitly fictional")?;
        require_identifier(&self.run_id, "run id")?;
        require_identifier(&self.root_context_id, "root context id")?;
        require(
            self.gateways.len() == 6,
            "exactly six discovery gateways are required",
        )?;
        require(
            self.operations.len() == 4,
            "exactly four concurrent operations are required",
        )?;

        let mut gateway_ids = HashSet::new();
        for gateway in &self.gateways {
            require_identifier(&gateway.id, "gateway id")?;
            require(
                gateway_ids.insert(gateway.id.as_str()),
                "gateway ids must be unique",
            )?;
            validate_discovery_url(&gateway.discovery_url)?;
            require_text(&gateway.expected_organization, 128, "expected organization")?;
            require_identifier(&gateway.expected_skill_id, "expected skill id")?;
        }

        let mut operation_ids = HashSet::new();
        for operation in &self.operations {
            require_identifier(&operation.id, "operation id")?;
            require(
                operation_ids.insert(operation.id.as_str()),
                "operation ids must be unique",
            )?;
            require(
                gateway_ids.contains(operation.gateway_id.as_str()),
                "operation gateway does not exist",
            )?;
            require_text(&operation.prompt, 512, "operation prompt")?;
        }
        require(
            gateway_ids.contains(self.review.gateway_id.as_str()),
            "review gateway does not exist",
        )?;
        require(
            self.review.path == LifelineDirectorPath::SyncJsonrpc,
            "review must use sync-jsonrpc",
        )?;
        require_text(&self.review.prompt, 512, "review prompt")?;
        require(
            gateway_ids.contains(self.logistics.primary_gateway_id.as_str()),
            "primary logistics gateway does not exist",
        )?;
        require(
            gateway_ids.contains(self.logistics.fallback_gateway_id.as_str()),
            "fallback logistics gateway does not exist",
        )?;
        require(
            self.logistics.primary_gateway_id != self.logistics.fallback_gateway_id,
            "logistics gateways must differ",
        )?;
        self.validate_approved_run_plan()?;
        Ok(())
    }

    fn validate_approved_run_plan(&self) -> Result<(), LifelineDirectorError> {
        let approved: Self = serde_json::from_str(APPROVED_DIRECTOR_MANIFEST)
            .map_err(|_| invariant("built-in director manifest is invalid"))?;
        let mut candidate = self.clone();
        for (candidate_gateway, approved_gateway) in
            candidate.gateways.iter_mut().zip(&approved.gateways)
        {
            let candidate_url = Url::parse(&candidate_gateway.discovery_url)
                .map_err(|_| invariant("discovery URL is invalid"))?;
            let approved_url = Url::parse(&approved_gateway.discovery_url)
                .map_err(|_| invariant("built-in discovery URL is invalid"))?;
            require(
                candidate_url.scheme() == approved_url.scheme()
                    && candidate_url.host_str() == approved_url.host_str()
                    && candidate_url.path() == approved_url.path()
                    && candidate_url.username() == approved_url.username()
                    && candidate_url.password() == approved_url.password()
                    && candidate_url.query() == approved_url.query()
                    && candidate_url.fragment() == approved_url.fragment(),
                "only discovery URL loopback ports may vary",
            )?;
            candidate_gateway
                .discovery_url
                .clone_from(&approved_gateway.discovery_url);
        }
        require(
            candidate == approved,
            "director manifest must match the reviewed LIFELINE run plan",
        )
    }

    #[must_use]
    pub fn is_fictional(&self) -> bool {
        self.fictional
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub fn root_context_id(&self) -> &str {
        &self.root_context_id
    }

    #[must_use]
    pub fn gateways(&self) -> &[LifelineDirectorGateway] {
        &self.gateways
    }

    #[must_use]
    pub fn operations(&self) -> &[LifelineDirectorOperation] {
        &self.operations
    }

    #[must_use]
    pub fn review(&self) -> &LifelineDirectorReview {
        &self.review
    }

    #[must_use]
    pub fn logistics(&self) -> &LifelineDirectorLogistics {
        &self.logistics
    }
}

impl LifelineResponseDirector {
    #[must_use]
    pub fn new(manifest: LifelineDirectorManifest) -> Self {
        Self { manifest }
    }

    /// Resolves every declared gateway through the official A2A card resolver
    /// and validates the selected public interface contract.
    ///
    /// # Errors
    /// Returns an error when resolution times out, fails, or the public card
    /// does not match the reviewed gateway contract.
    pub async fn resolve_gateways(
        &self,
    ) -> Result<Vec<ResolvedLifelineGateway>, LifelineDirectorError> {
        let mut gateways = Vec::with_capacity(self.manifest.gateways.len());
        for gateway in &self.manifest.gateways {
            gateways.push(self.resolve_gateway(gateway).await?);
        }
        Ok(gateways)
    }

    async fn resolve_gateway(
        &self,
        gateway: &LifelineDirectorGateway,
    ) -> Result<ResolvedLifelineGateway, LifelineDirectorError> {
        let resolver = AgentCardResolver::new(Some(director_http_client()?));
        let card = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            resolver.resolve(&gateway.discovery_url),
        )
        .await
        .map_err(|_| LifelineDirectorError::Discovery {
            gateway_id: gateway.id.clone(),
        })?
        .map_err(|_| LifelineDirectorError::Discovery {
            gateway_id: gateway.id.clone(),
        })?;
        validate_resolved_card(gateway, &card)?;
        Ok(ResolvedLifelineGateway {
            gateway_id: gateway.id.clone(),
            discovery_url: gateway.discovery_url.clone(),
            card,
        })
    }

    async fn resolve_gateways_for_run(
        &self,
    ) -> Result<
        (
            Vec<ResolvedLifelineGateway>,
            Vec<LifelineDirectorDiscoveryFailure>,
        ),
        LifelineDirectorError,
    > {
        let mut gateways = Vec::with_capacity(self.manifest.gateways.len());
        let mut failures = Vec::new();
        for gateway in &self.manifest.gateways {
            match self.resolve_gateway(gateway).await {
                Ok(resolved) => gateways.push(resolved),
                Err(LifelineDirectorError::Discovery { .. })
                    if gateway.id == self.manifest.logistics.primary_gateway_id =>
                {
                    failures.push(LifelineDirectorDiscoveryFailure {
                        gateway_id: gateway.id.clone(),
                        outcome: "unavailable-before-commission".to_owned(),
                    });
                }
                Err(error) => return Err(error),
            }
        }
        Ok((gateways, failures))
    }

    /// Resolves public Agent Cards and commissions the four initial children.
    ///
    /// # Errors
    /// Returns an error when discovery, client creation, transport, or response
    /// validation fails.
    pub async fn run(&self) -> Result<LifelineDirectorRun, LifelineDirectorError> {
        let (resolved, discovery_failures) = self.resolve_gateways_for_run().await?;
        let root_context_id = self.manifest.root_context_id.clone();
        let futures = self.manifest.operations.iter().filter_map(|operation| {
            let gateway = resolved
                .iter()
                .find(|gateway| gateway.gateway_id == operation.gateway_id)
                .cloned();
            gateway.map(|gateway| {
                execute_initial_operation(
                    operation.clone(),
                    Some(gateway),
                    root_context_id.clone(),
                    Vec::new(),
                )
            })
        });
        let initial_operations = join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        assemble_director_run(
            &self.manifest,
            &resolved,
            discovery_failures,
            root_context_id,
            initial_operations,
        )
        .await
    }

    /// Runs the closed Atlas-primary outage, cancellation, and single fallback scenario.
    ///
    /// # Errors
    /// Returns an error when discovery, an official A2A operation, live trace capture,
    /// cancellation reconciliation, fallback, or final primary reconciliation fails.
    #[allow(clippy::too_many_lines)] // The linear orchestration order is the audited scenario contract.
    pub async fn run_failure_scenario(
        &self,
        failure: LifelineTeamFailureMode,
    ) -> Result<LifelineFailureScenarioRun, LifelineDirectorError> {
        let trace = failure.trace();
        let resolved = self.resolve_gateways().await?;
        let root = self.manifest.root_context_id.clone();
        let primary_operation = self
            .manifest
            .operations
            .iter()
            .find(|operation| operation.gateway_id == self.manifest.logistics.primary_gateway_id)
            .cloned()
            .ok_or_else(|| invariant("primary logistics operation is missing"))?;
        let primary_gateway = resolved
            .iter()
            .find(|gateway| gateway.gateway_id == primary_operation.gateway_id)
            .cloned()
            .ok_or_else(|| invariant("primary logistics gateway is missing"))?;
        let primary_future = execute_failure_primary(
            primary_operation,
            primary_gateway.clone(),
            root.clone(),
            failure,
            trace.clone(),
        );
        let sibling_futures = self
            .manifest
            .operations
            .iter()
            .filter(|operation| operation.gateway_id != self.manifest.logistics.primary_gateway_id)
            .map(|operation| {
                let operation = operation.clone();
                let gateway = resolved
                    .iter()
                    .find(|gateway| gateway.gateway_id == operation.gateway_id)
                    .cloned();
                let root = root.clone();
                let trace = trace.clone();
                async move {
                    trace
                        .record(LifelineFailureTransition {
                            kind: LifelineFailureEventKind::SiblingSubmitted,
                            operation_id: &operation.id,
                            gateway_id: &operation.gateway_id,
                            context_id: &root,
                            task_id: None,
                            message_id: None,
                            attempt: 1,
                            outcome: "submitted",
                            replaces_task_id: None,
                        })
                        .map_err(|_| LifelineDirectorError::Operation {
                            operation_id: operation.id.clone(),
                        })?;
                    let receipt =
                        execute_initial_operation(operation, gateway, root, Vec::new()).await?;
                    record_receipt_transition(
                        &trace,
                        LifelineFailureEventKind::SiblingCompleted,
                        &receipt,
                        "completed",
                        None,
                    )?;
                    Ok::<LifelineDirectorOperationReceipt, LifelineDirectorError>(receipt)
                }
            });
        let sibling_future = join_all(sibling_futures);
        let (primary, siblings) = tokio::join!(primary_future, sibling_future);
        let primary = primary?;
        let siblings = siblings.into_iter().collect::<Result<Vec<_>, _>>()?;
        if !primary.is_canceled() || siblings.iter().any(|receipt| !receipt.is_completed()) {
            return Err(LifelineDirectorError::Operation {
                operation_id: primary.operation_id.clone(),
            });
        }

        trace
            .record(LifelineFailureTransition {
                kind: LifelineFailureEventKind::FallbackSelected,
                operation_id: "shipment-routing-fallback",
                gateway_id: &self.manifest.logistics.fallback_gateway_id,
                context_id: &root,
                task_id: None,
                message_id: None,
                attempt: 1,
                outcome: "selected",
                replaces_task_id: Some(&primary.task_id),
            })
            .map_err(|_| LifelineDirectorError::Operation {
                operation_id: "shipment-routing-fallback".to_owned(),
            })?;
        let fallback_gateway = resolved
            .iter()
            .find(|gateway| gateway.gateway_id == self.manifest.logistics.fallback_gateway_id)
            .cloned()
            .ok_or_else(|| invariant("fallback logistics gateway is missing"))?;
        let fallback = execute_failure_fallback(
            fallback_gateway,
            root.clone(),
            primary.task_id.clone(),
            trace.clone(),
        )
        .await?;

        let mut initial_operations = siblings;
        initial_operations.push(primary.clone());
        initial_operations.sort_by_key(|receipt| {
            self.manifest
                .operations
                .iter()
                .position(|operation| operation.id == receipt.operation_id)
                .unwrap_or(usize::MAX)
        });
        let review_reference_task_ids = initial_operations
            .iter()
            .chain(std::iter::once(&fallback))
            .map(|receipt| receipt.task_id.clone())
            .collect::<Vec<_>>();
        let review_operation = LifelineDirectorOperation {
            id: "independent-review".to_owned(),
            gateway_id: self.manifest.review.gateway_id.clone(),
            path: self.manifest.review.path,
            prompt: review_prompt(&self.manifest, &initial_operations, Some(&fallback)),
        };
        let review = execute_initial_operation(
            review_operation,
            resolved
                .iter()
                .find(|gateway| gateway.gateway_id == self.manifest.review.gateway_id)
                .cloned(),
            root.clone(),
            review_reference_task_ids,
        )
        .await?;
        record_receipt_transition(
            &trace,
            LifelineFailureEventKind::ReviewCompleted,
            &review,
            "completed",
            None,
        )?;

        let final_primary = get_failure_primary(&primary_gateway, &primary.task_id, &root).await?;
        if final_primary.status.state != TaskState::Canceled
            || final_primary
                .artifacts
                .as_ref()
                .is_some_and(|artifacts| !artifacts.is_empty())
        {
            return Err(LifelineDirectorError::Operation {
                operation_id: primary.operation_id.clone(),
            });
        }
        trace
            .record(LifelineFailureTransition {
                kind: LifelineFailureEventKind::PrimaryFinalReconciled,
                operation_id: &primary.operation_id,
                gateway_id: &primary.gateway_id,
                context_id: &primary.context_id,
                task_id: Some(&primary.task_id),
                message_id: Some(&primary.message_id),
                attempt: 1,
                outcome: "canceled",
                replaces_task_id: None,
            })
            .map_err(|_| LifelineDirectorError::Operation {
                operation_id: primary.operation_id.clone(),
            })?;
        trace.sync().map_err(|_| LifelineDirectorError::Operation {
            operation_id: primary.operation_id.clone(),
        })?;

        let director_run = build_run_record(
            &self.manifest,
            &resolved,
            Vec::new(),
            root.clone(),
            initial_operations,
            Some(fallback.clone()),
            Some(review),
        );
        let all_contexts = director_run
            .initial_operations
            .iter()
            .chain(director_run.fallback_operation.iter())
            .chain(director_run.review.iter())
            .map(|receipt| receipt.context_id.as_str())
            .collect::<HashSet<_>>();
        let run = LifelineFailureScenarioRun {
            schema_version: "lifeline-failure-scenario-run/1".to_owned(),
            root_context_id: root,
            primary_task_id: primary.task_id.clone(),
            fallback_task_id: fallback.task_id.clone(),
            fallback_context_id: fallback.context_id.clone(),
            fallback_replaces_task_id: fallback
                .replaces_task_id
                .clone()
                .ok_or_else(|| invariant("fallback replacement is missing"))?,
            primary_final_state: "canceled".to_owned(),
            primary_attempts: director_run
                .initial_operations
                .iter()
                .filter(|receipt| receipt.gateway_id == self.manifest.logistics.primary_gateway_id)
                .count(),
            fallback_attempts: usize::from(director_run.fallback_operation.is_some()),
            sibling_dispatches: director_run
                .initial_operations
                .iter()
                .filter(|receipt| receipt.gateway_id != self.manifest.logistics.primary_gateway_id)
                .count(),
            root_context_restarts: all_contexts.len().saturating_sub(1),
            director_run,
        };
        trace
            .record(LifelineFailureTransition {
                kind: LifelineFailureEventKind::ScenarioCompleted,
                operation_id: "incident-response",
                gateway_id: "director",
                context_id: &run.root_context_id,
                task_id: None,
                message_id: None,
                attempt: 1,
                outcome: "completed",
                replaces_task_id: None,
            })
            .map_err(|_| invariant("scenario completion evidence could not be recorded"))?;
        trace
            .sync()
            .map_err(|_| invariant("scenario completion evidence could not be synchronized"))?;
        Ok(run)
    }
}

struct FailurePrimaryOwner {
    failure: LifelineTeamFailureMode,
    armed: bool,
}

impl FailurePrimaryOwner {
    fn new(failure: LifelineTeamFailureMode) -> Self {
        Self {
            failure,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FailurePrimaryOwner {
    fn drop(&mut self) {
        if self.armed {
            self.failure.abandon_primary();
        }
    }
}

#[allow(clippy::too_many_lines)] // Keep stream outage and cancel linearization visibly contiguous.
async fn execute_failure_primary(
    operation: LifelineDirectorOperation,
    gateway: ResolvedLifelineGateway,
    root_context_id: String,
    failure: LifelineTeamFailureMode,
    trace: LifelineFailureTrace,
) -> Result<LifelineDirectorOperationReceipt, LifelineDirectorError> {
    let error = || LifelineDirectorError::Operation {
        operation_id: operation.id.clone(),
    };
    let stage_error = |stage: &str| LifelineDirectorError::Operation {
        operation_id: format!("{}:{stage}", operation.id),
    };
    let client = official_client_for(&gateway, TRANSPORT_PROTOCOL_JSONRPC)
        .await
        .map_err(|_| error())?;
    let mut message = Message::new(Role::User, vec![Part::text(operation.prompt.clone())]);
    message.context_id = Some(root_context_id.clone());
    let message_id = message.message_id.clone();
    let request = SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.send_streaming_message(&request),
    )
    .await
    .map_err(|_| stage_error("stream-open-timeout"))?
    .map_err(|_| stage_error("stream-open"))?;
    let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .map_err(|_| stage_error("first-event-timeout"))?
        .ok_or_else(|| stage_error("first-event-closed"))?
        .map_err(|_| stage_error("first-event-error"))?;
    let StreamResponse::Task(task) = first else {
        return Err(stage_error("first-event-not-task"));
    };
    validate_task_evidence(&task)?;
    validate_task_identity(&task.id, &task.context_id, &task.id, &root_context_id)?;
    trace
        .record(LifelineFailureTransition {
            kind: LifelineFailureEventKind::PrimarySubmitted,
            operation_id: &operation.id,
            gateway_id: &gateway.gateway_id,
            context_id: &root_context_id,
            task_id: Some(&task.id),
            message_id: Some(&message_id),
            attempt: 1,
            outcome: "submitted",
            replaces_task_id: None,
        })
        .map_err(|_| error())?;
    failure
        .bind_primary(&operation.id, &task.id, &root_context_id, &message_id)
        .map_err(|_| error())?;
    let mut primary_owner = FailurePrimaryOwner::new(failure.clone());
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        failure.wait_for_outage_signal(),
    )
    .await
    .map_err(|_| stage_error("outage-timeout"))?;
    let mut observed_message_ids = vec![message_id.clone()];
    let mut observed_task_ids = Vec::new();
    let mut artifact_ids = Vec::new();
    capture_task_ids(
        &task,
        &mut observed_message_ids,
        &mut observed_task_ids,
        &mut artifact_ids,
    )?;
    let stream_failure = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match stream.next().await {
                None => return Err(stage_error("stream-closed-without-error")),
                Some(Err(_)) => return Ok("error"),
                Some(Ok(update)) => {
                    validate_stream_evidence(&update)?;
                    let terminal =
                        stream_event_is_terminal_for(&update, &task.id, &root_context_id)?;
                    capture_stream_ids(
                        &update,
                        &mut observed_message_ids,
                        &mut observed_task_ids,
                        &mut artifact_ids,
                    )?;
                    if terminal {
                        return Err(stage_error("unexpected-stream-terminal"));
                    }
                }
            }
        }
    })
    .await
    .map_err(|_| stage_error("stream-failure-timeout"))??;
    trace
        .record(LifelineFailureTransition {
            kind: LifelineFailureEventKind::PrimaryStreamFailed,
            operation_id: &operation.id,
            gateway_id: &gateway.gateway_id,
            context_id: &root_context_id,
            task_id: Some(&task.id),
            message_id: Some(&message_id),
            attempt: 1,
            outcome: stream_failure,
            replaces_task_id: None,
        })
        .map_err(|_| error())?;
    drop(stream);
    trace
        .record(LifelineFailureTransition {
            kind: LifelineFailureEventKind::CancelRequested,
            operation_id: &operation.id,
            gateway_id: &gateway.gateway_id,
            context_id: &root_context_id,
            task_id: Some(&task.id),
            message_id: Some(&message_id),
            attempt: 1,
            outcome: "requested",
            replaces_task_id: None,
        })
        .map_err(|_| error())?;
    let cancellation_response = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        client.cancel_task(&CancelTaskRequest {
            id: task.id.clone(),
            metadata: None,
            tenant: None,
        }),
    )
    .await
    .map_err(|_| stage_error("cancel-timeout"))?
    .map_err(|_| stage_error("cancel"))?;
    validate_task_evidence(&cancellation_response)?;
    validate_task_identity(
        &cancellation_response.id,
        &cancellation_response.context_id,
        &task.id,
        &root_context_id,
    )?;
    let canceled = wait_for_failure_primary_canceled(&client, &task.id, &root_context_id)
        .await
        .map_err(|_| stage_error("cancel-not-canceled"))?;
    failure.mark_public_cancel_confirmed();
    capture_task_ids(
        &canceled,
        &mut observed_message_ids,
        &mut observed_task_ids,
        &mut artifact_ids,
    )?;
    trace
        .record(LifelineFailureTransition {
            kind: LifelineFailureEventKind::CancelConfirmed,
            operation_id: &operation.id,
            gateway_id: &gateway.gateway_id,
            context_id: &root_context_id,
            task_id: Some(&task.id),
            message_id: Some(&message_id),
            attempt: 1,
            outcome: "canceled",
            replaces_task_id: None,
        })
        .map_err(|_| error())?;
    primary_owner.disarm();
    Ok(LifelineDirectorOperationReceipt {
        operation_id: operation.id,
        gateway_id: gateway.gateway_id,
        binding: TRANSPORT_PROTOCOL_JSONRPC.to_owned(),
        message_id,
        observed_message_ids,
        observed_task_ids,
        task_id: canceled.id,
        context_id: canceled.context_id,
        terminal_state: canceled.status.state,
        artifact_ids,
        observations: vec![
            LifelineDirectorObservation::Streaming,
            LifelineDirectorObservation::Cancel,
        ],
        replaces_task_id: None,
        reference_task_ids: Vec::new(),
    })
}

async fn execute_failure_fallback(
    gateway: ResolvedLifelineGateway,
    root_context_id: String,
    primary_task_id: String,
    trace: LifelineFailureTrace,
) -> Result<LifelineDirectorOperationReceipt, LifelineDirectorError> {
    let operation_id = "shipment-routing-fallback";
    let error = || LifelineDirectorError::Operation {
        operation_id: operation_id.to_owned(),
    };
    let client = official_client_for(&gateway, TRANSPORT_PROTOCOL_HTTP_JSON)
        .await
        .map_err(|_| error())?;
    let mut message = Message::new(
        Role::User,
        vec![Part::text(
            "Map the bounded fictional shipment routes using the reviewed fallback route.",
        )],
    );
    message.context_id = Some(root_context_id.clone());
    message.reference_task_ids = Some(vec![primary_task_id.clone()]);
    let message_id = message.message_id.clone();
    trace
        .record(LifelineFailureTransition {
            kind: LifelineFailureEventKind::FallbackSubmitted,
            operation_id,
            gateway_id: &gateway.gateway_id,
            context_id: &root_context_id,
            task_id: None,
            message_id: Some(&message_id),
            attempt: 1,
            outcome: "submitted",
            replaces_task_id: Some(&primary_task_id),
        })
        .map_err(|_| error())?;
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.send_message(&SendMessageRequest {
            message,
            configuration: None,
            metadata: None,
            tenant: None,
        }),
    )
    .await
    .map_err(|_| error())?
    .map_err(|_| error())?;
    let SendMessageResponse::Task(task) = response else {
        return Err(error());
    };
    validate_task_evidence(&task)?;
    validate_task_identity(&task.id, &task.context_id, &task.id, &root_context_id)?;
    if task.status.state != TaskState::Completed || task.id == primary_task_id {
        return Err(error());
    }
    let mut observed_message_ids = vec![message_id.clone()];
    let mut observed_task_ids = vec![primary_task_id.clone()];
    let mut artifact_ids = Vec::new();
    capture_task_ids(
        &task,
        &mut observed_message_ids,
        &mut observed_task_ids,
        &mut artifact_ids,
    )?;
    trace
        .record(LifelineFailureTransition {
            kind: LifelineFailureEventKind::FallbackCompleted,
            operation_id,
            gateway_id: &gateway.gateway_id,
            context_id: &root_context_id,
            task_id: Some(&task.id),
            message_id: Some(&message_id),
            attempt: 1,
            outcome: "completed",
            replaces_task_id: Some(&primary_task_id),
        })
        .map_err(|_| error())?;
    Ok(LifelineDirectorOperationReceipt {
        operation_id: operation_id.to_owned(),
        gateway_id: gateway.gateway_id,
        binding: TRANSPORT_PROTOCOL_HTTP_JSON.to_owned(),
        message_id,
        observed_message_ids,
        observed_task_ids,
        task_id: task.id,
        context_id: task.context_id,
        terminal_state: task.status.state,
        artifact_ids,
        observations: Vec::new(),
        replaces_task_id: Some(primary_task_id.clone()),
        reference_task_ids: vec![primary_task_id],
    })
}

async fn official_client_for(
    gateway: &ResolvedLifelineGateway,
    binding: &str,
) -> Result<OfficialA2AClient, LifelineDirectorError> {
    let http = director_http_client()?;
    let factory = match binding {
        TRANSPORT_PROTOCOL_JSONRPC => A2AClientFactory::builder()
            .no_defaults()
            .register(Arc::new(JsonRpcTransportFactory::new(Some(http)))),
        TRANSPORT_PROTOCOL_HTTP_JSON => A2AClientFactory::builder()
            .no_defaults()
            .register(Arc::new(RestTransportFactory::new(Some(http)))),
        _ => return Err(invariant("unsupported failure scenario binding")),
    }
    .preferred_bindings(vec![binding.to_owned()])
    .build();
    factory
        .create_from_card(&gateway.card)
        .await
        .map_err(|_| LifelineDirectorError::Operation {
            operation_id: "failure-scenario-client".to_owned(),
        })
}

async fn get_failure_primary(
    gateway: &ResolvedLifelineGateway,
    task_id: &str,
    context_id: &str,
) -> Result<Task, LifelineDirectorError> {
    let client = official_client_for(gateway, TRANSPORT_PROTOCOL_JSONRPC).await?;
    let task = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.get_task(&GetTaskRequest {
            id: task_id.to_owned(),
            history_length: Some(0),
            tenant: None,
        }),
    )
    .await
    .map_err(|_| LifelineDirectorError::Operation {
        operation_id: "primary-final-reconciliation".to_owned(),
    })?
    .map_err(|_| LifelineDirectorError::Operation {
        operation_id: "primary-final-reconciliation".to_owned(),
    })?;
    validate_task_evidence(&task)?;
    validate_task_identity(&task.id, &task.context_id, task_id, context_id)?;
    Ok(task)
}

async fn wait_for_failure_primary_canceled(
    client: &OfficialA2AClient,
    task_id: &str,
    context_id: &str,
) -> Result<Task, LifelineDirectorError> {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let task = client
                .get_task(&GetTaskRequest {
                    id: task_id.to_owned(),
                    history_length: Some(0),
                    tenant: None,
                })
                .await
                .map_err(|_| invariant("primary cancellation reconciliation failed"))?;
            validate_task_evidence(&task)?;
            validate_task_identity(&task.id, &task.context_id, task_id, context_id)?;
            if task.status.state == TaskState::Canceled {
                return Ok(task);
            }
            if task.status.state.is_terminal() {
                return Err(invariant(
                    "primary reached a non-canceled terminal state during reconciliation",
                ));
            }
        }
    })
    .await
    .map_err(|_| invariant("primary cancellation reconciliation timed out"))?
}

fn record_receipt_transition(
    trace: &LifelineFailureTrace,
    kind: LifelineFailureEventKind,
    receipt: &LifelineDirectorOperationReceipt,
    outcome: &str,
    replaces_task_id: Option<&str>,
) -> Result<(), LifelineDirectorError> {
    trace
        .record(LifelineFailureTransition {
            kind,
            operation_id: &receipt.operation_id,
            gateway_id: &receipt.gateway_id,
            context_id: &receipt.context_id,
            task_id: Some(&receipt.task_id),
            message_id: Some(&receipt.message_id),
            attempt: 1,
            outcome,
            replaces_task_id,
        })
        .map_err(|_| LifelineDirectorError::Operation {
            operation_id: receipt.operation_id.clone(),
        })
}

async fn assemble_director_run(
    manifest: &LifelineDirectorManifest,
    resolved: &[ResolvedLifelineGateway],
    discovery_failures: Vec<LifelineDirectorDiscoveryFailure>,
    root_context_id: String,
    initial_operations: Vec<LifelineDirectorOperationReceipt>,
) -> Result<LifelineDirectorRun, LifelineDirectorError> {
    let mut fallback_operation = None;
    let primary = initial_operations
        .iter()
        .find(|receipt| receipt.gateway_id == manifest.logistics.primary_gateway_id);
    let primary_discovery_failed = discovery_failures
        .iter()
        .any(|failure| failure.gateway_id == manifest.logistics.primary_gateway_id);
    let replaced_task_id = if primary.is_some_and(LifelineDirectorOperationReceipt::is_canceled) {
        primary.map(|receipt| receipt.task_id.clone())
    } else if let Some(primary) = primary.filter(|receipt| !receipt.is_completed()) {
        return Err(LifelineDirectorError::Operation {
            operation_id: primary.operation_id.clone(),
        });
    } else {
        None
    };
    if replaced_task_id.is_some() || primary_discovery_failed {
        let mut fallback = manifest
            .operations
            .iter()
            .find(|operation| operation.gateway_id == manifest.logistics.primary_gateway_id)
            .cloned()
            .ok_or_else(|| invariant("primary logistics operation is missing"))?;
        "shipment-routing-fallback".clone_into(&mut fallback.id);
        fallback.gateway_id = manifest.logistics.fallback_gateway_id.clone();
        fallback.path = LifelineDirectorPath::SyncRest;
        let gateway = resolved
            .iter()
            .find(|gateway| gateway.gateway_id == fallback.gateway_id)
            .cloned();
        let mut receipt = execute_initial_operation(
            fallback,
            gateway,
            root_context_id.clone(),
            replaced_task_id.iter().cloned().collect(),
        )
        .await?;
        if !receipt.is_completed() {
            return Err(LifelineDirectorError::Operation {
                operation_id: receipt.operation_id.clone(),
            });
        }
        receipt.replaces_task_id.clone_from(&replaced_task_id);
        fallback_operation = Some(receipt);
    }

    let review_reference_task_ids = initial_operations
        .iter()
        .chain(fallback_operation.iter())
        .map(|receipt| receipt.task_id.clone())
        .collect::<Vec<_>>();
    let review_prompt = review_prompt(manifest, &initial_operations, fallback_operation.as_ref());
    let review_operation = LifelineDirectorOperation {
        id: "independent-review".to_owned(),
        gateway_id: manifest.review.gateway_id.clone(),
        path: manifest.review.path,
        prompt: review_prompt,
    };
    let review_gateway = resolved
        .iter()
        .find(|gateway| gateway.gateway_id == review_operation.gateway_id)
        .cloned();
    let review = Some(
        execute_initial_operation(
            review_operation,
            review_gateway,
            root_context_id.clone(),
            review_reference_task_ids,
        )
        .await?,
    );
    Ok(build_run_record(
        manifest,
        resolved,
        discovery_failures,
        root_context_id,
        initial_operations,
        fallback_operation,
        review,
    ))
}

fn review_prompt(
    manifest: &LifelineDirectorManifest,
    initial_operations: &[LifelineDirectorOperationReceipt],
    fallback_operation: Option<&LifelineDirectorOperationReceipt>,
) -> String {
    let mut prompt = manifest.review.prompt.clone();
    prompt.push_str(" Task references:");
    for receipt in initial_operations.iter().chain(fallback_operation) {
        prompt.push(' ');
        prompt.push_str(&receipt.task_id);
        for artifact_id in &receipt.artifact_ids {
            prompt.push(' ');
            prompt.push_str(artifact_id);
        }
    }
    prompt
}

fn build_run_record(
    manifest: &LifelineDirectorManifest,
    resolved: &[ResolvedLifelineGateway],
    discovery_failures: Vec<LifelineDirectorDiscoveryFailure>,
    root_context_id: String,
    initial_operations: Vec<LifelineDirectorOperationReceipt>,
    fallback_operation: Option<LifelineDirectorOperationReceipt>,
    review: Option<LifelineDirectorOperationReceipt>,
) -> LifelineDirectorRun {
    let mut captured_message_ids = Vec::new();
    let mut captured_task_ids = Vec::new();
    let mut captured_artifact_ids = Vec::new();
    for receipt in initial_operations
        .iter()
        .chain(fallback_operation.iter())
        .chain(review.iter())
    {
        for message_id in &receipt.observed_message_ids {
            push_unique(&mut captured_message_ids, message_id);
        }
        for task_id in &receipt.observed_task_ids {
            push_unique(&mut captured_task_ids, task_id);
        }
        for artifact_id in &receipt.artifact_ids {
            push_unique(&mut captured_artifact_ids, artifact_id);
        }
    }
    LifelineDirectorRun {
        schema_version: LIFELINE_DIRECTOR_SCHEMA_VERSION.to_owned(),
        fictional: true,
        disclaimer: LIFELINE_DIRECTOR_EVIDENCE_DISCLAIMER.to_owned(),
        run_id: manifest.run_id.clone(),
        root_context_id,
        discovered_gateways: resolved
            .iter()
            .map(|gateway| LifelineDirectorDiscoveryReceipt {
                gateway_id: gateway.gateway_id.clone(),
                discovery_url: gateway.discovery_url.clone(),
                provider_organization: gateway
                    .card
                    .provider
                    .as_ref()
                    .map_or_else(String::new, |provider| provider.organization.clone()),
                skill_ids: gateway
                    .card
                    .skills
                    .iter()
                    .map(|skill| skill.id.clone())
                    .collect(),
                interfaces: gateway
                    .card
                    .supported_interfaces
                    .iter()
                    .map(|interface| LifelineDirectorInterfaceReceipt {
                        url: interface.url.clone(),
                        protocol_binding: interface.protocol_binding.clone(),
                        protocol_version: interface.protocol_version.clone(),
                    })
                    .collect(),
            })
            .collect(),
        discovery_failures,
        initial_operations,
        fallback_operation,
        review,
        captured_message_ids,
        captured_task_ids,
        captured_artifact_ids,
    }
}

// Keep the official-client stream, reconnect, reconciliation, and cancellation
// sequence contiguous so its ordering is directly auditable.
#[allow(clippy::too_many_lines)]
async fn execute_initial_operation(
    operation: LifelineDirectorOperation,
    gateway: Option<ResolvedLifelineGateway>,
    root_context_id: String,
    reference_task_ids: Vec<String>,
) -> Result<LifelineDirectorOperationReceipt, LifelineDirectorError> {
    let error = || LifelineDirectorError::Operation {
        operation_id: operation.id.clone(),
    };
    let gateway = gateway.ok_or_else(&error)?;
    let binding = operation.path.binding();
    let http = director_http_client()?;
    let factory = match binding {
        TRANSPORT_PROTOCOL_JSONRPC => A2AClientFactory::builder()
            .no_defaults()
            .register(Arc::new(JsonRpcTransportFactory::new(Some(http)))),
        TRANSPORT_PROTOCOL_HTTP_JSON => A2AClientFactory::builder()
            .no_defaults()
            .register(Arc::new(RestTransportFactory::new(Some(http)))),
        _ => return Err(error()),
    }
    .preferred_bindings(vec![binding.to_owned()])
    .build();
    let client = factory
        .create_from_card(&gateway.card)
        .await
        .map_err(|_| error())?;
    let mut message = Message::new(Role::User, vec![Part::text(operation.prompt.clone())]);
    message.context_id = Some(root_context_id.clone());
    if !reference_task_ids.is_empty() {
        message.reference_task_ids = Some(reference_task_ids.clone());
    }
    let message_id = message.message_id.clone();
    let mut observed_message_ids = vec![message_id.clone()];
    let mut observed_task_ids = reference_task_ids.clone();
    let mut observed_artifact_ids = Vec::new();
    let request = SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let (task, observations) = if operation.path == LifelineDirectorPath::StreamReconnect {
        let mut observations = vec![LifelineDirectorObservation::Streaming];
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.send_streaming_message(&request),
        )
        .await
        .map_err(|_| error())?
        .map_err(|_| error())?;
        let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .map_err(|_| error())?
            .ok_or_else(&error)?
            .map_err(|_| error())?;
        let StreamResponse::Task(first_task) = first else {
            return Err(error());
        };
        if validate_task_evidence(&first_task).is_err() || first_task.context_id != root_context_id
        {
            cancel_task_best_effort(&client, &first_task.id).await;
            return Err(error());
        }
        capture_task_ids(
            &first_task,
            &mut observed_message_ids,
            &mut observed_task_ids,
            &mut observed_artifact_ids,
        )?;
        let first_task_id = first_task.id.clone();
        drop(stream);
        let task_result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.get_task(&GetTaskRequest {
                id: first_task_id.clone(),
                history_length: Some(0),
                tenant: None,
            }),
        )
        .await;
        let Ok(Ok(mut task)) = task_result else {
            cancel_task_best_effort(&client, &first_task_id).await;
            return Err(error());
        };
        if validate_task_evidence(&task).is_err()
            || validate_task_identity(&task.id, &task.context_id, &first_task_id, &root_context_id)
                .is_err()
        {
            cancel_task_best_effort(&client, &first_task_id).await;
            return Err(error());
        }
        capture_task_ids(
            &task,
            &mut observed_message_ids,
            &mut observed_task_ids,
            &mut observed_artifact_ids,
        )?;
        observations.push(LifelineDirectorObservation::GetTask);
        if !task.status.state.is_terminal() {
            observations.push(LifelineDirectorObservation::Subscribe);
            let subscribe_result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                client.subscribe_to_task(&SubscribeToTaskRequest {
                    id: task.id.clone(),
                    tenant: None,
                }),
            )
            .await;
            let Ok(Ok(mut updates)) = subscribe_result else {
                cancel_task_best_effort(&client, &task.id).await;
                return Err(error());
            };
            let mut terminal_observed = false;
            for _ in 0..16 {
                let next =
                    tokio::time::timeout(std::time::Duration::from_secs(2), updates.next()).await;
                let Ok(Some(Ok(update))) = next else {
                    break;
                };
                let Ok(terminal) = validate_stream_evidence(&update).and_then(|()| {
                    stream_event_is_terminal_for(&update, &task.id, &root_context_id)
                }) else {
                    cancel_task_best_effort(&client, &task.id).await;
                    return Err(error());
                };
                if terminal {
                    capture_stream_ids(
                        &update,
                        &mut observed_message_ids,
                        &mut observed_task_ids,
                        &mut observed_artifact_ids,
                    )?;
                    terminal_observed = true;
                    break;
                }
                capture_stream_ids(
                    &update,
                    &mut observed_message_ids,
                    &mut observed_task_ids,
                    &mut observed_artifact_ids,
                )?;
            }
            if terminal_observed {
                let expected_task_id = task.id.clone();
                let snapshot_result = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    client.get_task(&GetTaskRequest {
                        id: expected_task_id.clone(),
                        history_length: Some(0),
                        tenant: None,
                    }),
                )
                .await;
                let Ok(Ok(snapshot)) = snapshot_result else {
                    cancel_task_best_effort(&client, &expected_task_id).await;
                    return Err(error());
                };
                if validate_task_evidence(&snapshot).is_err()
                    || validate_task_identity(
                        &snapshot.id,
                        &snapshot.context_id,
                        &expected_task_id,
                        &root_context_id,
                    )
                    .is_err()
                {
                    cancel_task_best_effort(&client, &expected_task_id).await;
                    return Err(error());
                }
                capture_task_ids(
                    &snapshot,
                    &mut observed_message_ids,
                    &mut observed_task_ids,
                    &mut observed_artifact_ids,
                )?;
                task = snapshot;
            } else {
                let expected_task_id = task.id.clone();
                let cancel_result = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    client.cancel_task(&CancelTaskRequest {
                        id: expected_task_id.clone(),
                        metadata: None,
                        tenant: None,
                    }),
                )
                .await;
                let Ok(Ok(canceled)) = cancel_result else {
                    cancel_task_best_effort(&client, &expected_task_id).await;
                    return Err(error());
                };
                if validate_task_evidence(&canceled).is_err()
                    || validate_task_identity(
                        &canceled.id,
                        &canceled.context_id,
                        &expected_task_id,
                        &root_context_id,
                    )
                    .is_err()
                {
                    cancel_task_best_effort(&client, &expected_task_id).await;
                    return Err(error());
                }
                capture_task_ids(
                    &canceled,
                    &mut observed_message_ids,
                    &mut observed_task_ids,
                    &mut observed_artifact_ids,
                )?;
                task = canceled;
                observations.push(LifelineDirectorObservation::Cancel);
            }
        }
        (task, observations)
    } else {
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.send_message(&request),
        )
        .await
        .map_err(|_| error())?
        .map_err(|_| error())?;
        let SendMessageResponse::Task(task) = response else {
            return Err(error());
        };
        if validate_task_evidence(&task).is_err() {
            cancel_task_best_effort(&client, &task.id).await;
            return Err(error());
        }
        (task, Vec::new())
    };
    if validate_task_evidence(&task).is_err()
        || task.context_id != root_context_id
        || !task.status.state.is_terminal()
    {
        cancel_task_best_effort(&client, &task.id).await;
        return Err(error());
    }
    capture_task_ids(
        &task,
        &mut observed_message_ids,
        &mut observed_task_ids,
        &mut observed_artifact_ids,
    )?;
    Ok(LifelineDirectorOperationReceipt {
        operation_id: operation.id,
        gateway_id: gateway.gateway_id,
        binding: binding.to_owned(),
        message_id,
        observed_message_ids,
        observed_task_ids,
        task_id: task.id,
        context_id: task.context_id,
        terminal_state: task.status.state,
        artifact_ids: observed_artifact_ids,
        observations,
        replaces_task_id: None,
        reference_task_ids,
    })
}

async fn cancel_task_best_effort(client: &OfficialA2AClient, task_id: &str) {
    if validate_protocol_identifier(task_id).is_err() {
        return;
    }
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.cancel_task(&CancelTaskRequest {
            id: task_id.to_owned(),
            metadata: None,
            tenant: None,
        }),
    )
    .await;
}

fn capture_message_ids(
    message: &Message,
    message_ids: &mut Vec<String>,
    task_ids: &mut Vec<String>,
) {
    push_unique(message_ids, &message.message_id);
    if let Some(task_id) = message.task_id.as_deref() {
        push_unique(task_ids, task_id);
    }
    for task_id in message.reference_task_ids.as_deref().unwrap_or_default() {
        push_unique(task_ids, task_id);
    }
}

fn capture_task_ids(
    task: &Task,
    message_ids: &mut Vec<String>,
    task_ids: &mut Vec<String>,
    artifact_ids: &mut Vec<String>,
) -> Result<(), LifelineDirectorError> {
    validate_task_evidence(task)?;
    push_unique(task_ids, &task.id);
    if let Some(message) = task.status.message.as_ref() {
        capture_message_ids(message, message_ids, task_ids);
    }
    for message in task.history.as_deref().unwrap_or_default() {
        capture_message_ids(message, message_ids, task_ids);
    }
    for artifact in task.artifacts.as_deref().unwrap_or_default() {
        push_unique(artifact_ids, &artifact.artifact_id);
    }
    Ok(())
}

fn capture_stream_ids(
    event: &StreamResponse,
    message_ids: &mut Vec<String>,
    task_ids: &mut Vec<String>,
    artifact_ids: &mut Vec<String>,
) -> Result<(), LifelineDirectorError> {
    validate_stream_evidence(event)?;
    match event {
        StreamResponse::Task(task) => {
            capture_task_ids(task, message_ids, task_ids, artifact_ids)?;
        }
        StreamResponse::Message(message) => {
            capture_message_ids(message, message_ids, task_ids);
        }
        StreamResponse::StatusUpdate(update) => {
            push_unique(task_ids, &update.task_id);
            if let Some(message) = update.status.message.as_ref() {
                capture_message_ids(message, message_ids, task_ids);
            }
        }
        StreamResponse::ArtifactUpdate(update) => {
            push_unique(task_ids, &update.task_id);
            push_unique(artifact_ids, &update.artifact.artifact_id);
        }
    }
    Ok(())
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|candidate| candidate == value) {
        values.push(value.to_owned());
    }
}

fn validate_serialized_bound<T: Serialize>(
    value: &T,
    max_bytes: usize,
    label: &str,
) -> Result<(), LifelineDirectorError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| invariant(format!("{label} could not be bounded")))?;
    require(
        bytes.len() <= max_bytes,
        &format!("{label} exceeds {max_bytes} bytes"),
    )
}

fn validate_message_evidence(
    message: &Message,
    expected_task_id: Option<&str>,
    expected_context_id: Option<&str>,
) -> Result<(), LifelineDirectorError> {
    validate_protocol_identifier(&message.message_id)?;
    if let Some(context_id) = message.context_id.as_deref() {
        validate_protocol_identifier(context_id)?;
        if let Some(expected) = expected_context_id {
            require(
                context_id == expected,
                "nested message context does not match enclosing protocol value",
            )?;
        }
    }
    if let Some(task_id) = message.task_id.as_deref() {
        validate_protocol_identifier(task_id)?;
        if let Some(expected) = expected_task_id {
            require(
                task_id == expected,
                "nested message task does not match enclosing protocol value",
            )?;
        }
    }
    for task_id in message.reference_task_ids.as_deref().unwrap_or_default() {
        validate_protocol_identifier(task_id)?;
    }
    Ok(())
}

fn validate_task_evidence(task: &Task) -> Result<(), LifelineDirectorError> {
    validate_serialized_bound(task, 64 * 1024, "task response")?;
    validate_protocol_identifier(&task.id)?;
    validate_protocol_identifier(&task.context_id)?;
    if let Some(message) = task.status.message.as_ref() {
        validate_message_evidence(message, Some(&task.id), Some(&task.context_id))?;
    }
    for message in task.history.as_deref().unwrap_or_default() {
        validate_message_evidence(message, Some(&task.id), Some(&task.context_id))?;
    }
    for artifact in task.artifacts.as_deref().unwrap_or_default() {
        validate_protocol_identifier(&artifact.artifact_id)?;
    }
    Ok(())
}

fn validate_stream_evidence(event: &StreamResponse) -> Result<(), LifelineDirectorError> {
    validate_serialized_bound(event, 64 * 1024, "stream event")?;
    match event {
        StreamResponse::Task(task) => validate_task_evidence(task),
        StreamResponse::Message(message) => validate_message_evidence(message, None, None),
        StreamResponse::StatusUpdate(update) => {
            validate_protocol_identifier(&update.task_id)?;
            validate_protocol_identifier(&update.context_id)?;
            if let Some(message) = update.status.message.as_ref() {
                validate_message_evidence(
                    message,
                    Some(&update.task_id),
                    Some(&update.context_id),
                )?;
            }
            Ok(())
        }
        StreamResponse::ArtifactUpdate(update) => {
            validate_protocol_identifier(&update.task_id)?;
            validate_protocol_identifier(&update.context_id)?;
            validate_protocol_identifier(&update.artifact.artifact_id)
        }
    }
}

fn validate_protocol_identifier(value: &str) -> Result<(), LifelineDirectorError> {
    require(
        !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            }),
        "protocol identifier violates bounds or safe character policy",
    )
}

fn validate_task_identity(
    observed_task_id: &str,
    observed_context_id: &str,
    expected_task_id: &str,
    expected_context_id: &str,
) -> Result<(), LifelineDirectorError> {
    require(
        observed_task_id == expected_task_id && observed_context_id == expected_context_id,
        "task snapshot identifiers changed during reconciliation",
    )
}

fn stream_event_is_terminal_for(
    event: &StreamResponse,
    task_id: &str,
    context_id: &str,
) -> Result<bool, LifelineDirectorError> {
    let (observed_task_id, observed_context_id, terminal) = match event {
        StreamResponse::Task(task) => (
            task.id.as_str(),
            task.context_id.as_str(),
            task.status.state.is_terminal(),
        ),
        StreamResponse::StatusUpdate(update) => (
            update.task_id.as_str(),
            update.context_id.as_str(),
            update.status.state.is_terminal(),
        ),
        StreamResponse::ArtifactUpdate(update) => {
            (update.task_id.as_str(), update.context_id.as_str(), false)
        }
        StreamResponse::Message(message) => (
            message.task_id.as_deref().unwrap_or_default(),
            message.context_id.as_deref().unwrap_or_default(),
            false,
        ),
    };
    require(
        observed_task_id == task_id && observed_context_id == context_id,
        "stream update identifiers changed during reconnect",
    )?;
    Ok(terminal)
}

impl LifelineDirectorPath {
    fn binding(self) -> &'static str {
        match self {
            Self::SyncRest => TRANSPORT_PROTOCOL_HTTP_JSON,
            Self::SyncJsonrpc | Self::StreamReconnect => TRANSPORT_PROTOCOL_JSONRPC,
        }
    }
}

impl LifelineDirectorRun {
    #[must_use]
    pub fn root_context_id(&self) -> &str {
        &self.root_context_id
    }

    #[must_use]
    pub fn initial_operations(&self) -> &[LifelineDirectorOperationReceipt] {
        &self.initial_operations
    }

    #[must_use]
    pub fn fallback_operation(&self) -> Option<&LifelineDirectorOperationReceipt> {
        self.fallback_operation.as_ref()
    }

    #[must_use]
    pub fn review(&self) -> Option<&LifelineDirectorOperationReceipt> {
        self.review.as_ref()
    }

    #[must_use]
    pub fn captured_message_ids(&self) -> &[String] {
        &self.captured_message_ids
    }

    #[must_use]
    pub fn captured_task_ids(&self) -> &[String] {
        &self.captured_task_ids
    }

    #[must_use]
    pub fn all_protocol_ids_are_captured(&self) -> bool {
        let receipts = self
            .initial_operations
            .iter()
            .chain(self.fallback_operation.iter())
            .chain(self.review.iter())
            .collect::<Vec<_>>();
        let message_ids = receipts
            .iter()
            .flat_map(|receipt| receipt.observed_message_ids.iter().map(String::as_str))
            .collect::<HashSet<_>>();
        let task_ids = receipts
            .iter()
            .flat_map(|receipt| receipt.observed_task_ids.iter().map(String::as_str))
            .collect::<HashSet<_>>();
        let receipt_task_ids = receipts
            .iter()
            .map(|receipt| receipt.task_id.as_str())
            .collect::<HashSet<_>>();
        let artifact_ids = receipts
            .iter()
            .flat_map(|receipt| receipt.artifact_ids.iter().map(String::as_str))
            .collect::<HashSet<_>>();
        self.schema_version == LIFELINE_DIRECTOR_SCHEMA_VERSION
            && self.fictional
            && self.disclaimer == LIFELINE_DIRECTOR_EVIDENCE_DISCLAIMER
            && !self.root_context_id.is_empty()
            && receipts.iter().all(|receipt| {
                receipt.context_id == self.root_context_id
                    && receipt
                        .observed_task_ids
                        .iter()
                        .any(|task_id| task_id == &receipt.task_id)
                    && receipt
                        .observed_message_ids
                        .iter()
                        .any(|message_id| message_id == &receipt.message_id)
                    && receipt
                        .reference_task_ids
                        .iter()
                        .all(|task_id| task_ids.contains(task_id.as_str()))
                    && receipt
                        .replaces_task_id
                        .as_deref()
                        .is_none_or(|task_id| task_ids.contains(task_id))
            })
            && message_ids.iter().all(|message_id| !message_id.is_empty())
            && receipt_task_ids.len() == receipts.len()
            && self
                .captured_message_ids
                .iter()
                .map(String::as_str)
                .collect::<HashSet<_>>()
                == message_ids
            && self
                .captured_task_ids
                .iter()
                .map(String::as_str)
                .collect::<HashSet<_>>()
                == task_ids
            && self
                .captured_artifact_ids
                .iter()
                .map(String::as_str)
                .collect::<HashSet<_>>()
                == artifact_ids
    }
}

impl LifelineFailureScenarioRun {
    /// Verifies the read-back run receipt against the closed causal trace.
    ///
    /// # Errors
    /// Returns an error when either artifact is invalid, downgraded, or belongs
    /// to a different scenario execution.
    #[allow(clippy::too_many_lines)] // Keep the audited cross-artifact contract visibly contiguous.
    pub fn verify(&self, events: &[LifelineFailureEvent]) -> Result<(), LifelineDirectorError> {
        verify_lifeline_failure_events(events)
            .map_err(|_| invariant("failure trace semantic verification failed"))?;
        let primary = self
            .director_run
            .initial_operations
            .iter()
            .find(|receipt| receipt.task_id == self.primary_task_id)
            .ok_or_else(|| invariant("primary receipt is missing"))?;
        let fallback = self
            .director_run
            .fallback_operation
            .as_ref()
            .ok_or_else(|| invariant("fallback receipt is missing"))?;
        let review = self
            .director_run
            .review
            .as_ref()
            .ok_or_else(|| invariant("review receipt is missing"))?;
        let event = |kind: &str| events.iter().find(|event| event.kind() == kind);
        let trace_primary = event("primary-submitted")
            .ok_or_else(|| invariant("primary trace event is missing"))?;
        let trace_fallback = event("fallback-completed")
            .ok_or_else(|| invariant("fallback trace event is missing"))?;
        let trace_review =
            event("review-completed").ok_or_else(|| invariant("review trace event is missing"))?;
        let sibling_receipts = self
            .director_run
            .initial_operations
            .iter()
            .filter(|receipt| receipt.task_id != self.primary_task_id)
            .collect::<Vec<_>>();
        let trace_siblings = events
            .iter()
            .filter(|event| event.kind() == "sibling-completed")
            .collect::<Vec<_>>();
        let receipts = self
            .director_run
            .initial_operations
            .iter()
            .chain(self.director_run.fallback_operation.iter())
            .chain(self.director_run.review.iter())
            .collect::<Vec<_>>();
        let receipt_ids_are_valid = failure_receipt_ids_are_valid(&receipts);
        let receipt_protocols_are_valid = failure_receipt_protocols_are_valid(&receipts);
        let expected_review_references = self
            .director_run
            .initial_operations
            .iter()
            .chain(self.director_run.fallback_operation.iter())
            .map(|receipt| receipt.task_id.as_str())
            .collect::<HashSet<_>>();
        let observed_review_references = review
            .reference_task_ids
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let review_references_match = review.reference_task_ids.len()
            == expected_review_references.len()
            && observed_review_references == expected_review_references;
        let siblings_match = sibling_receipts.iter().all(|receipt| {
            trace_siblings.iter().any(|event| {
                event.operation_id() == receipt.operation_id
                    && event.gateway_id() == receipt.gateway_id
                    && event.context_id() == receipt.context_id
                    && event.task_id() == Some(receipt.task_id.as_str())
                    && event.message_id() == Some(receipt.message_id.as_str())
            })
        });
        require(
            self.schema_version == "lifeline-failure-scenario-run/1"
                && self.primary_final_state == "canceled"
                && self.primary_attempts == 1
                && self.fallback_attempts == 1
                && self.sibling_dispatches == 3
                && self.root_context_restarts == 0
                && self.director_run.schema_version == LIFELINE_DIRECTOR_SCHEMA_VERSION
                && self.director_run.fictional
                && self.director_run.disclaimer == LIFELINE_DIRECTOR_EVIDENCE_DISCLAIMER
                && self.director_run.run_id == "lifeline-director-0047"
                && self.director_run.root_context_id == self.root_context_id
                && self.director_run.discovery_failures.is_empty()
                && failure_discovery_receipts_are_valid(&self.director_run.discovered_gateways)
                && self.director_run.initial_operations.len() == 4
                && self.director_run.all_protocol_ids_are_captured()
                && receipt_ids_are_valid
                && receipt_protocols_are_valid
                && primary.operation_id == "shipment-routing"
                && primary.gateway_id == "atlas-primary"
                && primary.context_id == self.root_context_id
                && primary.terminal_state == TaskState::Canceled
                && primary.used_streaming()
                && primary.used_cancel()
                && trace_primary.operation_id() == primary.operation_id
                && trace_primary.gateway_id() == primary.gateway_id
                && fallback.operation_id == "shipment-routing-fallback"
                && fallback.gateway_id == "atlas-fallback"
                && fallback.task_id == self.fallback_task_id
                && fallback.context_id == self.fallback_context_id
                && fallback.context_id == self.root_context_id
                && fallback.replaces_task_id.as_deref()
                    == Some(self.fallback_replaces_task_id.as_str())
                && self.fallback_replaces_task_id == self.primary_task_id
                && fallback.reference_task_ids == [self.primary_task_id.as_str()]
                && fallback.task_id != primary.task_id
                && fallback.message_id != primary.message_id
                && fallback.is_completed()
                && trace_fallback.operation_id() == fallback.operation_id
                && trace_fallback.gateway_id() == fallback.gateway_id
                && review.operation_id == "independent-review"
                && review.gateway_id == "sentinel"
                && review.is_completed()
                && review_references_match
                && trace_review.operation_id() == review.operation_id
                && trace_review.gateway_id() == review.gateway_id
                && sibling_receipts.len() == 3
                && trace_siblings.len() == 3
                && sibling_receipts
                    .iter()
                    .all(|receipt| receipt.is_completed())
                && siblings_match
                && trace_primary.context_id() == self.root_context_id
                && trace_primary.task_id() == Some(primary.task_id.as_str())
                && trace_primary.message_id() == Some(primary.message_id.as_str())
                && trace_fallback.context_id() == self.root_context_id
                && trace_fallback.task_id() == Some(fallback.task_id.as_str())
                && trace_fallback.message_id() == Some(fallback.message_id.as_str())
                && trace_fallback.replaces_task_id() == Some(primary.task_id.as_str())
                && trace_review.context_id() == self.root_context_id
                && trace_review.task_id() == Some(review.task_id.as_str())
                && trace_review.message_id() == Some(review.message_id.as_str()),
            "failure scenario run and trace are inconsistent",
        )
    }
}

fn failure_receipt_ids_are_valid(receipts: &[&LifelineDirectorOperationReceipt]) -> bool {
    receipts.iter().all(|receipt| {
        [
            receipt.operation_id.as_str(),
            receipt.gateway_id.as_str(),
            receipt.message_id.as_str(),
            receipt.task_id.as_str(),
            receipt.context_id.as_str(),
        ]
        .into_iter()
        .chain(receipt.observed_message_ids.iter().map(String::as_str))
        .chain(receipt.observed_task_ids.iter().map(String::as_str))
        .chain(receipt.artifact_ids.iter().map(String::as_str))
        .chain(receipt.reference_task_ids.iter().map(String::as_str))
        .chain(receipt.replaces_task_id.iter().map(String::as_str))
        .all(|value| require_identifier(value, "receipt protocol id").is_ok())
    })
}

fn failure_receipt_protocols_are_valid(receipts: &[&LifelineDirectorOperationReceipt]) -> bool {
    receipts
        .iter()
        .all(|receipt| match receipt.operation_id.as_str() {
            "shipment-routing" => {
                receipt.binding == TRANSPORT_PROTOCOL_JSONRPC
                    && receipt.observations
                        == [
                            LifelineDirectorObservation::Streaming,
                            LifelineDirectorObservation::Cancel,
                        ]
            }
            "lot-genealogy" | "recall-criteria" | "independent-review" => {
                receipt.binding == TRANSPORT_PROTOCOL_JSONRPC && receipt.observations.is_empty()
            }
            "exposure-cohort" | "shipment-routing-fallback" => {
                receipt.binding == TRANSPORT_PROTOCOL_HTTP_JSON && receipt.observations.is_empty()
            }
            _ => false,
        })
}

fn failure_discovery_receipts_are_valid(receipts: &[LifelineDirectorDiscoveryReceipt]) -> bool {
    let expected = HashSet::from([
        ("meridian", "Meridian Bio", "lifeline.lot-genealogy"),
        (
            "atlas-primary",
            "Atlas Cold Chain",
            "lifeline.shipment-quarantine",
        ),
        (
            "atlas-fallback",
            "Atlas Cold Chain",
            "lifeline.shipment-quarantine",
        ),
        (
            "helix",
            "Helix Medicines Authority",
            "lifeline.recall-criteria",
        ),
        ("harbor", "Harbor Health", "lifeline.exposure-cohort"),
        ("sentinel", "Sentinel Labs", "lifeline.evidence-review"),
    ]);
    receipts.len() == expected.len()
        && receipts
            .iter()
            .map(|receipt| {
                (
                    receipt.gateway_id.as_str(),
                    receipt.provider_organization.as_str(),
                    receipt.skill_ids.first().map_or("", String::as_str),
                )
            })
            .collect::<HashSet<_>>()
            == expected
        && receipts.iter().all(|receipt| {
            receipt.skill_ids.len() == 1
                && validate_discovery_url(&receipt.discovery_url).is_ok()
                && failure_interfaces_are_local(&receipt.discovery_url, &receipt.interfaces)
        })
}

fn failure_interfaces_are_local(
    discovery_url: &str,
    interfaces: &[LifelineDirectorInterfaceReceipt],
) -> bool {
    let Ok(discovery) = Url::parse(discovery_url) else {
        return false;
    };
    if interfaces.len() != 2 {
        return false;
    }
    let mut bindings = HashSet::new();
    interfaces.iter().all(|interface| {
        let Ok(url) = Url::parse(&interface.url) else {
            return false;
        };
        let expected_path = match interface.protocol_binding.as_str() {
            TRANSPORT_PROTOCOL_JSONRPC => "/jsonrpc",
            TRANSPORT_PROTOCOL_HTTP_JSON => "/rest",
            _ => return false,
        };
        bindings.insert(interface.protocol_binding.as_str())
            && interface.protocol_version == a2a::VERSION
            && url.scheme() == discovery.scheme()
            && url.username().is_empty()
            && url.password().is_none()
            && url.host_str() == discovery.host_str()
            && url.port_or_known_default() == discovery.port_or_known_default()
            && url.path() == expected_path
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

impl LifelineDirectorOperationReceipt {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn binding(&self) -> &str {
        &self.binding
    }

    #[must_use]
    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    #[must_use]
    pub fn used_streaming(&self) -> bool {
        self.observations
            .contains(&LifelineDirectorObservation::Streaming)
    }

    #[must_use]
    pub fn used_get_task(&self) -> bool {
        self.observations
            .contains(&LifelineDirectorObservation::GetTask)
    }

    #[must_use]
    pub fn used_subscribe(&self) -> bool {
        self.observations
            .contains(&LifelineDirectorObservation::Subscribe)
    }

    #[must_use]
    pub fn used_cancel(&self) -> bool {
        self.observations
            .contains(&LifelineDirectorObservation::Cancel)
    }

    #[must_use]
    pub fn replaces_task_id(&self) -> Option<&str> {
        self.replaces_task_id.as_deref()
    }

    #[must_use]
    pub fn reference_task_ids(&self) -> &[String] {
        &self.reference_task_ids
    }

    #[must_use]
    pub fn is_canceled(&self) -> bool {
        self.terminal_state == TaskState::Canceled
    }

    #[must_use]
    pub fn is_completed(&self) -> bool {
        self.terminal_state == TaskState::Completed
    }
}

impl ResolvedLifelineGateway {
    #[must_use]
    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    #[must_use]
    pub fn interfaces_are_local(&self) -> bool {
        interfaces_match_discovery(&self.discovery_url, &self.card)
    }

    #[must_use]
    pub fn card_contract_matches(&self) -> bool {
        self.card.provider.is_some()
            && self.card.skills.len() == 1
            && self.card.security_schemes.is_none()
            && self.card.security_requirements.is_none()
    }
}

impl LifelineDirectorOperation {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl LifelineDirectorReview {
    #[must_use]
    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }
}

impl LifelineDirectorLogistics {
    #[must_use]
    pub fn primary_gateway_id(&self) -> &str {
        &self.primary_gateway_id
    }

    #[must_use]
    pub fn fallback_gateway_id(&self) -> &str {
        &self.fallback_gateway_id
    }
}

fn director_http_client() -> Result<reqwest::Client, LifelineDirectorError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|_| invariant("director HTTP client construction failed"))
}

fn validate_resolved_card(
    gateway: &LifelineDirectorGateway,
    card: &AgentCard,
) -> Result<(), LifelineDirectorError> {
    validate_serialized_bound(card, 64 * 1024, "resolved Agent Card")?;
    require(
        card.provider
            .as_ref()
            .is_some_and(|provider| provider.organization == gateway.expected_organization),
        "resolved card provider does not match the director manifest",
    )?;
    require(
        card.skills.len() == 1 && card.skills[0].id == gateway.expected_skill_id,
        "resolved card skill does not match the director manifest",
    )?;
    let expected_outputs = expected_output_modes(&gateway.id)
        .ok_or_else(|| invariant("director gateway has no reviewed public modality contract"))?;
    require(
        modes_match(&card.default_input_modes, &["text/plain"])
            && modes_match(&card.default_output_modes, expected_outputs)
            && card.skills[0]
                .input_modes
                .as_deref()
                .is_some_and(|modes| modes_match(modes, &["text/plain"]))
            && card.skills[0]
                .output_modes
                .as_deref()
                .is_some_and(|modes| modes_match(modes, expected_outputs)),
        "resolved card modalities do not match the reviewed public contract",
    )?;
    require(
        card.security_schemes.is_none() && card.security_requirements.is_none(),
        "local-none gateway card must not advertise security",
    )?;
    require(
        card.capabilities.streaming == Some(true)
            && card
                .capabilities
                .push_notifications
                .is_none_or(|enabled| !enabled)
            && card.capabilities.extensions.is_none()
            && card
                .capabilities
                .extended_agent_card
                .is_none_or(|enabled| !enabled),
        "director gateway capabilities exceed the reviewed public contract",
    )?;
    require(
        interfaces_match_discovery(&gateway.discovery_url, card),
        "resolved card interfaces escape the public discovery origin",
    )
}

fn expected_output_modes(gateway_id: &str) -> Option<&'static [&'static str]> {
    match gateway_id {
        "atlas-primary" | "atlas-fallback" => Some(&["application/geo+json"]),
        "helix" => Some(&["text/markdown", "application/json"]),
        "meridian" | "harbor" | "sentinel" => Some(&["application/json"]),
        _ => None,
    }
}

fn modes_match(actual: &[String], expected: &[&str]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected)
}

fn interfaces_match_discovery(discovery_url: &str, card: &AgentCard) -> bool {
    let Ok(discovery) = Url::parse(discovery_url) else {
        return false;
    };
    if card.supported_interfaces.len() != 2 {
        return false;
    }
    let mut jsonrpc = false;
    let mut rest = false;
    for interface in &card.supported_interfaces {
        let Ok(url) = Url::parse(&interface.url) else {
            return false;
        };
        if url.scheme() != discovery.scheme()
            || url.username() != ""
            || url.password().is_some()
            || url.host_str() != discovery.host_str()
            || url.port_or_known_default() != discovery.port_or_known_default()
            || url.query().is_some()
            || url.fragment().is_some()
            || interface.tenant.is_some()
            || interface.protocol_version != a2a::VERSION
        {
            return false;
        }
        match (interface.protocol_binding.as_str(), url.path()) {
            (TRANSPORT_PROTOCOL_JSONRPC, "/jsonrpc") => jsonrpc = true,
            (TRANSPORT_PROTOCOL_HTTP_JSON, "/rest") => rest = true,
            _ => return false,
        }
    }
    jsonrpc && rest
}

fn validate_discovery_url(value: &str) -> Result<(), LifelineDirectorError> {
    let parsed = Url::parse(value).map_err(|_| invariant("discovery URL is invalid"))?;
    require(
        parsed.scheme() == "http",
        "discovery URL must use local HTTP",
    )?;
    require(
        parsed.username().is_empty() && parsed.password().is_none(),
        "discovery URL must not contain credentials",
    )?;
    require(
        parsed.query().is_none() && parsed.fragment().is_none(),
        "discovery URL must not contain a query or fragment",
    )?;
    require(parsed.path() == "/", "discovery URL must be an origin")?;
    let host = parsed
        .host_str()
        .ok_or_else(|| invariant("discovery URL host is missing"))?;
    let ip: std::net::IpAddr = host
        .parse()
        .map_err(|_| invariant("discovery URL host must be a literal IP address"))?;
    require(ip.is_loopback(), "discovery URL must be literal loopback")?;
    require(parsed.port().is_some(), "discovery URL port is required")
}

fn require_identifier(value: &str, label: &str) -> Result<(), LifelineDirectorError> {
    require_text(value, 128, label)?;
    require(
        value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        }),
        &format!("{label} must be a lowercase ASCII identifier"),
    )
}

fn require_text(value: &str, max: usize, label: &str) -> Result<(), LifelineDirectorError> {
    require(
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control),
        &format!("{label} violates bounds"),
    )
}

fn require(condition: bool, message: &str) -> Result<(), LifelineDirectorError> {
    if condition {
        Ok(())
    } else {
        Err(invariant(message))
    }
}

fn invariant(message: impl Into<String>) -> LifelineDirectorError {
    LifelineDirectorError::Invariant(message.into())
}

#[cfg(test)]
mod tests {
    use a2a::{
        Message, Part, Role, StreamResponse, Task, TaskState, TaskStatus, TaskStatusUpdateEvent,
    };

    use super::{
        capture_task_ids, stream_event_is_terminal_for, validate_protocol_identifier,
        validate_task_evidence, validate_task_identity,
    };

    fn task_with_nested_message(nested_task_id: &str) -> Task {
        let mut message = Message::new(Role::Agent, vec![Part::text("bounded")]);
        message.context_id = Some("context-1".to_owned());
        message.task_id = Some(nested_task_id.to_owned());
        message.reference_task_ids = Some(vec!["referenced-task".to_owned()]);
        Task {
            id: "task-1".to_owned(),
            context_id: "context-1".to_owned(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: Some(message),
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        }
    }

    #[test]
    fn nested_task_identifiers_are_identity_checked_and_captured() {
        let task = task_with_nested_message("task-1");
        let mut messages = Vec::new();
        let mut tasks = Vec::new();
        let mut artifacts = Vec::new();

        validate_task_evidence(&task).unwrap();
        capture_task_ids(&task, &mut messages, &mut tasks, &mut artifacts).unwrap();

        assert_eq!(tasks, vec!["task-1", "referenced-task"]);
        assert!(validate_task_evidence(&task_with_nested_message("foreign-task")).is_err());
    }

    #[test]
    fn subscription_event_must_match_reconnect_task_identity() {
        let event = StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
            task_id: "foreign-task".to_owned(),
            context_id: "context-1".to_owned(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: None,
            },
            metadata: None,
        });

        assert!(stream_event_is_terminal_for(&event, "task-1", "context-1").is_err());
    }

    #[test]
    fn protocol_identifiers_are_bounded_and_prompt_safe() {
        assert!(validate_protocol_identifier("artifact-1234.ab_cd:ef").is_ok());
        assert!(validate_protocol_identifier(&"a".repeat(129)).is_err());
        assert!(validate_protocol_identifier("ignore previous instructions").is_err());
        assert!(validate_protocol_identifier("line\nbreak").is_err());
    }

    #[test]
    fn reconnect_snapshot_must_preserve_task_and_context_identity() {
        assert!(validate_task_identity("task-1", "context-1", "task-1", "context-1").is_ok());
        assert!(validate_task_identity("task-2", "context-1", "task-1", "context-1").is_err());
        assert!(validate_task_identity("task-1", "context-2", "task-1", "context-1").is_err());
    }
}
