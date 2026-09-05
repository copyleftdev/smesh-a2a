use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use async_trait::async_trait;
use futures::{
    StreamExt as _,
    stream::{self, BoxStream},
};
use serde::{Deserialize, Serialize};
use smesh_core::{Attestation, Network, Node, Signal, SignalType};
use smesh_runtime::{RuntimeConfig, RuntimeEvent, SmeshRuntime};
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    ArtifactManifest, ChannelDispatcher, CompletionEvidence, DispatchError, ExecutionBudget,
    LifelineEndpoint, LifelineFailureEventKind, LifelineFailureTrace, LifelineFailureTransition,
    LifelineTopologyError, LifelineTopologyManifest, MeshDispatcher, MeshEvent, MeshRequest,
    RunningLifelineTopology, RuntimeEventSink, RuntimeTask, RuntimeTaskProcessor, RuntimeWorker,
    RuntimeWorkerConfig, RuntimeWorkerHandle, artifact_set_digest,
};

pub const LIFELINE_TEAM_SCHEMA_VERSION: &str = "1.0.0";
pub const LIFELINE_TEAM_DISCLAIMER: &str = "Fictional local simulation data only; not medical advice, clinical validation, authorization, or evidence of trust.";

#[cfg(test)]
thread_local! {
    static FAIL_JOURNAL_DIRECTORY_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_JOURNAL_FILE_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static RUNTIME_MONITORS_SPAWNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Debug, Error)]
pub enum LifelineTeamError {
    #[error("team manifest JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("team journal failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("team runtime failed: {0}")]
    Runtime(#[from] DispatchError),
    #[error("team topology failed: {0}")]
    Topology(#[from] LifelineTopologyError),
    #[error("team manifest invariant failed: {0}")]
    Invariant(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineTeamManifest {
    schema_version: String,
    fictional: bool,
    disclaimer: String,
    seed: u64,
    teams: Vec<LifelineTeam>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineTeam {
    id: String,
    organization: String,
    gateways: Vec<String>,
    roles: Vec<LifelineTeamRole>,
    tool: LifelineLocalTool,
    candidate: LifelineCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineTeamRole {
    id: String,
    concern: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineLocalTool {
    id: String,
    record_count: usize,
    records: Vec<String>,
    projection: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineCandidate {
    name: String,
    media_type: String,
}

#[derive(Clone)]
pub struct LifelineTeamDispatcher {
    inner: ChannelDispatcher,
    team_id: String,
    gateway_id: String,
    authority_roles: [String; 3],
    registry: Arc<Mutex<TeamTaskRegistry>>,
    runtime_trace: RuntimeTraceHealth,
    failure: Option<LifelineTeamFailureMode>,
}

pub struct RunningLifelineTeams {
    dispatchers: HashMap<String, LifelineTeamDispatcher>,
    organizations: HashMap<String, String>,
    journal_paths: HashMap<String, PathBuf>,
    runtime_trace_paths: HashMap<String, PathBuf>,
    journals: Vec<Arc<TeamJournal>>,
    runtime_monitors: Vec<RuntimeEventMonitor>,
    workers: Vec<RuntimeWorkerHandle>,
}

pub struct RunningLifelineTeamTopology {
    topology: RunningLifelineTopology,
    teams: RunningLifelineTeams,
}

struct TeamJournal {
    state: Mutex<TeamJournalState>,
    runtime_trace: bool,
}

struct RuntimeEventMonitor {
    stop: CancellationToken,
    join: Option<JoinHandle<Result<(), DispatchError>>>,
}

struct OwnedRuntimeMonitorTask(JoinHandle<Result<(), DispatchError>>);

impl Drop for OwnedRuntimeMonitorTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone)]
struct RuntimeTraceHealth {
    barriers: mpsc::Sender<oneshot::Sender<()>>,
    failed: Arc<AtomicBool>,
}

struct TeamJournalState {
    file: std::fs::File,
    sequence: u64,
    event_count: usize,
    byte_count: usize,
}

#[derive(Clone)]
struct LifelineTeamProcessor {
    team: LifelineTeam,
    seed: u64,
    journal: Arc<TeamJournal>,
    registry: Arc<Mutex<TeamTaskRegistry>>,
    runtime_trace: RuntimeTraceHealth,
    failure: Option<LifelineTeamFailureMode>,
}

#[derive(Default)]
struct TeamTaskRegistry {
    requests: HashMap<String, TeamRequestSubject>,
    outcomes: HashMap<(String, String), TeamOutcome>,
}

#[derive(Clone)]
#[allow(clippy::struct_field_names)]
struct TeamRequestSubject {
    task_id: String,
    context_id: String,
    gateway_id: String,
}

#[derive(Clone)]
pub struct LifelineTeamFailureMode {
    trace: LifelineFailureTrace,
    primary: Arc<Mutex<Option<FailurePrimaryBinding>>>,
    primary_bound: Arc<tokio::sync::Notify>,
    outage_emitted: Arc<AtomicBool>,
    outage_ready: Arc<tokio::sync::Notify>,
    internal_stopped: Arc<AtomicBool>,
    internal_stop_ready: Arc<tokio::sync::Notify>,
    public_cancel_confirmed: Arc<AtomicBool>,
    public_cancel_ready: Arc<tokio::sync::Notify>,
    primary_abandoned: Arc<AtomicBool>,
    primary_abandon_ready: Arc<tokio::sync::Notify>,
}

#[derive(Clone)]
#[allow(clippy::struct_field_names)]
struct FailurePrimaryBinding {
    operation_id: String,
    task_id: String,
    context_id: String,
    message_id: String,
}

#[derive(Clone)]
struct TeamOutcome {
    team_id: String,
    claim_hash: String,
    reinforcement_count: u32,
    attesters: Vec<String>,
    hypothesis_hash: String,
    contradiction_hash: String,
    tool_id: String,
    dataset_digest: String,
    candidate_digest: String,
    decayed: bool,
    authority_evidence: [AuthorityRuntimeEvidence; 3],
}

#[derive(Clone)]
struct AuthorityRuntimeEvidence {
    role: String,
    signal_hash: String,
    payload: serde_json::Value,
    attestation: Attestation,
}

impl LifelineTeamManifest {
    /// Parse the bounded fictional organization-team manifest.
    ///
    /// # Errors
    /// Returns an error when decoding or a closed team invariant fails.
    pub fn from_json(input: &str) -> Result<Self, LifelineTeamError> {
        if input.len() > 64 * 1024 {
            return Err(invariant("manifest exceeds 64 KiB"));
        }
        let manifest: Self = serde_json::from_str(input)?;
        manifest.validate_approved()?;
        Ok(manifest)
    }

    fn validate_approved(&self) -> Result<(), LifelineTeamError> {
        self.validate()?;
        let approved: Self = serde_json::from_str(include_str!("../deploy/lifeline-teams.json"))?;
        require(
            self == &approved,
            "manifest must match the reviewed LIFELINE team catalog",
        )
    }

    fn validate(&self) -> Result<(), LifelineTeamError> {
        require(
            self.schema_version == LIFELINE_TEAM_SCHEMA_VERSION,
            "unsupported schemaVersion",
        )?;
        require(self.fictional, "team data must be explicitly fictional")?;
        require(
            self.disclaimer == LIFELINE_TEAM_DISCLAIMER,
            "disclaimer must match the reviewed local-data boundary",
        )?;
        require(self.seed == 47, "the reviewed deterministic seed is 47")?;
        require(
            self.teams.len() == 5,
            "exactly five organization teams are required",
        )?;

        let mut team_ids = HashSet::new();
        let mut organizations = HashSet::new();
        let mut gateways = HashSet::new();
        for team in &self.teams {
            require_identifier(&team.id, "team id")?;
            require(team_ids.insert(team.id.as_str()), "team ids must be unique")?;
            require_text(&team.organization, 128, "organization")?;
            require(
                organizations.insert(team.organization.as_str()),
                "organizations must be unique",
            )?;
            require(
                !team.gateways.is_empty(),
                "team must own at least one gateway",
            )?;
            for gateway in &team.gateways {
                require_identifier(gateway, "gateway id")?;
                require(
                    gateways.insert(gateway.as_str()),
                    "gateway ownership must be unique",
                )?;
            }
            require(
                team.roles.len() >= 4,
                "team must define at least four roles",
            )?;
            let mut role_ids = HashSet::new();
            let mut concerns = HashSet::new();
            for role in &team.roles {
                require_identifier(&role.id, "role id")?;
                require_identifier(&role.concern, "role concern")?;
                require(role_ids.insert(role.id.as_str()), "role ids must be unique")?;
                require(
                    concerns.insert(role.concern.as_str()),
                    "role concerns must be non-overlapping",
                )?;
            }
            require_identifier(&team.tool.id, "tool id")?;
            require(team.tool.id.starts_with("local."), "tool must be local")?;
            require(
                (1..=32).contains(&team.tool.record_count)
                    && team.tool.record_count == team.tool.records.len(),
                "local tool record count violates bounds",
            )?;
            for record in &team.tool.records {
                require_text(record, 128, "local tool record")?;
            }
            require(
                serde_json::to_vec(&team.tool.records).is_ok_and(|bytes| bytes.len() <= 8 * 1024),
                "local tool dataset exceeds 8 KiB",
            )?;
            require(
                serde_json::to_vec(&team.tool.projection)
                    .is_ok_and(|bytes| bytes.len() <= 4 * 1024),
                "local tool projection exceeds 4 KiB",
            )?;
            require_identifier(&team.candidate.name, "candidate name")?;
            require_text(&team.candidate.media_type, 128, "candidate media type")?;
        }
        let expected = HashSet::from([
            "meridian",
            "atlas-primary",
            "atlas-fallback",
            "helix",
            "harbor",
            "sentinel",
        ]);
        require(
            gateways == expected,
            "gateway ownership must match LIFELINE topology",
        )
    }

    #[must_use]
    pub fn is_fictional(&self) -> bool {
        self.fictional
    }

    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }

    #[must_use]
    pub fn teams(&self) -> &[LifelineTeam] {
        &self.teams
    }

    /// Start one isolated real SMESH runtime per provider organization.
    ///
    /// # Errors
    /// Returns an error if private journal creation or runtime ownership setup fails.
    pub async fn launch(
        self,
        journal_root: impl AsRef<Path>,
    ) -> Result<RunningLifelineTeams, LifelineTeamError> {
        self.launch_with_failure(journal_root, None).await
    }

    /// Starts the reviewed Atlas-primary outage mode in the organization runtime.
    ///
    /// # Errors
    /// Returns an error if private journals or organization runtime ownership fail.
    pub async fn launch_failure(
        self,
        journal_root: impl AsRef<Path>,
        failure: LifelineTeamFailureMode,
    ) -> Result<RunningLifelineTeams, LifelineTeamError> {
        self.launch_with_failure(journal_root, Some(failure)).await
    }

    async fn launch_with_failure(
        self,
        journal_root: impl AsRef<Path>,
        failure: Option<LifelineTeamFailureMode>,
    ) -> Result<RunningLifelineTeams, LifelineTeamError> {
        self.validate_approved()?;
        let journal_root = journal_root.as_ref();
        prepare_private_journal_root(journal_root)?;
        preflight_team_journals(journal_root, &self.teams)?;
        let mut prepared_journals = HashMap::with_capacity(self.teams.len());
        for team in &self.teams {
            let journal_path = journal_root.join(format!("{}.jsonl", team.id));
            let journal = Arc::new(TeamJournal::create(&journal_path)?);
            let runtime_trace_path = journal_root.join(format!("{}.runtime.jsonl", team.id));
            let runtime_trace = Arc::new(TeamJournal::create_runtime(&runtime_trace_path)?);
            prepared_journals.insert(
                team.id.clone(),
                (journal_path, journal, runtime_trace_path, runtime_trace),
            );
        }
        sync_journal_directory(journal_root)?;
        let mut dispatchers = HashMap::new();
        let mut organizations = HashMap::new();
        let mut journal_paths = HashMap::new();
        let mut runtime_trace_paths = HashMap::new();
        let mut journals = Vec::with_capacity(self.teams.len() * 2);
        let mut runtime_monitors = Vec::with_capacity(self.teams.len());
        let mut workers = Vec::with_capacity(self.teams.len());

        for team in self.teams {
            let (journal_path, journal, runtime_trace_path, runtime_trace) = prepared_journals
                .remove(&team.id)
                .ok_or_else(|| invariant("prepared team journals are absent"))?;
            let gateway_node_id = format!("{}-gateway", team.id);
            let mut network = Network::new();
            network.add_node(Node::named(&gateway_node_id));
            for role in &team.roles {
                network.add_node(Node::named(format!("{}-{}", team.id, role.id)));
            }
            let mut runtime = SmeshRuntime::with_network(
                network,
                RuntimeConfig {
                    tick_interval_ms: 100,
                },
            );
            let runtime_events = runtime
                .take_events()
                .ok_or_else(|| invariant("organization runtime event stream is absent"))?;
            let (runtime_monitor, runtime_trace_health) =
                RuntimeEventMonitor::spawn(runtime_events, Arc::clone(&runtime_trace));
            let runtime = Arc::new(runtime);
            let registry = Arc::new(Mutex::new(TeamTaskRegistry::default()));
            let processor = LifelineTeamProcessor {
                team: team.clone(),
                seed: self.seed,
                journal: Arc::clone(&journal),
                registry: Arc::clone(&registry),
                runtime_trace: runtime_trace_health.clone(),
                failure: failure.clone(),
            };
            let (dispatcher, worker) = RuntimeWorker::spawn_with_config(
                runtime,
                gateway_node_id,
                processor,
                RuntimeWorkerConfig {
                    command_capacity: 8,
                    max_active_tasks: 2,
                    cancel_grace: Duration::from_secs(1),
                },
            )
            .await?;
            for gateway in &team.gateways {
                let team_dispatcher = LifelineTeamDispatcher {
                    inner: dispatcher.clone(),
                    team_id: team.id.clone(),
                    gateway_id: gateway.clone(),
                    authority_roles: [
                        team.roles[1].id.clone(),
                        team.roles[2].id.clone(),
                        team.roles[3].id.clone(),
                    ],
                    registry: Arc::clone(&registry),
                    runtime_trace: runtime_trace_health.clone(),
                    failure: failure.clone(),
                };
                dispatchers.insert(gateway.clone(), team_dispatcher);
                organizations.insert(gateway.clone(), team.organization.clone());
            }
            journal_paths.insert(team.id.clone(), journal_path);
            runtime_trace_paths.insert(team.id.clone(), runtime_trace_path);
            journals.push(journal);
            journals.push(runtime_trace);
            runtime_monitors.push(runtime_monitor);
            workers.push(worker);
        }

        Ok(RunningLifelineTeams {
            dispatchers,
            organizations,
            journal_paths,
            runtime_trace_paths,
            journals,
            runtime_monitors,
            workers,
        })
    }

    /// Start the six reviewed A2A gateways with five organization-scoped teams.
    ///
    /// # Errors
    /// Returns an error after cleaning up team workers if topology startup fails.
    pub async fn launch_topology(
        self,
        topology: LifelineTopologyManifest,
        journal_root: impl AsRef<Path>,
    ) -> Result<RunningLifelineTeamTopology, LifelineTeamError> {
        let teams = self.launch(journal_root).await?;
        launch_team_topology(topology, teams, None).await
    }

    /// Starts the reviewed topology with only the Atlas primary route faulted.
    ///
    /// # Errors
    /// Returns an error if the organization runtimes, trace, or gateway topology fail.
    pub async fn launch_failure_topology(
        self,
        topology: LifelineTopologyManifest,
        journal_root: impl AsRef<Path>,
        failure: LifelineTeamFailureMode,
    ) -> Result<RunningLifelineTeamTopology, LifelineTeamError> {
        let teams = self.launch_failure(journal_root, failure.clone()).await?;
        launch_team_topology(topology, teams, Some(failure)).await
    }
}

async fn launch_team_topology(
    topology: LifelineTopologyManifest,
    teams: RunningLifelineTeams,
    failure: Option<LifelineTeamFailureMode>,
) -> Result<RunningLifelineTeamTopology, LifelineTeamError> {
    let dispatchers = teams.dispatchers.clone();
    let launched = match failure {
        Some(failure) => {
            topology
                .launch_with_failure_dispatchers(dispatchers, failure)
                .await
        }
        None => topology.launch_with_dispatchers(dispatchers).await,
    };
    match launched {
        Ok(topology) => Ok(RunningLifelineTeamTopology { topology, teams }),
        Err(error) => {
            let cleanup = teams.shutdown().await;
            cleanup?;
            Err(error.into())
        }
    }
}

impl LifelineTeamFailureMode {
    #[must_use]
    pub fn new(trace: LifelineFailureTrace) -> Self {
        Self {
            trace,
            primary: Arc::new(Mutex::new(None)),
            primary_bound: Arc::new(tokio::sync::Notify::new()),
            outage_emitted: Arc::new(AtomicBool::new(false)),
            outage_ready: Arc::new(tokio::sync::Notify::new()),
            internal_stopped: Arc::new(AtomicBool::new(false)),
            internal_stop_ready: Arc::new(tokio::sync::Notify::new()),
            public_cancel_confirmed: Arc::new(AtomicBool::new(false)),
            public_cancel_ready: Arc::new(tokio::sync::Notify::new()),
            primary_abandoned: Arc::new(AtomicBool::new(false)),
            primary_abandon_ready: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub(crate) fn trace(&self) -> LifelineFailureTrace {
        self.trace.clone()
    }

    /// Binds the official A2A primary identity before releasing the outage processor.
    ///
    /// # Errors
    /// Returns an error if the binding lock fails or a primary was already bound.
    pub fn bind_primary(
        &self,
        operation_id: &str,
        task_id: &str,
        context_id: &str,
        message_id: &str,
    ) -> Result<(), LifelineTeamError> {
        let mut primary = self
            .primary
            .lock()
            .map_err(|_| invariant("failure binding lock poisoned"))?;
        if primary.is_some() {
            return Err(invariant("failure primary identity was already bound"));
        }
        *primary = Some(FailurePrimaryBinding {
            operation_id: operation_id.to_owned(),
            task_id: task_id.to_owned(),
            context_id: context_id.to_owned(),
            message_id: message_id.to_owned(),
        });
        drop(primary);
        self.primary_bound.notify_waiters();
        Ok(())
    }

    async fn primary_binding(&self) -> Result<FailurePrimaryBinding, DispatchError> {
        loop {
            let notified = self.primary_bound.notified();
            if let Some(binding) = self
                .primary
                .lock()
                .map_err(|_| DispatchError::message("failure binding lock poisoned"))?
                .clone()
            {
                return Ok(binding);
            }
            notified.await;
        }
    }

    pub(crate) async fn wait_for_outage_signal(&self) {
        loop {
            let notified = self.outage_ready.notified();
            if self.outage_emitted.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn mark_public_cancel_confirmed(&self) {
        self.public_cancel_confirmed.store(true, Ordering::SeqCst);
        self.public_cancel_ready.notify_waiters();
    }

    pub(crate) async fn wait_for_public_cancel_signal(&self) {
        loop {
            let notified = self.public_cancel_ready.notified();
            if self.public_cancel_confirmed.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn abandon_primary(&self) {
        self.primary_abandoned.store(true, Ordering::SeqCst);
        self.primary_abandon_ready.notify_waiters();
    }

    pub(crate) async fn wait_for_primary_abandonment(&self) {
        loop {
            let notified = self.primary_abandon_ready.notified();
            if self.primary_abandoned.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

impl LifelineTeam {
    #[must_use]
    pub fn roles(&self) -> &[LifelineTeamRole] {
        &self.roles
    }

    #[must_use]
    pub fn gateways(&self) -> &[String] {
        &self.gateways
    }

    #[must_use]
    pub fn tool(&self) -> &LifelineLocalTool {
        &self.tool
    }
}

impl LifelineTeamRole {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn concern(&self) -> &str {
        &self.concern
    }
}

impl LifelineLocalTool {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.record_count
    }
}

#[async_trait]
impl RuntimeTaskProcessor for LifelineTeamProcessor {
    #[allow(clippy::too_many_lines)] // One linear real-runtime trace keeps ordering and failure propagation auditable.
    async fn process(
        &self,
        task: RuntimeTask,
        cancellation: CancellationToken,
        events: RuntimeEventSink,
    ) -> Result<(), DispatchError> {
        if cancellation.is_cancelled() {
            return Err(DispatchError::message("organization team task canceled"));
        }
        let runtime_task_id = task.request.task_id.clone();
        let subject = self
            .registry
            .lock()
            .map_err(|_| DispatchError::message("team task registry lock poisoned"))?
            .requests
            .get(&runtime_task_id)
            .cloned()
            .ok_or_else(|| DispatchError::message("organization task subject is absent"))?;
        self.runtime_trace.verify().await?;
        self.journal.record(
            "query_retained",
            &serde_json::json!({
                "organization": self.team.organization,
                "task_id": subject.task_id,
                "context_id": subject.context_id,
                "signal_hash": task.signal_hash,
            }),
        )?;
        if subject.gateway_id == "atlas-primary"
            && let Some(failure) = &self.failure
        {
            let binding = failure.primary_binding().await?;
            if binding.task_id != subject.task_id || binding.context_id != subject.context_id {
                return Err(DispatchError::message(
                    "failure primary binding does not match runtime subject",
                ));
            }
            failure
                .trace
                .record(LifelineFailureTransition {
                    kind: LifelineFailureEventKind::PrimaryOutageObserved,
                    operation_id: &binding.operation_id,
                    gateway_id: &subject.gateway_id,
                    context_id: &binding.context_id,
                    task_id: Some(&binding.task_id),
                    message_id: Some(&binding.message_id),
                    attempt: 1,
                    outcome: "unavailable",
                    replaces_task_id: None,
                })
                .map_err(|error| DispatchError::message(error.to_string()))?;
            events.progress("atlas primary route unavailable").await?;
            failure.outage_emitted.store(true, Ordering::SeqCst);
            failure.outage_ready.notify_waiters();
            cancellation.cancelled().await;
            let artifact_fenced = events
                .artifact("late-primary.json", "application/json", "{}")
                .await
                .is_err();
            let completion_fenced = events
                .propose_completion("late primary completion")
                .await
                .is_err();
            if !(artifact_fenced && completion_fenced) {
                return Err(DispatchError::message(
                    "late primary output escaped cancellation fence",
                ));
            }
            failure
                .trace
                .record(LifelineFailureTransition {
                    kind: LifelineFailureEventKind::LateOutputFenced,
                    operation_id: &binding.operation_id,
                    gateway_id: &subject.gateway_id,
                    context_id: &binding.context_id,
                    task_id: Some(&binding.task_id),
                    message_id: Some(&binding.message_id),
                    attempt: 1,
                    outcome: "fenced",
                    replaces_task_id: None,
                })
                .map_err(|error| DispatchError::message(error.to_string()))?;
            return Ok(());
        }
        let first = self
            .team
            .roles
            .first()
            .ok_or_else(|| DispatchError::message("organization team has no claim owner"))?;
        let second = self
            .team
            .roles
            .get(1)
            .ok_or_else(|| DispatchError::message("organization team has no reinforcer"))?;
        let first_score =
            deterministic_affinity(self.seed, &self.team.id, &runtime_task_id, &first.id) * 2 + 1;
        let second_score =
            deterministic_affinity(self.seed, &self.team.id, &runtime_task_id, &second.id) * 2;
        let (owner, owner_score, reinforcer, loser_score) = if first_score > second_score {
            (first, first_score, second, second_score)
        } else {
            (second, second_score, first, first_score)
        };
        for (role, score) in [(first, first_score), (second, second_score)] {
            self.journal.record(
                "task_claimed",
                &serde_json::json!({
                    "organization": self.team.organization,
                    "role": role.id,
                    "score": score,
                    "seed": self.seed,
                    "task_id": subject.task_id,
                    "context_id": subject.context_id,
                }),
            )?;
        }
        self.journal.record(
            "task_backed_off",
            &serde_json::json!({
                "organization": self.team.organization,
                "role": reinforcer.id,
                "winner_role": owner.id,
                "winner_score": owner_score,
                "loser_score": loser_score,
                "seed": self.seed,
                "task_id": subject.task_id,
                "context_id": subject.context_id,
            }),
        )?;

        let claim_payload = serde_json::json!({
            "fictional": true,
            "organization": self.team.organization,
            "tool": self.team.tool.id,
            "record_count": self.team.tool.record_count,
            "task_id": subject.task_id,
            "context_id": subject.context_id,
            "dispatch_scope": runtime_task_id,
            "claim": "bounded local evidence supports the organization candidate",
        });
        let owner_node = format!("{}-{}", self.team.id, owner.id);
        let reinforcer_node = format!("{}-{}", self.team.id, reinforcer.id);
        let claim = || {
            Signal::builder(SignalType::Response)
                .payload_json(&claim_payload)
                .correlatable()
                .ttl(60.0)
                .build()
        };
        let claim_hash = task
            .runtime
            .emit(claim(), &owner_node)
            .await
            .ok_or_else(|| DispatchError::message("claim owner is absent from team runtime"))?;
        let reinforced_hash = task
            .runtime
            .emit(claim(), &reinforcer_node)
            .await
            .ok_or_else(|| DispatchError::message("reinforcer is absent from team runtime"))?;
        if reinforced_hash != claim_hash {
            return Err(DispatchError::message(
                "independent specialists did not converge on one claim",
            ));
        }
        let (reinforcement_count, attesters) = {
            let network = task.runtime.network();
            let network = network.read().await;
            network
                .field
                .signals
                .get(&claim_hash)
                .map(|signal| (signal.reinforcement_count, signal.verified_attesters()))
                .ok_or_else(|| DispatchError::message("reinforced claim is absent"))?
        };
        if reinforcement_count == 0 || attesters.len() < 2 {
            return Err(DispatchError::message(
                "claim lacks independent verified reinforcement",
            ));
        }
        self.journal.record(
            "signal_reinforced",
            &serde_json::json!({
                "organization": self.team.organization,
                "role": reinforcer.id,
                "task_id": subject.task_id,
                "context_id": subject.context_id,
                "signal_hash": claim_hash,
                "reinforcement_count": reinforcement_count,
                "attesters": attesters,
            }),
        )?;
        let hypothesis_owner =
            self.team.roles.get(2).ok_or_else(|| {
                DispatchError::message("organization team has no hypothesis role")
            })?;
        let challenger = self
            .team
            .roles
            .get(3)
            .ok_or_else(|| DispatchError::message("organization team has no challenger"))?;
        let hypothesis = Signal::builder(SignalType::Alert)
            .payload_json(&serde_json::json!({
                "fictional": true,
                "organization": self.team.organization,
                "task_id": subject.task_id,
                "context_id": subject.context_id,
                "dispatch_scope": runtime_task_id,
                "hypothesis": "all-lots-everywhere",
                "support": "none",
            }))
            .correlatable()
            .ttl(0.01)
            .build();
        let hypothesis_hash = task
            .runtime
            .emit(
                hypothesis,
                &format!("{}-{}", self.team.id, hypothesis_owner.id),
            )
            .await
            .ok_or_else(|| DispatchError::message("hypothesis role is absent from team runtime"))?;
        let contradiction = Signal::builder(SignalType::Response)
            .payload_json(&serde_json::json!({
                "fictional": true,
                "organization": self.team.organization,
                "contradicts_signal_hash": hypothesis_hash,
                "reason": "the bounded local dataset does not support this hypothesis",
            }))
            .ttl(60.0)
            .build();
        let contradiction_hash = task
            .runtime
            .emit(
                contradiction,
                &format!("{}-{}", self.team.id, challenger.id),
            )
            .await
            .ok_or_else(|| DispatchError::message("challenger is absent from team runtime"))?;
        {
            let network = task.runtime.network();
            let network = network.read().await;
            let contradiction = network
                .field
                .signals
                .get(&contradiction_hash)
                .ok_or_else(|| DispatchError::message("contradiction signal is absent"))?;
            let payload: serde_json::Value = serde_json::from_slice(&contradiction.payload)
                .map_err(|_| DispatchError::message("contradiction payload is invalid"))?;
            if payload["contradicts_signal_hash"] != hypothesis_hash
                || contradiction.verified_attesters().len() != 1
            {
                return Err(DispatchError::message(
                    "runtime contradiction is not bound to the unsupported hypothesis",
                ));
            }
        }
        self.journal.record(
            "signal_contradicted",
            &serde_json::json!({
                "organization": self.team.organization,
                "role": challenger.id,
                "task_id": subject.task_id,
                "context_id": subject.context_id,
                "hypothesis_hash": hypothesis_hash,
                "contradiction_hash": contradiction_hash,
            }),
        )?;
        let mut removed_from_active = false;
        let mut retained_in_history = false;
        for _ in 0..128 {
            task.runtime.tick().await;
            let network = task.runtime.network();
            let network = network.read().await;
            removed_from_active = !network.field.signals.contains_key(&hypothesis_hash);
            retained_in_history = network
                .field
                .signal_history
                .iter()
                .any(|(_, signal)| signal.origin_hash == hypothesis_hash);
            if removed_from_active && retained_in_history {
                break;
            }
        }
        if !(removed_from_active && retained_in_history) {
            return Err(DispatchError::message(
                "unsupported hypothesis did not decay into runtime history",
            ));
        }
        self.journal.record(
            "signal_decayed",
            &serde_json::json!({
                "organization": self.team.organization,
                "role": hypothesis_owner.id,
                "task_id": subject.task_id,
                "context_id": subject.context_id,
                "signal_hash": hypothesis_hash,
                "removed_from_active": removed_from_active,
                "retained_in_history": retained_in_history,
            }),
        )?;
        self.journal.record(
            "tool_called",
            &serde_json::json!({
                "organization": self.team.organization,
                "role": owner.id,
                "tool_id": self.team.tool.id,
                "task_id": subject.task_id,
                "context_id": subject.context_id,
                "seed": self.seed,
            }),
        )?;
        let dataset_bytes = serde_json::to_vec(&self.team.tool.records)
            .map_err(|_| DispatchError::message("local tool dataset serialization failed"))?;
        let dataset_digest = crate::content_digest(&dataset_bytes);
        self.journal.record(
            "tool_completed",
            &serde_json::json!({
                "organization": self.team.organization,
                "role": owner.id,
                "tool_id": self.team.tool.id,
                "task_id": subject.task_id,
                "context_id": subject.context_id,
                "dataset_digest": dataset_digest,
                "record_count": self.team.tool.record_count,
            }),
        )?;
        let candidate = serde_json::json!({
            "schemaVersion": "lifeline-team-candidate/1",
            "fictional": true,
            "disclaimer": LIFELINE_TEAM_DISCLAIMER,
            "organization": self.team.organization,
            "toolId": self.team.tool.id,
            "recordCount": self.team.tool.record_count,
            "datasetDigest": dataset_digest,
            "claimSignalHash": claim_hash,
            "taskId": subject.task_id,
            "contextId": subject.context_id,
            "result": self.team.tool.projection,
        });
        let content = serde_json::to_string(&candidate)
            .map_err(|_| DispatchError::message("candidate serialization failed"))?;
        if content.len() > 8 * 1024 {
            return Err(DispatchError::message(
                "organization candidate exceeds 8 KiB",
            ));
        }
        let candidate_digest = crate::content_digest(content.as_bytes());
        self.journal.record(
            "candidate_built",
            &serde_json::json!({
                "organization": self.team.organization,
                "role": owner.id,
                "task_id": subject.task_id,
                "context_id": subject.context_id,
                "name": self.team.candidate.name,
                "media_type": self.team.candidate.media_type,
                "bytes": content.len(),
                "digest": candidate_digest,
            }),
        )?;
        let subject_digest = artifact_set_digest(&[ArtifactManifest {
            name: self.team.candidate.name.clone(),
            media_type: self.team.candidate.media_type.clone(),
            digest: candidate_digest.clone(),
        }])
        .map_err(|error| DispatchError::message(error.to_string()))?;
        let authority_evidence = [
            emit_authority_signal(
                task.runtime.as_ref(),
                &self.team.id,
                &self.team.roles[1].id,
                &subject_digest,
                serde_json::json!({
                    "kind": "review",
                    "claimHash": claim_hash,
                    "reinforcementCount": reinforcement_count,
                    "attesters": attesters,
                }),
            )
            .await?,
            emit_authority_signal(
                task.runtime.as_ref(),
                &self.team.id,
                &self.team.roles[2].id,
                &subject_digest,
                serde_json::json!({
                    "kind": "test",
                    "toolId": self.team.tool.id,
                    "datasetDigest": dataset_digest,
                    "candidateDigest": candidate_digest,
                }),
            )
            .await?,
            emit_authority_signal(
                task.runtime.as_ref(),
                &self.team.id,
                &self.team.roles[3].id,
                &subject_digest,
                serde_json::json!({
                    "kind": "contradiction-clearance",
                    "hypothesisHash": hypothesis_hash,
                    "contradictionHash": contradiction_hash,
                    "decayed": removed_from_active && retained_in_history,
                }),
            )
            .await?,
        ];
        let outcome_key = (runtime_task_id.clone(), subject.context_id.clone());
        let outcome = TeamOutcome {
            team_id: self.team.id.clone(),
            claim_hash,
            reinforcement_count,
            attesters,
            hypothesis_hash,
            contradiction_hash,
            tool_id: self.team.tool.id.clone(),
            dataset_digest,
            candidate_digest,
            decayed: removed_from_active && retained_in_history,
            authority_evidence,
        };
        self.runtime_trace.verify().await?;
        {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| DispatchError::message("team task registry lock poisoned"))?;
            if registry
                .requests
                .get(&runtime_task_id)
                .is_none_or(|active| active.context_id != subject.context_id)
            {
                return Err(DispatchError::message(
                    "organization task consumer is no longer active",
                ));
            }
            registry.outcomes.insert(outcome_key, outcome);
        }
        events
            .progress("organization-local SMESH claim was reinforced")
            .await?;
        events
            .artifact(
                self.team.candidate.name.clone(),
                self.team.candidate.media_type.clone(),
                content,
            )
            .await?;
        events
            .propose_completion("organization team proposed bounded candidate completion")
            .await
    }
}

async fn emit_authority_signal(
    runtime: &SmeshRuntime,
    team_id: &str,
    role: &str,
    subject_digest: &str,
    assertion: serde_json::Value,
) -> Result<AuthorityRuntimeEvidence, DispatchError> {
    let payload = serde_json::json!({
        "schemaVersion": "lifeline-runtime-authority-claim/1",
        "teamId": team_id,
        "role": role,
        "subjectDigest": subject_digest,
        "assertion": assertion,
    });
    let signal = Signal::builder(SignalType::Response)
        .payload_json(&payload)
        .ttl(60.0)
        .build();
    let expected_hash = signal.origin_hash.clone();
    let node_id = format!("{team_id}-{role}");
    let signal_hash = runtime
        .emit(signal, &node_id)
        .await
        .ok_or_else(|| DispatchError::message("authority role is absent from team runtime"))?;
    if signal_hash != expected_hash {
        return Err(DispatchError::message(
            "authority runtime signal hash changed during emission",
        ));
    }
    let attestation = {
        let network = runtime.network();
        let network = network.read().await;
        let signal = network
            .field
            .signals
            .get(&signal_hash)
            .ok_or_else(|| DispatchError::message("authority runtime signal is absent"))?;
        signal
            .attestations
            .iter()
            .find(|attestation| attestation.node_id == node_id && attestation.verify(&signal_hash))
            .cloned()
            .ok_or_else(|| DispatchError::message("authority runtime signature is absent"))?
    };
    Ok(AuthorityRuntimeEvidence {
        role: role.to_owned(),
        signal_hash,
        payload,
        attestation,
    })
}

struct TeamEvidenceState {
    inner: BoxStream<'static, Result<MeshEvent, DispatchError>>,
    pending: VecDeque<Result<MeshEvent, DispatchError>>,
    artifact: Option<(String, String, String)>,
    team_id: String,
    authority_roles: [String; 3],
    outcome_key: (String, String),
    registry: Arc<Mutex<TeamTaskRegistry>>,
    request_id: String,
    runtime_trace: RuntimeTraceHealth,
    finished: bool,
}

impl Drop for TeamEvidenceState {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.outcomes.remove(&self.outcome_key);
            registry.requests.remove(&self.request_id);
        }
    }
}

#[async_trait]
impl MeshDispatcher for LifelineTeamDispatcher {
    fn dispatch(
        &self,
        request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let (request, outcome_key) = match self.scope_request(request) {
            Ok(value) => value,
            Err(error) => return Box::pin(stream::once(async move { Err(error) })),
        };
        let inner = self.inner.dispatch(request);
        self.with_evidence(inner, outcome_key)
    }

    fn dispatch_bounded(
        &self,
        request: MeshRequest,
        budget: ExecutionBudget,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let (request, outcome_key) = match self.scope_request(request) {
            Ok(value) => value,
            Err(error) => return Box::pin(stream::once(async move { Err(error) })),
        };
        let inner = self.inner.dispatch_bounded(request, budget);
        self.with_evidence(inner, outcome_key)
    }

    async fn cancel(&self, task_id: &str) -> Result<(), DispatchError> {
        self.inner
            .cancel(&scoped_task_id(&self.gateway_id, task_id))
            .await?;
        if self.gateway_id == "atlas-primary"
            && let Some(failure) = &self.failure
        {
            let binding = failure
                .primary
                .lock()
                .map_err(|_| DispatchError::message("failure binding lock poisoned"))?
                .clone()
                .ok_or_else(|| DispatchError::message("failure primary binding is missing"))?;
            if binding.task_id != task_id {
                return Err(DispatchError::message(
                    "failure cancellation identity does not match the primary",
                ));
            }
            failure
                .trace
                .record(LifelineFailureTransition {
                    kind: LifelineFailureEventKind::InternalProcessorStopped,
                    operation_id: &binding.operation_id,
                    gateway_id: &self.gateway_id,
                    context_id: &binding.context_id,
                    task_id: Some(&binding.task_id),
                    message_id: Some(&binding.message_id),
                    attempt: 1,
                    outcome: "cooperative-stop",
                    replaces_task_id: None,
                })
                .map_err(|error| DispatchError::message(error.to_string()))?;
            failure.internal_stopped.store(true, Ordering::SeqCst);
            failure.internal_stop_ready.notify_waiters();
        }
        Ok(())
    }
}

impl LifelineTeamDispatcher {
    fn scope_request(
        &self,
        mut request: MeshRequest,
    ) -> Result<(MeshRequest, (String, String)), DispatchError> {
        let outer = TeamRequestSubject {
            task_id: request.task_id.clone(),
            context_id: request.context_id.clone(),
            gateway_id: self.gateway_id.clone(),
        };
        let internal_task_id = scoped_task_id(&self.gateway_id, &request.task_id);
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| DispatchError::message("team task registry lock poisoned"))?;
        if let std::collections::hash_map::Entry::Vacant(entry) =
            registry.requests.entry(internal_task_id.clone())
        {
            entry.insert(outer);
        } else {
            return Err(DispatchError::message(
                "gateway already owns this organization task identity",
            ));
        }
        drop(registry);
        request.task_id.clone_from(&internal_task_id);
        let context_id = request.context_id.clone();
        Ok((request, (internal_task_id, context_id)))
    }

    #[allow(clippy::too_many_lines)] // Stream policy is one ordered artifact/outcome/evidence state machine.
    fn with_evidence(
        &self,
        inner: BoxStream<'static, Result<MeshEvent, DispatchError>>,
        outcome_key: (String, String),
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let state = TeamEvidenceState {
            inner,
            pending: VecDeque::new(),
            artifact: None,
            team_id: self.team_id.clone(),
            authority_roles: self.authority_roles.clone(),
            outcome_key: outcome_key.clone(),
            registry: Arc::clone(&self.registry),
            request_id: outcome_key.0,
            runtime_trace: self.runtime_trace.clone(),
            finished: false,
        };
        Box::pin(stream::unfold(state, |mut state| async move {
            if let Some(event) = state.pending.pop_front() {
                if matches!(event, Ok(MeshEvent::Completed { .. }))
                    && let Err(error) = state.runtime_trace.ensure_healthy()
                {
                    state.finished = true;
                    state.pending.clear();
                    return Some((Err(error), state));
                }
                return Some((event, state));
            }
            if state.finished {
                return None;
            }
            match state.inner.next().await {
                Some(Ok(event @ (MeshEvent::Progress(_) | MeshEvent::Evidence(_)))) => {
                    Some((Ok(event), state))
                }
                Some(Ok(event @ MeshEvent::Artifact { .. })) => {
                    let MeshEvent::Artifact {
                        name,
                        media_type,
                        content,
                    } = &event
                    else {
                        unreachable!()
                    };
                    if state.artifact.is_some() {
                        state.finished = true;
                        return Some((
                            Err(DispatchError::message(
                                "organization team emitted multiple candidate artifacts",
                            )),
                            state,
                        ));
                    }
                    state.artifact = Some((name.clone(), media_type.clone(), content.clone()));
                    Some((Ok(event), state))
                }
                Some(Ok(completion @ MeshEvent::Completed { .. })) => {
                    let Some((name, media_type, content)) = state.artifact.as_ref() else {
                        state.finished = true;
                        return Some((
                            Err(DispatchError::message(
                                "organization team completed without a candidate artifact",
                            )),
                            state,
                        ));
                    };
                    let subject_digest = match artifact_set_digest(&[ArtifactManifest {
                        name: name.clone(),
                        media_type: media_type.clone(),
                        digest: crate::content_digest(content.as_bytes()),
                    }]) {
                        Ok(value) => value,
                        Err(error) => {
                            state.finished = true;
                            return Some((Err(DispatchError::message(error.to_string())), state));
                        }
                    };
                    let registry = Arc::clone(&state.registry);
                    let outcome = match take_team_outcome(&registry, &state.outcome_key) {
                        Ok(outcome) => outcome,
                        Err(error) => {
                            state.finished = true;
                            return Some((Err(error), state));
                        }
                    };
                    let Some(outcome) = outcome else {
                        state.finished = true;
                        return Some((
                            Err(DispatchError::message(
                                "organization team completion lacks runtime outcome",
                            )),
                            state,
                        ));
                    };
                    if outcome.team_id != state.team_id
                        || outcome.candidate_digest != crate::content_digest(content.as_bytes())
                        || !outcome.decayed
                    {
                        state.finished = true;
                        return Some((
                            Err(DispatchError::message(
                                "organization team outcome does not match completion subject",
                            )),
                            state,
                        ));
                    }
                    let evidence = match build_team_evidence(
                        &state.team_id,
                        &state.authority_roles,
                        &subject_digest,
                        &outcome,
                    ) {
                        Ok(evidence) => evidence,
                        Err(error) => {
                            state.finished = true;
                            return Some((Err(error), state));
                        }
                    };
                    for evidence in evidence {
                        state.pending.push_back(Ok(MeshEvent::Evidence(evidence)));
                    }
                    state.pending.push_back(Ok(completion));
                    state.finished = true;
                    state.pending.pop_front().map(|event| (event, state))
                }
                Some(Err(error)) => {
                    state.finished = true;
                    Some((Err(error), state))
                }
                None => {
                    state.finished = true;
                    Some((
                        Err(DispatchError::message(
                            "organization team stream ended without completion",
                        )),
                        state,
                    ))
                }
            }
        }))
    }
}

fn take_team_outcome(
    registry: &Arc<Mutex<TeamTaskRegistry>>,
    key: &(String, String),
) -> Result<Option<TeamOutcome>, DispatchError> {
    registry
        .lock()
        .map_err(|_| DispatchError::message("team task registry lock poisoned"))
        .map(|mut registry| registry.outcomes.remove(key))
}

fn build_team_evidence(
    team_id: &str,
    roles: &[String; 3],
    subject_digest: &str,
    outcome: &TeamOutcome,
) -> Result<[CompletionEvidence; 3], DispatchError> {
    let make_id = |kind: &str| {
        let digest =
            crate::content_digest(format!("{team_id}\0{kind}\0{subject_digest}").as_bytes());
        format!("{team_id}-{kind}-{}", &digest[7..23])
    };
    let mut payloads = Vec::with_capacity(3);
    for (authority, expected_role) in outcome.authority_evidence.iter().zip(roles) {
        if &authority.role != expected_role
            || authority.payload["teamId"] != team_id
            || authority.payload["role"] != *expected_role
            || authority.payload["subjectDigest"] != subject_digest
            || !authority.attestation.verify(&authority.signal_hash)
            || authority.attestation.node_id != format!("{team_id}-{expected_role}")
        {
            return Err(DispatchError::message(
                "organization authority evidence is not runtime-signed for this subject",
            ));
        }
        payloads.push(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": "lifeline-runtime-authority-evidence/1",
                "teamId": team_id,
                "role": expected_role,
                "subjectDigest": subject_digest,
                "assertion": authority.payload["assertion"],
                "runtimeSignalHash": authority.signal_hash,
                "runtimeAttestation": authority.attestation,
            }))
            .map_err(|_| DispatchError::message("authority evidence serialization failed"))?,
        );
    }
    let [review_authority, test_authority, contradiction_authority] = &outcome.authority_evidence;
    if review_authority.payload["assertion"]["claimHash"] != outcome.claim_hash
        || review_authority.payload["assertion"]["reinforcementCount"]
            != outcome.reinforcement_count
        || review_authority.payload["assertion"]["attesters"]
            != serde_json::json!(outcome.attesters)
        || test_authority.payload["assertion"]["toolId"] != outcome.tool_id
        || test_authority.payload["assertion"]["datasetDigest"] != outcome.dataset_digest
        || test_authority.payload["assertion"]["candidateDigest"] != outcome.candidate_digest
        || contradiction_authority.payload["assertion"]["hypothesisHash"] != outcome.hypothesis_hash
        || contradiction_authority.payload["assertion"]["contradictionHash"]
            != outcome.contradiction_hash
        || contradiction_authority.payload["assertion"]["decayed"] != outcome.decayed
    {
        return Err(DispatchError::message(
            "runtime authority assertions do not match the organization outcome",
        ));
    }
    let [review, test, contradiction]: [Vec<u8>; 3] = payloads
        .try_into()
        .map_err(|_| DispatchError::message("authority evidence set is incomplete"))?;
    Ok([
        CompletionEvidence::Review {
            id: make_id("review"),
            issuer: "review-authority".to_owned(),
            subject_digest: subject_digest.to_owned(),
            evidence_digest: crate::content_digest(&review),
            evidence: review,
            approved: true,
            assurance_bps: 9_000,
        },
        CompletionEvidence::Test {
            id: make_id("test"),
            issuer: "test-authority".to_owned(),
            subject_digest: subject_digest.to_owned(),
            evidence_digest: crate::content_digest(&test),
            evidence: test,
            passed: true,
            assurance_bps: 9_000,
        },
        CompletionEvidence::Contradiction {
            id: make_id("contradiction"),
            issuer: "contradiction-monitor".to_owned(),
            subject_digest: subject_digest.to_owned(),
            evidence_digest: crate::content_digest(&contradiction),
            evidence: contradiction,
            blocking: false,
        },
    ])
}

impl RunningLifelineTeamTopology {
    #[must_use]
    pub fn endpoints(&self) -> &[LifelineEndpoint] {
        self.topology.endpoints()
    }

    #[must_use]
    pub fn journal_path(&self, team_id: &str) -> Option<&Path> {
        self.teams.journal_path(team_id)
    }

    /// Stop listeners first, then stop organization workers and sync journals.
    ///
    /// # Errors
    /// Returns the first shutdown error after attempting both ownership layers.
    pub async fn shutdown(self) -> Result<(), LifelineTeamError> {
        let topology_result = self.topology.shutdown().await;
        let teams_result = self.teams.shutdown().await;
        topology_result?;
        teams_result
    }
}

impl RunningLifelineTeams {
    #[must_use]
    pub fn dispatcher_for_gateway(&self, gateway_id: &str) -> Option<LifelineTeamDispatcher> {
        self.dispatchers.get(gateway_id).cloned()
    }

    #[must_use]
    pub fn organization_for_gateway(&self, gateway_id: &str) -> Option<&str> {
        self.organizations.get(gateway_id).map(String::as_str)
    }

    #[must_use]
    pub fn journal_path(&self, team_id: &str) -> Option<&Path> {
        self.journal_paths.get(team_id).map(PathBuf::as_path)
    }

    #[must_use]
    pub fn runtime_trace_path(&self, team_id: &str) -> Option<&Path> {
        self.runtime_trace_paths.get(team_id).map(PathBuf::as_path)
    }

    /// Stop and join every organization worker.
    ///
    /// # Errors
    /// Returns the first worker shutdown failure after attempting all workers.
    pub async fn shutdown(self) -> Result<(), LifelineTeamError> {
        let mut first_error: Option<LifelineTeamError> = None;
        for worker in self.workers {
            if let Err(error) = worker.shutdown().await
                && first_error.is_none()
            {
                first_error = Some(error.into());
            }
        }
        for monitor in self.runtime_monitors {
            if let Err(error) = monitor.shutdown().await
                && first_error.is_none()
            {
                first_error = Some(error.into());
            }
        }
        for journal in self.journals {
            if let Err(error) = journal.sync()
                && first_error.is_none()
            {
                first_error = Some(error.into());
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn preflight_team_journals(
    journal_root: &Path,
    teams: &[LifelineTeam],
) -> Result<(), LifelineTeamError> {
    for team in teams {
        for path in [
            journal_root.join(format!("{}.jsonl", team.id)),
            journal_root.join(format!("{}.runtime.jsonl", team.id)),
        ] {
            if path.try_exists()? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("team journal already exists: {}", path.display()),
                )
                .into());
            }
        }
    }
    Ok(())
}

#[allow(clippy::verbose_bit_mask)] // POSIX group/other permission bits are clearest in octal.
fn prepare_private_journal_root(path: &Path) -> Result<(), LifelineTeamError> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        require(metadata.is_dir(), "journal root must be a directory")?;
        require(
            !metadata.file_type().is_symlink(),
            "journal root must not be a symlink",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            require(
                metadata.permissions().mode() & 0o077 == 0,
                "journal root must be private (mode 0700)",
            )?;
        }
    } else {
        std::fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

fn sync_journal_directory(path: &Path) -> Result<(), LifelineTeamError> {
    #[cfg(test)]
    if FAIL_JOURNAL_DIRECTORY_SYNC.with(|failure| failure.replace(false)) {
        return Err(std::io::Error::other("injected journal directory sync failure").into());
    }
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

impl RuntimeEventMonitor {
    fn spawn(
        mut events: mpsc::Receiver<RuntimeEvent>,
        journal: Arc<TeamJournal>,
    ) -> (Self, RuntimeTraceHealth) {
        #[cfg(test)]
        RUNTIME_MONITORS_SPAWNED.with(|count| count.set(count.get() + 1));
        let stop = CancellationToken::new();
        let stop_signal = stop.clone();
        let failed = Arc::new(AtomicBool::new(false));
        let monitor_failed = Arc::clone(&failed);
        let (barriers, mut barrier_requests) = mpsc::channel::<oneshot::Sender<()>>(8);
        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    event = events.recv() => {
                        let Some(event) = event else {
                            return Ok(());
                        };
                        capture_runtime_event(&journal, &monitor_failed, event, &stop_signal).await?;
                    }
                    barrier = barrier_requests.recv() => {
                        let Some(barrier) = barrier else {
                            return Ok(());
                        };
                        let _ = barrier.send(());
                    }
                    () = stop_signal.cancelled() => {
                        while let Ok(event) = events.try_recv() {
                            capture_runtime_event(&journal, &monitor_failed, event, &stop_signal).await?;
                        }
                        return Ok(());
                    }
                }
            }
        });
        (
            Self {
                stop,
                join: Some(join),
            },
            RuntimeTraceHealth { barriers, failed },
        )
    }

    async fn shutdown(mut self) -> Result<(), DispatchError> {
        self.stop.cancel();
        let mut join = OwnedRuntimeMonitorTask(
            self.join
                .take()
                .expect("runtime monitor join handle is present until shutdown"),
        );
        if let Ok(result) = tokio::time::timeout(runtime_trace_watchdog(), &mut join.0).await {
            result.map_err(|_| DispatchError::message("runtime event monitor failed"))?
        } else {
            join.0.abort();
            let _ = (&mut join.0).await;
            Err(DispatchError::message(
                "runtime event monitor shutdown deadline exceeded",
            ))
        }
    }
}

impl RuntimeTraceHealth {
    async fn verify(&self) -> Result<(), DispatchError> {
        self.ensure_healthy()?;
        tokio::time::timeout(runtime_trace_watchdog(), async {
            let (ack, observed) = oneshot::channel();
            self.barriers
                .send(ack)
                .await
                .map_err(|_| DispatchError::message("runtime trace capture is unavailable"))?;
            observed
                .await
                .map_err(|_| DispatchError::message("runtime trace capture failed"))
        })
        .await
        .map_err(|_| DispatchError::message("runtime trace capture deadline exceeded"))??;
        self.ensure_healthy()
    }

    fn ensure_healthy(&self) -> Result<(), DispatchError> {
        if self.failed.load(Ordering::SeqCst) {
            Err(DispatchError::message("runtime trace capture failed"))
        } else {
            Ok(())
        }
    }
}

fn runtime_trace_watchdog() -> Duration {
    if cfg!(test) {
        Duration::from_millis(100)
    } else {
        Duration::from_secs(2)
    }
}

impl Drop for RuntimeEventMonitor {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

async fn capture_runtime_event(
    journal: &TeamJournal,
    failed: &AtomicBool,
    event: RuntimeEvent,
    stop: &CancellationToken,
) -> Result<(), DispatchError> {
    record_runtime_event(journal, event, stop)
        .await
        .inspect_err(|_| failed.store(true, Ordering::SeqCst))
}

async fn record_runtime_event(
    journal: &TeamJournal,
    event: RuntimeEvent,
    stop: &CancellationToken,
) -> Result<(), DispatchError> {
    let (kind, data) = match event {
        RuntimeEvent::SignalEmitted { hash } => {
            ("signal_emitted", serde_json::json!({"hash": hash}))
        }
        RuntimeEvent::SignalReinforced { hash, count } => (
            "signal_reinforced",
            serde_json::json!({"hash": hash, "count": count}),
        ),
        RuntimeEvent::SignalReceived { hash, from, hops } => (
            "signal_received",
            serde_json::json!({"hash": hash, "from": from.clone(), "hops": hops}),
        ),
        RuntimeEvent::SignalExpired { hash } => {
            ("signal_expired", serde_json::json!({"hash": hash}))
        }
        RuntimeEvent::TickCompleted {
            tick,
            active_signals,
            expired,
        } => (
            "tick_completed",
            serde_json::json!({
                "tick": tick,
                "active_signals": active_signals,
                "expired": expired,
            }),
        ),
        RuntimeEvent::PeerConnected { peer_id } => (
            "peer_connected",
            serde_json::json!({"peer_id": peer_id.clone()}),
        ),
        RuntimeEvent::PeerDisconnected { peer_id } => (
            "peer_disconnected",
            serde_json::json!({"peer_id": peer_id.clone()}),
        ),
    };
    loop {
        match journal.record(kind, &data) {
            Ok(()) => return Ok(()),
            Err(DispatchError::Message(message)) if message == "team journal is unavailable" => {
                tokio::select! {
                    biased;
                    () = stop.cancelled() => {
                        return Err(DispatchError::message("team journal is unavailable"));
                    }
                    () = tokio::time::sleep(Duration::from_millis(1)) => {}
                }
            }
            Err(error) => return Err(error),
        }
    }
}

impl TeamJournal {
    fn create(path: &Path) -> Result<Self, std::io::Error> {
        let journal = Self::create_with_kind(path, false)?;
        journal.sync_preflight()?;
        Ok(journal)
    }

    fn create_runtime(path: &Path) -> Result<Self, std::io::Error> {
        let journal = Self::create_with_kind(path, true)?;
        journal.sync_preflight()?;
        Ok(journal)
    }

    fn create_with_kind(path: &Path, runtime_trace: bool) -> Result<Self, std::io::Error> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        Ok(Self {
            state: Mutex::new(TeamJournalState {
                file: options.open(path)?,
                sequence: 0,
                event_count: 0,
                byte_count: 0,
            }),
            runtime_trace,
        })
    }

    fn record(&self, kind: &'static str, data: &serde_json::Value) -> Result<(), DispatchError> {
        const MAX_EVENTS: usize = 512;
        const MAX_EVENT_BYTES: usize = 4 * 1024;
        const MAX_TOTAL_BYTES: usize = 256 * 1024;
        let approved_kind = if self.runtime_trace {
            matches!(
                kind,
                "signal_emitted"
                    | "signal_reinforced"
                    | "signal_received"
                    | "signal_expired"
                    | "tick_completed"
                    | "peer_connected"
                    | "peer_disconnected"
            )
        } else {
            matches!(
                kind,
                "query_retained"
                    | "task_claimed"
                    | "task_backed_off"
                    | "signal_reinforced"
                    | "signal_contradicted"
                    | "signal_decayed"
                    | "tool_called"
                    | "tool_completed"
                    | "candidate_built"
            )
        };
        if !approved_kind {
            return Err(DispatchError::message("unreviewed team journal event kind"));
        }
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| DispatchError::message("team journal is unavailable"))?;
        if state.event_count >= MAX_EVENTS {
            return Err(DispatchError::message("team journal event limit reached"));
        }
        let sequence = state.sequence + 1;
        let schema = if self.runtime_trace {
            "lifeline-runtime-trace/1"
        } else {
            "lifeline-team-journal/1"
        };
        let mut line = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": schema,
            "sequence": sequence,
            "kind": kind,
            "data": data,
        }))
        .map_err(|_| DispatchError::message("team journal serialization failed"))?;
        line.push(b'\n');
        if line.len() > MAX_EVENT_BYTES || state.byte_count + line.len() > MAX_TOTAL_BYTES {
            return Err(DispatchError::message("team journal byte limit reached"));
        }
        state
            .file
            .write_all(&line)
            .and_then(|()| state.file.sync_data())
            .map_err(|error| {
                DispatchError::message(format!("team journal write failed: {error}"))
            })?;
        state.sequence = sequence;
        state.event_count += 1;
        state.byte_count += line.len();
        Ok(())
    }

    fn sync(&self) -> Result<(), std::io::Error> {
        self.state
            .lock()
            .map_err(|_| std::io::Error::other("team journal lock poisoned"))?
            .file
            .sync_all()
    }

    fn sync_preflight(&self) -> Result<(), std::io::Error> {
        #[cfg(test)]
        if FAIL_JOURNAL_FILE_SYNC.with(|failure| failure.replace(false)) {
            return Err(std::io::Error::other(
                "injected team journal file synchronization failure",
            ));
        }
        self.sync()
    }
}

fn scoped_task_id(gateway_id: &str, task_id: &str) -> String {
    let digest = crate::content_digest(format!("{gateway_id}\0{task_id}").as_bytes());
    format!("team-task-{}", &digest[7..39])
}

fn deterministic_affinity(seed: u64, team: &str, task: &str, role: &str) -> u64 {
    let input = format!("{seed}\0{team}\0{task}\0{role}");
    let digest = crate::content_digest(input.as_bytes());
    u64::from_str_radix(&digest[7..22], 16).expect("SHA-256 digest is hexadecimal")
}

fn require(condition: bool, message: &str) -> Result<(), LifelineTeamError> {
    if condition {
        Ok(())
    } else {
        Err(invariant(message))
    }
}

fn require_identifier(value: &str, label: &str) -> Result<(), LifelineTeamError> {
    require_text(value, 128, label)?;
    require(
        value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        }),
        &format!("{label} must be a lowercase ASCII identifier"),
    )
}

fn require_text(value: &str, max: usize, label: &str) -> Result<(), LifelineTeamError> {
    require(
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control),
        &format!("{label} violates bounds"),
    )
}

fn invariant(message: impl Into<String>) -> LifelineTeamError {
    LifelineTeamError::Invariant(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn journal_file_sync_failure_precedes_runtime_spawn() {
        let root = std::env::temp_dir().join(format!(
            "smesh-journal-file-sync-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let manifest =
            LifelineTeamManifest::from_json(include_str!("../deploy/lifeline-teams.json")).unwrap();
        FAIL_JOURNAL_FILE_SYNC.with(|failure| failure.set(true));
        RUNTIME_MONITORS_SPAWNED.with(|count| count.set(0));

        let result = manifest.launch(&root).await;

        assert!(result.is_err());
        assert_eq!(RUNTIME_MONITORS_SPAWNED.with(std::cell::Cell::get), 0);
        assert!(!FAIL_JOURNAL_FILE_SYNC.with(std::cell::Cell::get));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn journal_directory_sync_failure_precedes_runtime_spawn() {
        let root = std::env::temp_dir().join(format!(
            "smesh-journal-launch-sync-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let manifest =
            LifelineTeamManifest::from_json(include_str!("../deploy/lifeline-teams.json")).unwrap();
        FAIL_JOURNAL_DIRECTORY_SYNC.with(|failure| failure.set(true));
        RUNTIME_MONITORS_SPAWNED.with(|count| count.set(0));

        let result = manifest.launch(&root).await;

        assert!(result.is_err());
        assert_eq!(RUNTIME_MONITORS_SPAWNED.with(std::cell::Cell::get), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_directory_sync_failure_is_not_acknowledged() {
        let root = std::env::temp_dir().join(format!(
            "smesh-journal-sync-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        FAIL_JOURNAL_DIRECTORY_SYNC.with(|failure| failure.set(true));

        let result = sync_journal_directory(&root);

        assert!(result.is_err());
        assert!(!FAIL_JOURNAL_DIRECTORY_SYNC.with(std::cell::Cell::get));
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn public_team_error_shape_remains_exhaustive() {
        fn classify(error: &LifelineTeamError) -> &'static str {
            match error {
                LifelineTeamError::Json(_) => "json",
                LifelineTeamError::Io(_) => "io",
                LifelineTeamError::Runtime(_) => "runtime",
                LifelineTeamError::Topology(_) => "topology",
                LifelineTeamError::Invariant(_) => "invariant",
            }
        }
        assert_eq!(
            classify(&LifelineTeamError::Invariant("test".into())),
            "invariant"
        );
    }

    #[tokio::test]
    async fn internal_stop_does_not_release_transport_before_public_cancel() {
        let path = std::env::temp_dir().join(format!(
            "smesh-failure-signal-{}-{}.jsonl",
            std::process::id(),
            rand::random::<u64>()
        ));
        let failure = LifelineTeamFailureMode::new(LifelineFailureTrace::create(&path).unwrap());
        failure.internal_stopped.store(true, Ordering::SeqCst);
        failure.internal_stop_ready.notify_waiters();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                failure.wait_for_public_cancel_signal(),
            )
            .await
            .is_err()
        );
        failure.mark_public_cancel_confirmed();
        tokio::time::timeout(
            Duration::from_millis(20),
            failure.wait_for_public_cancel_signal(),
        )
        .await
        .unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[allow(clippy::await_holding_lock)] // Holds the journal gate to prove monitor shutdown cannot block on it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_monitor_shutdown_rejects_a_busy_journal_without_blocking() {
        let path = std::env::temp_dir().join(format!(
            "smesh-runtime-monitor-{}-{}.jsonl",
            std::process::id(),
            rand::random::<u64>()
        ));
        let journal = Arc::new(TeamJournal::create_runtime(&path).unwrap());
        let (events, receiver) = mpsc::channel(1);
        let (monitor, _health) = RuntimeEventMonitor::spawn(receiver, Arc::clone(&journal));
        let gate = journal.state.lock().unwrap();
        events
            .send(RuntimeEvent::TickCompleted {
                tick: 1,
                active_signals: 0,
                expired: 0,
            })
            .await
            .unwrap();
        tokio::task::yield_now().await;

        let result = tokio::time::timeout(Duration::from_millis(250), monitor.shutdown()).await;
        drop(gate);

        assert!(result.unwrap().is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn dropping_runtime_monitor_aborts_and_reaps_its_join() {
        struct Reaped(Option<oneshot::Sender<()>>);
        impl Drop for Reaped {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let (reaped, observed) = oneshot::channel();
        let (started, running) = oneshot::channel();
        let join = tokio::spawn(async move {
            let _reaped = Reaped(Some(reaped));
            let _ = started.send(());
            std::future::pending::<Result<(), DispatchError>>().await
        });
        running.await.unwrap();
        drop(RuntimeEventMonitor {
            stop: CancellationToken::new(),
            join: Some(join),
        });

        tokio::time::timeout(Duration::from_millis(20), observed)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn canceling_runtime_monitor_shutdown_aborts_its_taken_join() {
        struct Reaped(Option<oneshot::Sender<()>>);
        impl Drop for Reaped {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let (reaped, observed) = oneshot::channel();
        let join = tokio::spawn(async move {
            let _reaped = Reaped(Some(reaped));
            std::future::pending::<Result<(), DispatchError>>().await
        });
        let monitor = RuntimeEventMonitor {
            stop: CancellationToken::new(),
            join: Some(join),
        };
        let shutdown = tokio::spawn(monitor.shutdown());
        tokio::task::yield_now().await;
        shutdown.abort();
        let _ = shutdown.await;

        tokio::time::timeout(Duration::from_millis(50), observed)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn runtime_monitor_shutdown_is_bounded_and_reaped() {
        struct Reaped(Option<oneshot::Sender<()>>);
        impl Drop for Reaped {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let (reaped, observed) = oneshot::channel();
        let join = tokio::spawn(async move {
            let _reaped = Reaped(Some(reaped));
            std::future::pending::<Result<(), DispatchError>>().await
        });
        let monitor = RuntimeEventMonitor {
            stop: CancellationToken::new(),
            join: Some(join),
        };

        let result = tokio::time::timeout(Duration::from_millis(250), monitor.shutdown()).await;

        assert!(result.unwrap().is_err());
        tokio::time::timeout(Duration::from_millis(20), observed)
            .await
            .unwrap()
            .unwrap();
    }

    #[allow(clippy::await_holding_lock)] // Deliberately stalls trace capture to reproduce the cleanup race.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_trace_barrier_wait_is_bounded() {
        let (barriers, receiver) = mpsc::channel(1);
        let (occupied, _occupied_rx) = oneshot::channel();
        barriers.try_send(occupied).unwrap();
        let health = RuntimeTraceHealth {
            barriers,
            failed: Arc::new(AtomicBool::new(false)),
        };

        let result = tokio::time::timeout(Duration::from_millis(250), health.verify()).await;
        drop(receiver);

        assert!(result.unwrap().is_err());
    }

    #[allow(clippy::await_holding_lock)] // Deliberately stalls trace capture to reproduce the cleanup race.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_consumer_cannot_leave_a_late_runtime_outcome() {
        let root = std::env::temp_dir().join(format!(
            "smesh-lifeline-outcome-drop-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let fleet = LifelineTeamManifest::from_json(include_str!("../deploy/lifeline-teams.json"))
            .unwrap()
            .launch(&root)
            .await
            .unwrap();
        let runtime_trace = fleet
            .journals
            .iter()
            .find(|journal| journal.runtime_trace)
            .unwrap();
        let trace_guard = runtime_trace.state.lock().unwrap();
        let dispatcher = fleet.dispatcher_for_gateway("meridian").unwrap();
        let mut stream = dispatcher.dispatch(MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "dropped-consumer".to_owned(),
            context_id: "dropped-consumer-context".to_owned(),
            text: "drop after runtime admission".to_owned(),
        });
        assert!(stream.next().await.unwrap().is_ok());
        drop(stream);
        drop(trace_guard);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let registry = Arc::clone(&dispatcher.registry);
        fleet.shutdown().await.unwrap();
        let registry = registry.lock().unwrap();
        assert!(registry.requests.is_empty());
        assert!(registry.outcomes.is_empty());
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn runtime_trace_failure_prevents_public_completion() {
        let root = std::env::temp_dir().join(format!(
            "smesh-lifeline-trace-failure-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let fleet = LifelineTeamManifest::from_json(include_str!("../deploy/lifeline-teams.json"))
            .unwrap()
            .launch(&root)
            .await
            .unwrap();
        let runtime_trace = fleet
            .journals
            .iter()
            .find(|journal| journal.runtime_trace)
            .unwrap();
        runtime_trace.state.lock().unwrap().event_count = 512;

        let dispatcher = fleet.dispatcher_for_gateway("meridian").unwrap();
        let events = dispatcher
            .dispatch(MeshRequest {
                protocol: "a2a-v1".to_owned(),
                task_id: "trace-failure".to_owned(),
                context_id: "trace-failure-context".to_owned(),
                text: "capture must remain healthy".to_owned(),
            })
            .collect::<Vec<_>>()
            .await;
        assert!(events.iter().any(Result::is_err));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Ok(MeshEvent::Completed { .. })))
        );

        assert!(fleet.shutdown().await.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn concurrent_trace_failure_invalidates_completion_after_final_barrier() {
        let root = std::env::temp_dir().join(format!(
            "smesh-lifeline-trace-race-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let fleet = LifelineTeamManifest::from_json(include_str!("../deploy/lifeline-teams.json"))
            .unwrap()
            .launch(&root)
            .await
            .unwrap();
        let runtime_trace = fleet
            .journals
            .iter()
            .find(|journal| journal.runtime_trace)
            .unwrap();
        let dispatcher = fleet.dispatcher_for_gateway("meridian").unwrap();
        let mut first = dispatcher.dispatch(MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "completion-race-a".to_owned(),
            context_id: "completion-race-context-a".to_owned(),
            text: "pause after artifact".to_owned(),
        });
        loop {
            let event = first.next().await.unwrap().unwrap();
            if matches!(event, MeshEvent::Artifact { .. }) {
                break;
            }
        }

        runtime_trace.state.lock().unwrap().event_count = 512;
        let second = dispatcher.dispatch(MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "completion-race-b".to_owned(),
            context_id: "completion-race-context-b".to_owned(),
            text: "force a concurrent trace failure".to_owned(),
        });
        let second_events = second.collect::<Vec<_>>().await;
        assert!(second_events.iter().any(Result::is_err));

        let remaining = first.collect::<Vec<_>>().await;
        assert!(remaining.iter().any(Result::is_err));
        assert!(
            !remaining
                .iter()
                .any(|event| matches!(event, Ok(MeshEvent::Completed { .. })))
        );

        assert!(fleet.shutdown().await.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
