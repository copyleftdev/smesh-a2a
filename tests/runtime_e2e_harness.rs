use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a2a::{
    Message, Part, PartContent, Role, SendMessageRequest, StreamResponse,
    TRANSPORT_PROTOCOL_JSONRPC, TaskState,
};
use a2a_client::A2AClientFactory;
use a2a_client::agent_card::AgentCardResolver;
use async_trait::async_trait;
use futures::{
    StreamExt,
    stream::{self, BoxStream},
};
use serde::{Deserialize, Serialize};
use smesh_a2a::{
    ArtifactManifest, CompletionEvidence, DispatchError, GatewayConfig, MeshDispatcher, MeshEvent,
    MeshRequest, RuntimeEventSink, RuntimeTask, RuntimeTaskProcessor, RuntimeWorker,
    artifact_set_digest, build_router, completion_evidence_digest, content_digest,
};
use smesh_core::{Network, Node};
use smesh_runtime::{MeshConfig, RuntimeConfig, SmeshRuntime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{Notify, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

const SPECIALIST: &str = env!("CARGO_BIN_EXE_smesh-e2e-specialist");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TraceEvent {
    kind: &'static str,
    task_id: String,
    context_id: String,
    signal_hash: Option<String>,
    artifact_name: Option<String>,
    subject_digest: Option<String>,
    evidence_id: Option<String>,
    evidence_digest: Option<String>,
    role: Option<String>,
    process_id: Option<u32>,
    detail: Option<String>,
}

type Trace = Arc<Mutex<Vec<TraceEvent>>>;

struct TraceArtifactGuard {
    path: PathBuf,
    trace: Trace,
    finished: bool,
}

impl TraceArtifactGuard {
    fn new(trace: Trace) -> Self {
        static NEXT_RUN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let run = NEXT_RUN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("harness-artifacts");
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            path: directory.join(format!("run-{}-{run}.json", std::process::id())),
            trace,
            finished: false,
        }
    }

    fn finish(mut self) -> PathBuf {
        self.write().unwrap();
        self.finished = true;
        self.path.clone()
    }

    fn write(&self) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = serde_json::to_vec_pretty(&*self.trace.lock().unwrap())?;
        let temporary = self.path.with_extension("json.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        std::io::Write::write_all(&mut file, &bytes)?;
        file.sync_all()?;
        std::fs::rename(temporary, &self.path)?;
        Ok(())
    }
}

impl Drop for TraceArtifactGuard {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.write();
        }
    }
}

#[tokio::test]
async fn failed_specialist_run_is_reaped_and_preserves_diagnostic_trace() {
    let content = serde_json::json!({
        "analysis": "failure-path analysis",
        "checks": ["binding", "policy"],
        "contradictions": [],
    })
    .to_string();
    let subject_digest = artifact_set_digest(&[ArtifactManifest {
        name: "failure.json".to_owned(),
        media_type: "application/json".to_owned(),
        digest: content_digest(content.as_bytes()),
    }])
    .unwrap();
    let input = SpecialistInput {
        schema: "smesh-a2a/specialist-input/v1",
        task_id: "failed-task".to_owned(),
        context_id: "failed-context".to_owned(),
        subject_digest,
        artifact_name: "failure.json".to_owned(),
        media_type: "application/json".to_owned(),
        content,
    };
    let trace = Arc::new(Mutex::new(Vec::new()));
    let guard = TraceArtifactGuard::new(Arc::clone(&trace));
    let path = guard.path.clone();
    assert!(
        run_specialist(
            Path::new(SPECIALIST),
            "unsupported-role",
            &input,
            &trace,
            &CancellationToken::new(),
        )
        .await
        .is_err()
    );
    let events = trace.lock().unwrap().clone();
    assert!(
        events
            .iter()
            .any(|event| event.kind == "specialist-attempt")
    );
    assert!(
        events
            .iter()
            .any(|event| event.kind == "specialist-failure")
    );
    assert!(events.iter().any(|event| event.kind == "specialist-reaped"));
    drop(guard);
    let persisted: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(persisted.len(), events.len());
    std::fs::remove_file(path).unwrap();
}

#[derive(Clone)]
struct HarnessProcessor {
    trace: Trace,
}

#[async_trait]
impl RuntimeTaskProcessor for HarnessProcessor {
    async fn process(
        &self,
        task: RuntimeTask,
        _cancellation: CancellationToken,
        events: RuntimeEventSink,
    ) -> Result<(), DispatchError> {
        self.trace.lock().unwrap().push(TraceEvent {
            kind: "runtime-task",
            task_id: task.request.task_id.clone(),
            context_id: task.request.context_id.clone(),
            signal_hash: Some(task.signal_hash.clone()),
            artifact_name: None,
            subject_digest: None,
            evidence_id: None,
            evidence_digest: None,
            role: None,
            process_id: None,
            detail: None,
        });
        let content = serde_json::json!({
            "analysis": "The real runtime retained the exact correlated Query; the harness specialists independently validate binding and declared checks.",
            "checks": ["task-context-signal binding", "completion-policy boundary"],
            "contradictions": [],
            "contextId": task.request.context_id,
            "signalHash": task.signal_hash,
            "taskId": task.request.task_id,
        })
        .to_string();
        events
            .artifact("runtime-analysis.json", "application/json", content)
            .await?;
        events
            .propose_completion("specialist-reviewed runtime analysis proposed")
            .await
    }
}

#[derive(Clone)]
struct SpecialistEvidenceDispatcher<D> {
    inner: D,
    program: PathBuf,
    trace: Trace,
    active: Arc<Mutex<HashMap<String, ActiveHarness>>>,
}

#[derive(Clone)]
struct ActiveHarness {
    cancellation: CancellationToken,
    done: Arc<Notify>,
}

struct HarnessCompletionGuard {
    task_id: String,
    active: Arc<Mutex<HashMap<String, ActiveHarness>>>,
    done: Arc<Notify>,
}

impl Drop for HarnessCompletionGuard {
    fn drop(&mut self) {
        self.active.lock().unwrap().remove(&self.task_id);
        self.done.notify_one();
    }
}

impl<D> SpecialistEvidenceDispatcher<D> {
    fn new(inner: D, program: impl Into<PathBuf>, trace: Trace) -> Self {
        Self {
            inner,
            program: program.into(),
            trace,
            active: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl<D> MeshDispatcher for SpecialistEvidenceDispatcher<D>
where
    D: MeshDispatcher + Clone,
{
    #[allow(clippy::too_many_lines)] // Keep the bounded intercept/evidence sequence linear.
    fn dispatch(
        &self,
        request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let cancellation = CancellationToken::new();
        let done = Arc::new(Notify::new());
        {
            let mut active = self.active.lock().unwrap();
            if active.contains_key(&request.task_id) {
                return Box::pin(stream::once(async {
                    Err(DispatchError::Message(
                        "harness task ID is already active".to_owned(),
                    ))
                }));
            }
            active.insert(
                request.task_id.clone(),
                ActiveHarness {
                    cancellation: cancellation.clone(),
                    done: Arc::clone(&done),
                },
            );
        }
        let mut inner = self.inner.dispatch(request.clone());
        let program = self.program.clone();
        let trace = Arc::clone(&self.trace);
        let active = Arc::clone(&self.active);
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(async move {
            let _completion = HarnessCompletionGuard {
                task_id: request.task_id.clone(),
                active,
                done,
            };
            let mut artifact = None::<(String, String, String)>;
            let mut completion = None::<MeshEvent>;
            loop {
                let event = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => return,
                    event = inner.next() => event,
                };
                let Some(event) = event else {
                    break;
                };
                match event {
                    Ok(MeshEvent::Artifact {
                        name,
                        media_type,
                        content,
                    }) => {
                        if artifact.is_some() {
                            let _ = tx
                                .send(Err(DispatchError::Message(
                                    "harness received multiple candidate artifacts".to_owned(),
                                )))
                                .await;
                            return;
                        }
                        let candidate_subject = artifact_set_digest(&[ArtifactManifest {
                            name: name.clone(),
                            media_type: media_type.clone(),
                            digest: content_digest(content.as_bytes()),
                        }])
                        .ok();
                        let candidate_signal = serde_json::from_str::<serde_json::Value>(&content)
                            .ok()
                            .and_then(|value| {
                                value
                                    .get("signalHash")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned)
                            });
                        trace.lock().unwrap().push(TraceEvent {
                            kind: "candidate",
                            task_id: request.task_id.clone(),
                            context_id: request.context_id.clone(),
                            signal_hash: candidate_signal,
                            artifact_name: Some(name.clone()),
                            subject_digest: candidate_subject,
                            evidence_id: None,
                            evidence_digest: None,
                            role: None,
                            process_id: None,
                            detail: None,
                        });
                        artifact = Some((name.clone(), media_type.clone(), content.clone()));
                        if tx
                            .send(Ok(MeshEvent::Artifact {
                                name,
                                media_type,
                                content,
                            }))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok(event @ MeshEvent::Completed { .. }) => {
                        if completion.replace(event).is_some() {
                            let _ = tx
                                .send(Err(DispatchError::Message(
                                    "harness received multiple completion proposals".to_owned(),
                                )))
                                .await;
                            return;
                        }
                    }
                    other => {
                        if tx.send(other).await.is_err() {
                            return;
                        }
                    }
                }
            }
            let (Some((name, media_type, content)), Some(completion)) = (artifact, completion)
            else {
                let _ = tx
                    .send(Err(DispatchError::Message(
                        "harness candidate stream ended incomplete".to_owned(),
                    )))
                    .await;
                return;
            };
            let subject_digest = match artifact_set_digest(&[ArtifactManifest {
                name: name.clone(),
                media_type: media_type.clone(),
                digest: content_digest(content.as_bytes()),
            }]) {
                Ok(digest) => digest,
                Err(error) => {
                    let _ = tx
                        .send(Err(DispatchError::Message(error.to_string())))
                        .await;
                    return;
                }
            };
            let input = SpecialistInput {
                schema: "smesh-a2a/specialist-input/v1",
                task_id: request.task_id.clone(),
                context_id: request.context_id.clone(),
                subject_digest: subject_digest.clone(),
                artifact_name: name,
                media_type,
                content,
            };
            for role in ["review", "test", "contradiction"] {
                let decision =
                    match run_specialist(&program, role, &input, &trace, &cancellation).await {
                        Ok(decision) => decision,
                        Err(error) => {
                            let _ = tx.send(Err(error)).await;
                            return;
                        }
                    };
                let evidence = match decision.into_evidence(&subject_digest) {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        let _ = tx.send(Err(error)).await;
                        return;
                    }
                };
                let (evidence_id, _evidence_payload_digest, evidence_subject) = match &evidence {
                    CompletionEvidence::Review {
                        id,
                        evidence_digest,
                        subject_digest,
                        ..
                    }
                    | CompletionEvidence::Test {
                        id,
                        evidence_digest,
                        subject_digest,
                        ..
                    }
                    | CompletionEvidence::Contradiction {
                        id,
                        evidence_digest,
                        subject_digest,
                        ..
                    } => (id.clone(), evidence_digest.clone(), subject_digest.clone()),
                    CompletionEvidence::Attestation { .. }
                    | CompletionEvidence::Ratification(_) => unreachable!(),
                };
                let evidence_record_digest = match completion_evidence_digest(&evidence) {
                    Ok(digest) => digest,
                    Err(error) => {
                        let _ = tx
                            .send(Err(DispatchError::Message(error.to_string())))
                            .await;
                        return;
                    }
                };
                let evidence_signal = serde_json::from_str::<serde_json::Value>(&input.content)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("signalHash")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    });
                trace.lock().unwrap().push(TraceEvent {
                    kind: "evidence",
                    task_id: request.task_id.clone(),
                    context_id: request.context_id.clone(),
                    signal_hash: evidence_signal,
                    artifact_name: Some(input.artifact_name.clone()),
                    subject_digest: Some(evidence_subject),
                    evidence_id: Some(evidence_id),
                    evidence_digest: Some(evidence_record_digest),
                    role: Some(role.to_owned()),
                    process_id: None,
                    detail: None,
                });
                if tx.send(Ok(MeshEvent::Evidence(evidence))).await.is_err() {
                    return;
                }
            }
            let _ = tx.send(Ok(completion)).await;
        });
        Box::pin(ReceiverStream::new(rx))
    }

    async fn cancel(&self, task_id: &str) -> Result<(), DispatchError> {
        let active = self.active.lock().unwrap().get(task_id).cloned();
        if let Some(active) = active {
            active.cancellation.cancel();
            let _ = self.inner.cancel(task_id).await;
            tokio::time::timeout(Duration::from_secs(3), active.done.notified())
                .await
                .map_err(|_| DispatchError::Message("harness cancellation timed out".to_owned()))?;
            Ok(())
        } else {
            self.inner.cancel(task_id).await
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpecialistInput {
    schema: &'static str,
    task_id: String,
    context_id: String,
    subject_digest: String,
    artifact_name: String,
    media_type: String,
    content: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpecialistDecision {
    schema: String,
    role: String,
    issuer: String,
    approved: bool,
    assurance_bps: u16,
    evidence: String,
    task_id: String,
    context_id: String,
    subject_digest: String,
    #[serde(skip)]
    raw: Vec<u8>,
}

impl SpecialistDecision {
    fn into_evidence(self, subject_digest: &str) -> Result<CompletionEvidence, DispatchError> {
        if self.schema != "smesh-a2a/specialist-output/v1" || self.assurance_bps != 10_000 {
            return Err(DispatchError::Message(
                "specialist returned an invalid decision schema".to_owned(),
            ));
        }
        let digest = content_digest(&self.raw);
        match self.role.as_str() {
            "review" if self.issuer == "review-authority" => Ok(CompletionEvidence::Review {
                id: "process-review".to_owned(),
                issuer: self.issuer,
                subject_digest: subject_digest.to_owned(),
                evidence: self.raw,
                evidence_digest: digest,
                approved: self.approved,
                assurance_bps: self.assurance_bps,
            }),
            "test" if self.issuer == "test-authority" => Ok(CompletionEvidence::Test {
                id: "process-test".to_owned(),
                issuer: self.issuer,
                subject_digest: subject_digest.to_owned(),
                evidence: self.raw,
                evidence_digest: digest,
                passed: self.approved,
                assurance_bps: self.assurance_bps,
            }),
            "contradiction" if self.issuer == "contradiction-monitor" => {
                Ok(CompletionEvidence::Contradiction {
                    id: "process-contradiction".to_owned(),
                    issuer: self.issuer,
                    subject_digest: subject_digest.to_owned(),
                    evidence: self.raw,
                    evidence_digest: digest,
                    blocking: !self.approved,
                })
            }
            _ => Err(DispatchError::Message(
                "specialist role/issuer binding is invalid".to_owned(),
            )),
        }
    }
}

fn trace_specialist(
    trace: &Trace,
    input: &SpecialistInput,
    kind: &'static str,
    role: &str,
    process_id: u32,
    detail: Option<String>,
) {
    let signal_hash = serde_json::from_str::<serde_json::Value>(&input.content)
        .ok()
        .and_then(|value| {
            value
                .get("signalHash")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    trace.lock().unwrap().push(TraceEvent {
        kind,
        task_id: input.task_id.clone(),
        context_id: input.context_id.clone(),
        signal_hash,
        artifact_name: Some(input.artifact_name.clone()),
        subject_digest: Some(input.subject_digest.clone()),
        evidence_id: None,
        evidence_digest: None,
        role: Some(role.to_owned()),
        process_id: Some(process_id),
        detail,
    });
}

async fn read_bounded<R>(reader: R, limit: u64) -> Result<Vec<u8>, DispatchError>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| DispatchError::Message(error.to_string()))?;
    if bytes.len() > usize::try_from(limit).unwrap() {
        return Err(DispatchError::Message(
            "specialist process output exceeded bound".to_owned(),
        ));
    }
    Ok(bytes)
}

async fn fail_spawned_specialist(
    child: &mut Child,
    trace: &Trace,
    input: &SpecialistInput,
    role: &str,
    process_id: u32,
    detail: String,
) -> DispatchError {
    let _ = child.start_kill();
    let reaped = child.wait().await.is_ok();
    let detail = if reaped {
        detail
    } else {
        format!("{detail}; child reap failed")
    };
    trace_specialist(
        trace,
        input,
        "specialist-failure",
        role,
        process_id,
        Some(detail.clone()),
    );
    if reaped {
        trace_specialist(trace, input, "specialist-reaped", role, process_id, None);
    }
    DispatchError::Message(detail)
}

#[allow(clippy::too_many_lines)] // One bounded spawn/write/read/reap/validate sequence.
async fn run_specialist(
    program: &Path,
    role: &str,
    input: &SpecialistInput,
    trace: &Trace,
    cancellation: &CancellationToken,
) -> Result<SpecialistDecision, DispatchError> {
    let encoded =
        serde_json::to_vec(input).map_err(|error| DispatchError::Message(error.to_string()))?;
    let mut child = Command::new(program)
        .arg(role)
        .env_clear()
        .current_dir(std::env::temp_dir())
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| DispatchError::Message(error.to_string()))?;
    let process_id = child.id().unwrap_or_default();
    trace_specialist(trace, input, "specialist-attempt", role, process_id, None);
    let Some(stdout) = child.stdout.take() else {
        return Err(fail_spawned_specialist(
            &mut child,
            trace,
            input,
            role,
            process_id,
            "specialist stdout unavailable".to_owned(),
        )
        .await);
    };
    let Some(stderr) = child.stderr.take() else {
        return Err(fail_spawned_specialist(
            &mut child,
            trace,
            input,
            role,
            process_id,
            "specialist stderr unavailable".to_owned(),
        )
        .await);
    };
    let Some(mut stdin) = child.stdin.take() else {
        return Err(fail_spawned_specialist(
            &mut child,
            trace,
            input,
            role,
            process_id,
            "specialist stdin unavailable".to_owned(),
        )
        .await);
    };
    if let Err(error) = stdin.write_all(&encoded).await {
        return Err(fail_spawned_specialist(
            &mut child,
            trace,
            input,
            role,
            process_id,
            format!("specialist stdin write failed: {error}"),
        )
        .await);
    }
    if let Err(error) = stdin.shutdown().await {
        return Err(fail_spawned_specialist(
            &mut child,
            trace,
            input,
            role,
            process_id,
            format!("specialist stdin shutdown failed: {error}"),
        )
        .await);
    }
    drop(stdin);
    let stdout_task = tokio::spawn(read_bounded(stdout, 4096));
    let stderr_task = tokio::spawn(read_bounded(stderr, 4096));
    let waited = tokio::select! {
        biased;
        () = cancellation.cancelled() => None,
        result = tokio::time::timeout(Duration::from_secs(2), child.wait()) => Some(result),
    };
    let Some(waited) = waited else {
        let _ = child.start_kill();
        let reaped = child.wait().await.is_ok();
        let _ = stdout_task.await;
        let stderr = stderr_task
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        trace_specialist(
            trace,
            input,
            "specialist-failure",
            role,
            process_id,
            Some(format!("canceled: {}", String::from_utf8_lossy(&stderr))),
        );
        if reaped {
            trace_specialist(trace, input, "specialist-reaped", role, process_id, None);
        }
        return Err(DispatchError::Message(
            "specialist process canceled".to_owned(),
        ));
    };
    let status = if let Ok(result) = waited {
        if let Ok(status) = result {
            status
        } else {
            let error = fail_spawned_specialist(
                &mut child,
                trace,
                input,
                role,
                process_id,
                "specialist wait failed".to_owned(),
            )
            .await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            return Err(error);
        }
    } else {
        let _ = child.start_kill();
        let reaped = child.wait().await.is_ok();
        let _ = stdout_task.await;
        let stderr = stderr_task
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        trace_specialist(
            trace,
            input,
            "specialist-failure",
            role,
            process_id,
            Some(format!("timeout: {}", String::from_utf8_lossy(&stderr))),
        );
        if reaped {
            trace_specialist(trace, input, "specialist-reaped", role, process_id, None);
        }
        return Err(DispatchError::Message(
            "specialist process timed out".to_owned(),
        ));
    };
    trace_specialist(trace, input, "specialist-reaped", role, process_id, None);
    let stdout = match stdout_task.await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => {
            trace_specialist(
                trace,
                input,
                "specialist-failure",
                role,
                process_id,
                Some(error.to_string()),
            );
            return Err(error);
        }
        Err(_) => {
            trace_specialist(
                trace,
                input,
                "specialist-failure",
                role,
                process_id,
                Some("specialist stdout reader task failed".to_owned()),
            );
            return Err(DispatchError::Message(
                "specialist stdout reader task failed".to_owned(),
            ));
        }
    };
    let stderr = match stderr_task.await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => {
            trace_specialist(
                trace,
                input,
                "specialist-failure",
                role,
                process_id,
                Some(error.to_string()),
            );
            return Err(error);
        }
        Err(_) => {
            trace_specialist(
                trace,
                input,
                "specialist-failure",
                role,
                process_id,
                Some("specialist stderr reader task failed".to_owned()),
            );
            return Err(DispatchError::Message(
                "specialist stderr reader task failed".to_owned(),
            ));
        }
    };
    if !status.success() {
        trace_specialist(
            trace,
            input,
            "specialist-failure",
            role,
            process_id,
            Some(format!(
                "exit {:?}: {}",
                status.code(),
                String::from_utf8_lossy(&stderr)
            )),
        );
        return Err(DispatchError::Message(
            "specialist process failed".to_owned(),
        ));
    }
    let mut decision: SpecialistDecision = match serde_json::from_slice(&stdout) {
        Ok(decision) => decision,
        Err(error) => {
            trace_specialist(
                trace,
                input,
                "specialist-failure",
                role,
                process_id,
                Some(format!("malformed output: {error}")),
            );
            return Err(DispatchError::Message(error.to_string()));
        }
    };
    if decision.role != role
        || !decision.approved
        || decision.evidence.is_empty()
        || decision.task_id != input.task_id
        || decision.context_id != input.context_id
        || decision.subject_digest != input.subject_digest
    {
        trace_specialist(
            trace,
            input,
            "specialist-failure",
            role,
            process_id,
            Some("decision binding or approval rejected".to_owned()),
        );
        return Err(DispatchError::Message(
            "specialist decision is not acceptable".to_owned(),
        ));
    }
    decision.raw = stdout;
    trace_specialist(trace, input, "specialist", role, process_id, None);
    Ok(decision)
}

fn runtime() -> Arc<SmeshRuntime> {
    let mut network = Network::new();
    network.add_node(Node::named("harness-runtime"));
    Arc::new(SmeshRuntime::with_network(
        network,
        RuntimeConfig::default(),
    ))
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One auditable official-client/process/runtime lifecycle.
async fn official_client_observes_specialists_and_policy_accepted_runtime_artifact() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let trace_artifact = TraceArtifactGuard::new(Arc::clone(&trace));
    let runtime = runtime();
    let mesh = runtime
        .join_mesh(
            MeshConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                peer_discovery: false,
                ..MeshConfig::default()
            },
            "harness-runtime",
        )
        .await
        .unwrap();
    let (runtime_dispatcher, worker) = RuntimeWorker::spawn(
        Arc::clone(&runtime),
        "harness-runtime",
        HarnessProcessor {
            trace: Arc::clone(&trace),
        },
        8,
    )
    .await
    .unwrap();
    let dispatcher =
        SpecialistEvidenceDispatcher::new(runtime_dispatcher, SPECIALIST, Arc::clone(&trace));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let app = build_router(GatewayConfig::new(&base_url, "harness-runtime"), dispatcher);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let card = tokio::time::timeout(
        Duration::from_secs(5),
        AgentCardResolver::new(None).resolve(&base_url),
    )
    .await
    .unwrap();
    let card = card.unwrap();
    let client = A2AClientFactory::builder()
        .preferred_bindings(vec![TRANSPORT_PROTOCOL_JSONRPC.to_owned()])
        .build()
        .create_from_card(&card)
        .await
        .unwrap();
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        client.send_streaming_message(&SendMessageRequest {
            message: Message::new(
                Role::User,
                vec![Part::text("produce a correlated runtime policy analysis")],
            ),
            configuration: None,
            metadata: None,
            tenant: None,
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let StreamResponse::Task(first_task) = first else {
        panic!("first streaming response must be Task");
    };
    assert_eq!(first_task.status.state, TaskState::Working);
    let task_id = first_task.id.clone();
    let context_id = first_task.context_id.clone();
    let remaining = tokio::time::timeout(Duration::from_secs(5), stream.collect::<Vec<_>>())
        .await
        .unwrap()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let completed = remaining
        .iter()
        .find_map(|event| match event {
            StreamResponse::Task(task) if task.status.state == TaskState::Completed => Some(task),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing accepted terminal task: {remaining:?}"));
    assert_eq!(completed.id, task_id);
    assert_eq!(completed.context_id, context_id);
    assert_eq!(completed.artifacts.as_ref().map(Vec::len), Some(1));
    assert_eq!(
        completed.metadata.as_ref().unwrap()["smesh.completionPolicy"]["status"],
        "accepted"
    );
    let artifact = &completed.artifacts.as_ref().unwrap()[0];
    let [part] = artifact.parts.as_slice() else {
        panic!("accepted harness artifact must have one part");
    };
    let PartContent::Text(content) = &part.content else {
        panic!("accepted harness artifact must be text");
    };
    let terminal_signal = serde_json::from_str::<serde_json::Value>(content).unwrap()["signalHash"]
        .as_str()
        .unwrap()
        .to_owned();
    let terminal_subject = completed.metadata.as_ref().unwrap()["smesh.completionPolicy"]["record"]
        ["artifactSetDigest"]
        .as_str()
        .unwrap()
        .to_owned();

    trace.lock().unwrap().push(TraceEvent {
        kind: "terminal",
        task_id: task_id.clone(),
        context_id: context_id.clone(),
        signal_hash: Some(terminal_signal),
        artifact_name: artifact.name.clone(),
        subject_digest: Some(terminal_subject),
        evidence_id: None,
        evidence_digest: None,
        role: None,
        process_id: None,
        detail: None,
    });
    let trace_events = trace.lock().unwrap().clone();
    assert!(
        trace_events
            .iter()
            .all(|event| { event.task_id == task_id && event.context_id == context_id })
    );
    let runtime_signal = trace_events
        .iter()
        .find(|event| event.kind == "runtime-task")
        .and_then(|event| event.signal_hash.as_deref())
        .unwrap();
    let accepted_subject = trace_events
        .iter()
        .find(|event| event.kind == "terminal")
        .and_then(|event| event.subject_digest.as_deref())
        .unwrap();
    for event in trace_events.iter().filter(|event| {
        matches!(
            event.kind,
            "candidate" | "specialist" | "evidence" | "terminal"
        )
    }) {
        assert_eq!(event.signal_hash.as_deref(), Some(runtime_signal));
        assert_eq!(event.subject_digest.as_deref(), Some(accepted_subject));
        assert_eq!(
            event.artifact_name.as_deref(),
            Some("runtime-analysis.json")
        );
    }
    assert!(
        trace_events
            .iter()
            .filter(|event| event.kind == "evidence")
            .all(|event| event.evidence_id.is_some() && event.evidence_digest.is_some())
    );
    let receipt_evidence = completed.metadata.as_ref().unwrap()["smesh.completionPolicy"]["record"]
        ["evidenceHashes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    let traced_evidence = trace_events
        .iter()
        .filter(|event| event.kind == "evidence")
        .filter_map(|event| event.evidence_digest.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(traced_evidence, receipt_evidence);
    let specialist_events = trace_events
        .iter()
        .filter(|event| event.kind == "specialist")
        .collect::<Vec<_>>();
    assert_eq!(specialist_events.len(), 3);
    assert_eq!(
        trace_events
            .iter()
            .filter(|event| event.kind == "specialist-attempt")
            .count(),
        3
    );
    assert_eq!(
        trace_events
            .iter()
            .filter(|event| event.kind == "specialist-reaped")
            .count(),
        3,
        "every specialist child must be reaped"
    );
    assert_eq!(
        specialist_events
            .iter()
            .filter_map(|event| event.role.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    assert!(
        specialist_events
            .iter()
            .all(|event| event.process_id.is_some())
    );
    assert!(
        specialist_events
            .iter()
            .filter_map(|event| event.process_id)
            .collect::<std::collections::HashSet<_>>()
            .len()
            >= 2
    );
    for role in ["review", "test", "contradiction"] {
        assert_eq!(
            trace_events
                .iter()
                .filter(|event| {
                    event.kind == "specialist-attempt" && event.role.as_deref() == Some(role)
                })
                .count(),
            1,
            "hidden specialist retry detected for {role}"
        );
    }

    let trace_path = trace_artifact.finish();
    let persisted: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(&trace_path).unwrap()).unwrap();
    assert_eq!(persisted.len(), trace_events.len());
    std::fs::remove_file(trace_path).unwrap();

    server.abort();
    worker.shutdown().await.unwrap();
    mesh.shutdown().await;
}
