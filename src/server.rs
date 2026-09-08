use std::sync::Arc;
use std::time::Duration;

use a2a::{A2AError, AgentCard, ListTasksRequest, ListTasksResponse, Task};
use a2a_server::{DefaultRequestHandler, RequestHandler, StaticAgentCard, TaskStore};
use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{Extension, FromRequestParts, OriginalUri, Path};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use tower_http::limit::RequestBodyLimitLayer;

use crate::{
    ArtifactGcHandle, ArtifactOrphanScannerHandle, ArtifactPromoterHandle, BoundedTaskStore,
    CompletionPolicySpec, DurableAuthority, DurableLoopbackEndpoint, ExecutionLimits,
    InjectedClock, InputLimits, IntoDurableAuthority, MeshDispatcher, Operation, OwnedTaskScope,
    PolicyError, RuntimeEventCapture, SmeshExecutor, SqliteTaskStore, VersionedCompletionPolicy,
    auth::{AuthState, authenticate_request},
    authorization::{AuthorizationMiddlewareState, AuthorizationPolicy, authorize_request},
    build_agent_card, build_secured_agent_card_with_policy,
    card::LiveAgentCard,
    content_digest,
    durable_authority::DurableAuthorityParts,
    durable_handler::DurableRequestHandler,
    guard::GuardedRequestHandler,
    outbox_driver::{
        DurableDriverHandle, spawn_durable_driver, spawn_durable_driver_with_telemetry,
    },
    spawn_artifact_gc, spawn_artifact_orphan_scanner, spawn_artifact_promoter,
    spawn_artifact_promoter_with_telemetry,
};

struct SharedTaskStore<S>(Arc<S>);

async fn quota_retry_after_header(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}

#[allow(clippy::too_many_lines)]
async fn artifact_resolver(
    method: Method,
    Path(artifact_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    Extension(authority): Extension<Arc<dyn DurableAuthority>>,
    Extension(context): Extension<Arc<crate::AuthorizationContext>>,
    headers: axum::http::HeaderMap,
) -> Response {
    const NOT_FOUND: &str = "artifact not found";
    let Some(artifact_authority) = authority.artifact_authority() else {
        return (StatusCode::NOT_FOUND, NOT_FOUND).into_response();
    };
    if headers.contains_key(header::RANGE) {
        return (
            StatusCode::RANGE_NOT_SATISFIABLE,
            [(header::ACCEPT_RANGES, "none")],
            "range requests are unsupported",
        )
            .into_response();
    }
    if !matches!(method, Method::GET | Method::HEAD)
        || !canonical_artifact_resolver_request(&uri, &artifact_id)
        || context.authorize(Operation::ArtifactResolve).is_err()
    {
        return (StatusCode::NOT_FOUND, NOT_FOUND).into_response();
    }
    let Ok(visibility) = context.visibility(Operation::ArtifactResolve) else {
        return (StatusCode::NOT_FOUND, NOT_FOUND).into_response();
    };
    let Ok(scope) = OwnedTaskScope::new(context.tenant_id(), context.account_id(), visibility)
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(owner_digest) = authority.authorization_resource_digest(context.account_id()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(resource_digest) = authority.authorization_resource_digest(&artifact_id) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_millis()).ok())
        .unwrap_or(0);
    let Ok(subject) = crate::QuotaSubject::new(
        context.tenant_id(),
        context.account_id(),
        context.principal_scope(),
    ) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let decision_id = content_digest(&rand::random::<[u8; 32]>());
    let quota_intent = if let Some(policy) = authority.quota_policy_snapshot() {
        match policy.operation_intent(&subject, crate::QuotaOperation::TaskGet, &decision_id, 0) {
            Ok(intent) => Some(intent),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        None
    };
    let Ok(audit) = crate::AuthorizationAuditInput::new(
        decision_id,
        context.tenant_id(),
        context.account_id(),
        context.policy_id(),
        context.policy_revision(),
        context.policy_digest(),
        "artifactResolve",
        crate::AuthorizationDecisionEffect::Deny,
        "preflight",
        "artifact",
        resource_digest,
        None,
        now,
    ) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let resolution = match artifact_authority
        .begin_artifact_resolution(
            &scope,
            &artifact_id,
            None,
            &owner_digest,
            artifact_authority
                .artifact_runtime_limits()
                .read_lease_millis,
            quota_intent.as_ref(),
            audit,
            now,
        )
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return (StatusCode::NOT_FOUND, NOT_FOUND).into_response(),
        Err(error) => {
            return if error.code == -32_010 {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
            .into_response();
        }
    };
    let metadata = resolution.metadata();
    let Ok(bytes) = artifact_authority
        .read_artifact_resolution(&resolution)
        .await
    else {
        let _ = artifact_authority
            .finish_artifact_resolution(&resolution, 0, false)
            .await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if !matches!(
        artifact_authority
            .finish_artifact_resolution(&resolution, bytes.len() as u64, true)
            .await,
        Ok(true)
    ) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let Ok(etag) = HeaderValue::from_str(&format!("\"{}\"", metadata.content_digest)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(media) = HeaderValue::from_str(&metadata.media_type) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(length) = HeaderValue::from_str(&metadata.plaintext_length.to_string()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = Response::new(if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(bytes)
    });
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(header::ETAG, etag);
    response.headers_mut().insert(header::CONTENT_TYPE, media);
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, length);
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("none"));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, no-transform"),
    );
    response.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn canonical_artifact_resolver_request(uri: &Uri, artifact_id: &str) -> bool {
    crate::artifact::validate_artifact_id(artifact_id).is_ok()
        && uri.query().is_none()
        && uri.path() == format!("/artifacts/v1/{artifact_id}")
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewBody {
    evidence_hashes: Vec<String>,
    artifact_hashes: Vec<String>,
    artifact_manifest_digest: String,
    uncertainty_acknowledged: bool,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecisionBody {
    decision: crate::HumanDecision,
    rationale: String,
}

#[derive(Clone)]
struct RatificationOrigin(Arc<str>);

const RATIFICATION_CONSOLE: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SMESH Human Ratification</title><script src="/ratification/console.js" defer></script></head><body><main id="ratification"><h1>Human Ratification</h1><form id="bootstrap"><label for="task">Task</label><input id="task" required autocomplete="off"><label for="tenant">Tenant (optional)</label><input id="tenant" autocomplete="off"><label for="token">Bearer token (optional for mTLS)</label><input id="token" type="password" autocomplete="off"><button id="load" type="submit">Load</button></form><output id="status" data-state="BOOTSTRAP_LOCKED" aria-live="polite">Enter a task to begin.</output><section id="review-surface" hidden><h2>Review packet</h2><dl id="packet"></dl><fieldset id="review-items"><legend>Required acknowledgements</legend></fieldset><button id="review-submit" type="button" disabled>Record review</button><fieldset id="decisions"><legend>Decision</legend><label for="rationale">Rationale</label><textarea id="rationale"></textarea><button id="approve" type="button" disabled>Approve</button><button id="reject" type="button" disabled>Reject</button><button id="amend" type="button" disabled>Amend</button></fieldset></section><button id="retry" type="button" hidden>Retry</button></main></body></html>"#;

const RATIFICATION_CONSOLE_SCRIPT: &str = r"'use strict';
(()=>{
const byId=id=>document.getElementById(id), form=byId('bootstrap'), task=byId('task'), tenant=byId('tenant'), token=byId('token'), status=byId('status'), surface=byId('review-surface'), packet=byId('packet'), items=byId('review-items'), review=byId('review-submit'), retry=byId('retry'), rationale=byId('rationale'), decisions=['approve','reject','amend'].map(byId);
let bearer='', taskId='', tenantId='', view=null, etag='', busy=false, pending=null, terminal=false, epoch=0, representation=0, controller=null;
function setState(state,message){status.dataset.state=state;status.textContent=message;}
function lock(){review.disabled=true;for(const button of decisions)button.disabled=true;}
function erase(){epoch++;controller?.abort();controller=null;view=null;etag='';busy=false;pending=null;terminal=false;lock();surface.hidden=true;packet.replaceChildren();items.replaceChildren(items.querySelector('legend'));rationale.value='';retry.hidden=true;}
function bootstrapLock(){erase();setState('BOOTSTRAP_LOCKED','Enter a task to begin.');}
function identity(){return Object.freeze({bearer,taskId,tenantId});}
function current(requestEpoch,id){return requestEpoch===epoch&&id.bearer===bearer&&id.taskId===taskId&&id.tenantId===tenantId;}
function headers(id,mutation){const value={accept:'application/json'};if(id.bearer)value.authorization=`Bearer ${id.bearer}`;if(id.tenantId)value['x-smesh-tenant']=id.tenantId;if(mutation){value['content-type']='application/json';value['if-match']=mutation.etag;value['idempotency-key']=mutation.nonce;}return value;}
function text(parent,name,value){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=name;dd.textContent=String(value??'');parent.append(dt,dd);}
function checkbox(id,labelText,value,kind){const label=document.createElement('label'),box=document.createElement('input'),span=document.createElement('span');box.type='checkbox';box.id=id;box.dataset.kind=kind;box.value=value;span.textContent=labelText;label.append(box,span);items.append(label);box.addEventListener('change',gate);}
function gate(){if(!view||busy||terminal)return lock();const boxes=[...items.querySelectorAll('input[type=checkbox]')];review.disabled=view.reviewedByCurrentActor||boxes.length===0||boxes.some(box=>!box.checked);const allow=view.reviewedByCurrentActor;for(const button of decisions)button.disabled=!allow;}
function render(dto,responseEtag){view=dto;etag=responseEtag||dto.etag;representation++;surface.hidden=false;packet.replaceChildren();items.replaceChildren(items.querySelector('legend'));text(packet,'Task',dto.packet.taskId);text(packet,'Checkpoint',dto.packet.checkpoint);text(packet,'Policy',dto.packet.completionPolicyId);dto.packet.evidence.forEach((value,index)=>text(packet,`Evidence ${index+1}`,value));dto.packet.artifacts.forEach((artifact,index)=>{text(packet,`Artifact ${index+1}`,`${artifact.name} (${artifact.mediaType}) ${artifact.digest}`);text(packet,`Artifact ${index+1} exact publication JSON`,artifact.canonicalJson);});text(packet,'Artifact manifest digest',dto.packet.artifactSetDigest);text(packet,'Uncertainty',dto.packet.uncertaintySummary);dto.packet.evidenceHashes.forEach((hash,index)=>checkbox(`ack-evidence-${index}`,`Acknowledge evidence ${index+1}: ${hash}`,hash,'evidence'));dto.packet.artifacts.forEach((artifact,index)=>checkbox(`ack-artifact-${index}`,`Acknowledge artifact ${index+1}: ${artifact.digest}`,artifact.digest,'artifact'));checkbox('ack-manifest','Acknowledge exact publication manifest',dto.packet.artifactSetDigest,'manifest');checkbox('ack-uncertainty','Acknowledge uncertainty','true','uncertainty');terminal=Boolean(dto.terminalDecision)||dto.phase==='canceled'||dto.phase==='superseded';busy=false;pending=null;retry.hidden=true;if(terminal){surface.hidden=true;packet.replaceChildren();items.replaceChildren(items.querySelector('legend'));rationale.value='';lock();setState('TERMINAL',dto.terminalDecision?`Terminal decision: ${dto.terminalDecision}`:`Ratification ${dto.phase}.`);}else if(dto.reviewedByCurrentActor){setState('REVIEWED','Review recorded. Choose a decision.');gate();}else{setState('AWAITING_REVIEW','Acknowledge every item to record review.');gate();}}
function requestLock(state,message,operation,canRetry){erase();pending=operation;retry.hidden=!canRetry;setState(state,message);}
async function load(id=identity()){erase();const requestEpoch=epoch;busy=true;const operation=()=>load(id);pending=operation;controller=new AbortController();lock();setState('LOADING','Loading review packet.');try{const response=await fetch(`/ratification/v1/tasks/${encodeURIComponent(id.taskId)}`,{headers:headers(id),cache:'no-store',credentials:'same-origin',signal:controller.signal});if(!current(requestEpoch,id))return;if(response.status===401||response.status===403)return requestLock('AUTH_LOCKED','Authentication required. Enter credentials and load again.',null,false);if(!response.ok)return requestLock('ERROR_LOCKED','Request failed. Retry explicitly.',operation,true);const dto=await response.json();if(current(requestEpoch,id))render(dto,response.headers.get('etag'));}catch(error){if(current(requestEpoch,id)&&error.name!=='AbortError')requestLock('ERROR_LOCKED','Request failed. Retry explicitly.',operation,true);}finally{status.dispatchEvent(new Event('smesh-ratification-request-complete'));}}
async function send(operation){if(busy||terminal)return;const requestEpoch=epoch;busy=true;pending=()=>send(operation);controller=new AbortController();lock();retry.hidden=true;setState(operation.action==='review'?'REVIEW_SUBMITTING':'DECISION_SUBMITTING',operation.action==='review'?'Recording review.':'Recording decision.');try{const response=await fetch(operation.url,{method:'POST',headers:headers(operation.identity,operation),body:operation.body,cache:'no-store',credentials:'same-origin',signal:controller.signal});if(!current(requestEpoch,operation.identity))return;if(response.status===401||response.status===403)return requestLock('AUTH_LOCKED','Authentication required. Enter credentials and load again.',null,false);if(response.status===412){erase();setState('STALE','Review packet changed; reloading.');return load(operation.identity);}if(!response.ok)return requestLock('ERROR_LOCKED','Request failed. Retry explicitly.',()=>send(operation),true);const receipt=await response.json();if(!current(requestEpoch,operation.identity))return;etag=response.headers.get('etag')||receipt.etag;view.revision=receipt.revision;busy=false;pending=null;if(operation.action==='review'){view.reviewedByCurrentActor=true;setState('REVIEWED','Review recorded. Choose a decision.');gate();}else{terminal=true;surface.hidden=true;packet.replaceChildren();items.replaceChildren(items.querySelector('legend'));rationale.value='';lock();setState('TERMINAL','Decision recorded.');}}catch(error){if(current(requestEpoch,operation.identity)&&error.name!=='AbortError')requestLock('ERROR_LOCKED','Request failed. Retry explicitly.',()=>send(operation),true);}}
function mutate(action,body){if(busy||terminal||!view)return;const encoded=JSON.stringify(body),id=identity(),capturedEtag=etag;const semantic=JSON.stringify([id.bearer,id.tenantId,id.taskId,view.packet.generation,representation,capturedEtag,action,encoded]);const operation=Object.freeze({action,body:encoded,identity:id,etag:capturedEtag,nonce:crypto.randomUUID(),semantic,url:`/ratification/v1/tasks/${encodeURIComponent(id.taskId)}/${action==='review'?'review':'decision'}`});send(operation);}
review.addEventListener('click',()=>{if(review.disabled)return;const checked=[...items.querySelectorAll('input:checked')];mutate('review',{evidenceHashes:checked.filter(x=>x.dataset.kind==='evidence').map(x=>x.value),artifactHashes:checked.filter(x=>x.dataset.kind==='artifact').map(x=>x.value),artifactManifestDigest:checked.find(x=>x.dataset.kind==='manifest')?.value??'',uncertaintyAcknowledged:checked.some(x=>x.dataset.kind==='uncertainty')});});
for(const button of decisions)button.addEventListener('click',()=>{if(!button.disabled)mutate(button.id,{decision:button.id,rationale:rationale.value});});
retry.addEventListener('click',()=>{if(pending){const operation=pending;busy=false;operation();}});
for(const input of [task,tenant,token])input.addEventListener('input',bootstrapLock);
form.addEventListener('submit',event=>{event.preventDefault();bearer=token.value;token.value='';taskId=task.value;tenantId=tenant.value;load(identity());});
lock();
})();";

async fn ratification_console() -> Response {
    ratification_static_response("text/html; charset=utf-8", RATIFICATION_CONSOLE.to_owned())
}

async fn ratification_console_script() -> Response {
    ratification_static_response(
        "text/javascript; charset=utf-8",
        RATIFICATION_CONSOLE_SCRIPT.to_owned(),
    )
}

fn ratification_static_response(content_type: &'static str, body: String) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], body).into_response()
}

#[derive(Clone)]
struct RatificationMutation {
    view: crate::RatificationView,
    idempotency_key: String,
    expected_revision: u64,
    replay_candidate: bool,
}

#[allow(clippy::too_many_lines)] // Ordered mutation gates and replay exception form one boundary.
async fn ratification_mutation_policy(
    Extension(expected_origin): Extension<RatificationOrigin>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let operation = if request.uri().path().ends_with("/review") {
        Operation::RatificationReview
    } else {
        Operation::RatificationDecide
    };
    let Some(context) = request
        .extensions()
        .get::<Arc<crate::AuthorizationContext>>()
        .cloned()
    else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if context.authorize(operation).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !single_header_equals(
        request.headers(),
        header::ORIGIN,
        expected_origin.0.as_bytes(),
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !single_header_equals(request.headers(), header::CONTENT_TYPE, b"application/json") {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let match_values: Vec<_> = request.headers().get_all(header::IF_MATCH).iter().collect();
    if match_values.is_empty() {
        return StatusCode::PRECONDITION_REQUIRED.into_response();
    }
    let [match_value] = match_values.as_slice() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !valid_ratification_match(match_value.as_bytes()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let if_match = match_value
        .to_str()
        .expect("validated visible ASCII")
        .to_owned();
    let idempotency_values: Vec<_> = request
        .headers()
        .get_all("idempotency-key")
        .iter()
        .collect();
    let [idempotency_value] = idempotency_values.as_slice() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let bytes = idempotency_value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || bytes.contains(&b',')
        || !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let idempotency_key = String::from_utf8(bytes.to_vec()).expect("visible ASCII is UTF-8");
    let Some(authority) = request
        .extensions()
        .get::<Arc<dyn DurableAuthority>>()
        .cloned()
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(ratification) = authority.ratification_authority() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(scope) = ratification_scope(&context, operation) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let (mut parts, body) = request.into_parts();
    let Ok(Path(task_id)) = Path::<String>::from_request_parts(&mut parts, &()).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut request = axum::extract::Request::from_parts(parts, body);
    let mut view = match ratification.ratification_view(&scope, &task_id).await {
        Ok(Some(view)) => view,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let Ok(current_etag) = ratification_etag(&view, &context) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let can_replay = |candidate: &crate::RatificationView| match operation {
        Operation::RatificationReview => candidate.history.iter().any(|receipt| {
            matches!(
                receipt.action,
                crate::HumanRatificationAction::ReviewAcknowledged
            )
        }),
        Operation::RatificationDecide => candidate
            .history
            .iter()
            .any(|receipt| matches!(receipt.action, crate::HumanRatificationAction::Decision(_))),
        _ => false,
    };
    let replay_precondition_etag = |candidate: &crate::RatificationView| {
        let mut precondition_view = candidate.clone();
        match operation {
            Operation::RatificationReview => {
                precondition_view.history.clear();
                precondition_view.state = crate::RatificationState::AwaitingReview;
                precondition_view.revision = 0;
            }
            Operation::RatificationDecide
                if matches!(
                    precondition_view
                        .history
                        .last()
                        .map(|receipt| &receipt.action),
                    Some(crate::HumanRatificationAction::Decision(_))
                ) =>
            {
                precondition_view.history.pop();
                precondition_view.state = crate::RatificationState::Reviewed;
                precondition_view.revision = 1;
            }
            _ => {}
        }
        ratification_etag(&precondition_view, &context)
    };
    let current_can_replay = can_replay(&view);
    let mut replay_candidate = false;
    if current_can_replay {
        let Ok(precondition_etag) = replay_precondition_etag(&view) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        replay_candidate = if_match.as_bytes() == precondition_etag.as_bytes();
    } else if if_match.as_bytes() == current_etag.as_bytes() {
        let valid_current_phase = match operation {
            Operation::RatificationReview => {
                matches!(view.state, crate::RatificationState::AwaitingReview)
            }
            Operation::RatificationDecide => {
                matches!(view.state, crate::RatificationState::Reviewed)
            }
            _ => false,
        };
        if !valid_current_phase {
            return StatusCode::PRECONDITION_FAILED.into_response();
        }
        replay_candidate = false;
    }
    if !replay_candidate && (current_can_replay || if_match.as_bytes() != current_etag.as_bytes()) {
        let action = match operation {
            Operation::RatificationReview => crate::RatificationReplayAction::Review,
            Operation::RatificationDecide => crate::RatificationReplayAction::Decision,
            _ => return StatusCode::PRECONDITION_FAILED.into_response(),
        };
        let Ok(historical) = ratification
            .ratification_replay_candidate(
                &scope,
                &task_id,
                context.account_id(),
                &idempotency_key,
                action,
            )
            .await
        else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        if let Some(historical) = historical {
            let Ok(precondition_etag) = replay_precondition_etag(&historical) else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            if !can_replay(&historical) || if_match.as_bytes() != precondition_etag.as_bytes() {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
            view = historical;
            replay_candidate = true;
        } else {
            return StatusCode::PRECONDITION_FAILED.into_response();
        }
    }
    let expected_revision = if replay_candidate {
        // A precondition for a generation with this action already committed
        // reaches the durable authority only as a replay candidate. The
        // authority authenticates the exact actor/key/body semantics before
        // returning the original receipt and appending this attempt's audit.
        match operation {
            Operation::RatificationReview
                if view.history.iter().any(|receipt| {
                    matches!(
                        receipt.action,
                        crate::HumanRatificationAction::ReviewAcknowledged
                    )
                }) =>
            {
                0
            }
            Operation::RatificationDecide
                if view.history.iter().any(|receipt| {
                    matches!(receipt.action, crate::HumanRatificationAction::Decision(_))
                }) =>
            {
                1
            }
            _ => return StatusCode::PRECONDITION_FAILED.into_response(),
        }
    } else {
        view.revision
    };

    request.extensions_mut().insert(RatificationMutation {
        view,
        idempotency_key,
        expected_revision,
        replay_candidate,
    });
    next.run(request).await
}

fn single_header_equals(
    headers: &axum::http::HeaderMap,
    name: header::HeaderName,
    expected: &[u8],
) -> bool {
    let values: Vec<_> = headers.get_all(name).iter().collect();
    matches!(values.as_slice(), [value] if value.as_bytes() == expected && !value.as_bytes().contains(&b','))
}

fn valid_ratification_match(bytes: &[u8]) -> bool {
    bytes.len() == 82
        && bytes.starts_with(b"\"ratification-v1:")
        && bytes.ends_with(b"\"")
        && bytes[17..81]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

async fn ratification_response_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
    );
    response.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    for name in [
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        header::ACCESS_CONTROL_ALLOW_METHODS,
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        header::ACCESS_CONTROL_MAX_AGE,
    ] {
        response.headers_mut().remove(name);
    }
    response
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserRatificationPacket {
    task_id: String,
    generation: u64,
    task_revision: u64,
    packet_hash: String,
    checkpoint: String,
    checkpoint_hash: String,
    completion_policy_id: String,
    completion_policy_version: u32,
    completion_policy_hash: String,
    evidence: Vec<String>,
    evidence_hashes: Vec<String>,
    artifact_set_digest: String,
    artifacts: Vec<crate::ReviewArtifact>,
    uncertainty_summary: String,
    created_at_millis: i64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserRatificationHistory {
    revision: u64,
    action: crate::HumanRatificationAction,
    rationale: String,
    occurred_at_millis: i64,
    receipt_hash: String,
    previous_receipt_hash: Option<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserRatificationView {
    packet: BrowserRatificationPacket,
    history: Vec<BrowserRatificationHistory>,
    phase: crate::RatificationState,
    revision: u64,
    etag: String,
    reviewed_by_current_actor: bool,
    terminal_decision: Option<crate::HumanDecision>,
}

impl BrowserRatificationView {
    fn from_authority(
        view: crate::RatificationView,
        context: &crate::AuthorizationContext,
    ) -> Result<Self, ()> {
        let etag = ratification_etag(&view, context)?;
        let actor = context.account_id();
        let reviewed_by_current_actor = view.history.iter().any(|receipt| {
            receipt.account_id == actor
                && matches!(
                    receipt.action,
                    crate::HumanRatificationAction::ReviewAcknowledged
                )
        });
        let terminal_decision = view.history.iter().rev().find_map(|receipt| {
            if let crate::HumanRatificationAction::Decision(decision) = &receipt.action {
                Some(decision.clone())
            } else {
                None
            }
        });
        let packet = BrowserRatificationPacket {
            task_id: view.packet.task_id.clone(),
            generation: view.packet.generation,
            task_revision: view.packet.task_revision,
            packet_hash: view.packet.packet_hash.clone(),
            checkpoint: view.packet.checkpoint.clone(),
            checkpoint_hash: view.packet.checkpoint_hash.clone(),
            completion_policy_id: view.packet.completion_policy_id.clone(),
            completion_policy_version: view.packet.completion_policy_version,
            completion_policy_hash: view.packet.completion_policy_hash.clone(),
            evidence: view.packet.evidence.clone(),
            evidence_hashes: view.packet.evidence_hashes.clone(),
            artifact_set_digest: view.packet.artifact_set_digest.clone(),
            artifacts: view.packet.artifacts.clone(),
            uncertainty_summary: view.packet.uncertainty_summary.clone(),
            created_at_millis: view.packet.created_at_millis,
        };
        let history = view
            .history
            .into_iter()
            .map(|receipt| BrowserRatificationHistory {
                revision: receipt.revision,
                action: receipt.action,
                rationale: receipt.rationale,
                occurred_at_millis: receipt.occurred_at_millis,
                receipt_hash: receipt.receipt_hash,
                previous_receipt_hash: receipt.previous_receipt_hash,
            })
            .collect();
        Ok(Self {
            packet,
            history,
            phase: view.state,
            revision: view.revision,
            etag,
            reviewed_by_current_actor,
            terminal_decision,
        })
    }
}

fn ratification_etag(
    view: &crate::RatificationView,
    context: &crate::AuthorizationContext,
) -> Result<String, ()> {
    let binding = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "view": view,
        "tenantId": context.tenant_id(),
        "accountId": context.account_id(),
        "principalScope": context.principal_scope(),
        "authenticationMethod": authentication_method_name(context),
        "authorizationPolicyId": context.policy_id(),
        "authorizationPolicyRevision": context.policy_revision(),
        "authorizationPolicyDigest": context.policy_digest(),
    }))
    .map_err(|_| ())?;
    let digest = content_digest(&binding);
    Ok(format!(
        "\"ratification-v1:{}\"",
        digest.strip_prefix("sha256:").ok_or(())?
    ))
}

async fn ratification_view(
    Path(task_id): Path<String>,
    Extension(authority): Extension<Arc<dyn DurableAuthority>>,
    Extension(context): Extension<Arc<crate::AuthorizationContext>>,
) -> Response {
    let Ok(scope) = ratification_scope(&context, Operation::RatificationRead) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Some(ratification) = authority.ratification_authority() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match ratification.ratification_view(&scope, &task_id).await {
        Ok(Some(view)) => {
            let Ok(browser) = BrowserRatificationView::from_authority(view, &context) else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            let Ok(etag) = HeaderValue::from_str(&browser.etag) else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            let mut response = axum::Json(browser).into_response();
            response.headers_mut().insert(header::ETAG, etag);
            response
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn ratification_view_at_generation(
    Path((task_id, generation)): Path<(String, u64)>,
    Extension(authority): Extension<Arc<dyn DurableAuthority>>,
    Extension(context): Extension<Arc<crate::AuthorizationContext>>,
) -> Response {
    let Ok(scope) = ratification_scope(&context, Operation::RatificationRead) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if generation == 0 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(ratification) = authority.ratification_authority() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match ratification
        .ratification_view_at_generation(&scope, &task_id, generation)
        .await
    {
        Ok(Some(view)) => {
            let Ok(browser) = BrowserRatificationView::from_authority(view, &context) else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            let Ok(etag) = HeaderValue::from_str(&browser.etag) else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            let mut response = axum::Json(browser).into_response();
            response.headers_mut().insert(header::ETAG, etag);
            response
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn ratification_review(
    Path(task_id): Path<String>,
    Extension(authority): Extension<Arc<dyn DurableAuthority>>,
    Extension(context): Extension<Arc<crate::AuthorizationContext>>,
    Extension(clock): Extension<InjectedClock>,
    Extension(mutation): Extension<RatificationMutation>,
    axum::Json(body): axum::Json<ReviewBody>,
) -> Response {
    let Ok(scope) = ratification_scope(&context, Operation::RatificationReview) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Some(ratification) = authority.ratification_authority() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let expected_revision = mutation.expected_revision;
    let packet = mutation.view.packet;
    let artifact_hashes = packet
        .artifacts
        .iter()
        .map(|artifact| artifact.digest.clone())
        .collect::<Vec<_>>();
    if body.evidence_hashes != packet.evidence_hashes
        || body.artifact_hashes != artifact_hashes
        || body.artifact_manifest_digest != packet.artifact_set_digest
        || !body.uncertainty_acknowledged
    {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let now = clock.now();
    let command = crate::ReviewAcknowledgement {
        tenant_id: context.tenant_id().to_owned(),
        task_id: task_id.clone(),
        generation: packet.generation,
        account_id: context.account_id().to_owned(),
        authorization_policy_id: context.policy_id().to_owned(),
        authorization_policy_revision: context.policy_revision(),
        authorization_policy_digest: context.policy_digest().to_owned(),
        principal_scope: context.principal_scope().to_owned(),
        authentication_method: authentication_method_name(&context),
        context_id: packet.context_id.clone(),
        request_digest: packet.request_digest.clone(),
        ratification_key_generation: packet.ratification_key_generation.clone(),
        expected_revision,
        checkpoint_hash: packet.checkpoint_hash.clone(),
        packet_hash: packet.packet_hash.clone(),
        evidence_hashes: body.evidence_hashes,
        artifact_hashes: body.artifact_hashes,
        artifact_manifest_digest: body.artifact_manifest_digest,
        uncertainty_acknowledged: body.uncertainty_acknowledged,
        idempotency_key: mutation.idempotency_key,
        reviewed_at_millis: now,
    };
    let Ok(audit) = ratification_audit(
        &authority,
        &context,
        &task_id,
        &packet.packet_hash,
        "ratificationReview",
        now,
    ) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ratification_result(
        ratification
            .acknowledge_ratification_review(&scope, command, audit)
            .await,
        ratification,
        &scope,
        &context,
        &task_id,
    )
    .await
}

async fn ratification_decision(
    Path(task_id): Path<String>,
    Extension(authority): Extension<Arc<dyn DurableAuthority>>,
    Extension(context): Extension<Arc<crate::AuthorizationContext>>,
    Extension(clock): Extension<InjectedClock>,
    Extension(mutation): Extension<RatificationMutation>,
    axum::Json(body): axum::Json<DecisionBody>,
) -> Response {
    let Ok(scope) = ratification_scope(&context, Operation::RatificationDecide) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Some(ratification) = authority.ratification_authority() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let expected_revision = mutation.expected_revision;
    let replay_candidate = mutation.replay_candidate;
    let packet = mutation.view.packet;
    let now = clock.now();
    let command = crate::RatificationCommand {
        tenant_id: context.tenant_id().to_owned(),
        task_id: task_id.clone(),
        generation: packet.generation,
        account_id: context.account_id().to_owned(),
        authorization_policy_id: context.policy_id().to_owned(),
        authorization_policy_revision: context.policy_revision(),
        authorization_policy_digest: context.policy_digest().to_owned(),
        principal_scope: context.principal_scope().to_owned(),
        authentication_method: authentication_method_name(&context),
        context_id: packet.context_id.clone(),
        request_digest: packet.request_digest.clone(),
        ratification_key_generation: packet.ratification_key_generation.clone(),
        expected_revision,
        checkpoint_hash: packet.checkpoint_hash.clone(),
        packet_hash: packet.packet_hash.clone(),
        artifact_manifest_digest: packet.artifact_set_digest.clone(),
        idempotency_key: mutation.idempotency_key,
        decision: body.decision,
        rationale: body.rationale,
        decided_at_millis: now,
    };

    let Ok(audit) = ratification_audit(
        &authority,
        &context,
        &task_id,
        &packet.packet_hash,
        "ratificationDecide",
        now,
    ) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let amendment_quota_intent = if matches!(command.decision, crate::HumanDecision::Amend) {
        let Ok(subject) = crate::QuotaSubject::new(
            context.tenant_id(),
            context.account_id(),
            context.principal_scope(),
        ) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        match authority.quota_policy_snapshot() {
            Some(policy) => match policy.operation_intent(
                &subject,
                crate::QuotaOperation::TaskContinue,
                &command.idempotency_key,
                u64::try_from(command.rationale.len()).unwrap_or(u64::MAX),
            ) {
                Ok(intent) => Some(intent),
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            },
            None => None,
        }
    } else {
        None
    };
    let result = ratification
        .decide_ratification_with_quota(&scope, command, audit, amendment_quota_intent.as_ref())
        .await;
    if replay_candidate && result.as_ref().is_err_and(|error| error.code == -32_621) {
        return StatusCode::PRECONDITION_FAILED.into_response();
    }
    ratification_result(result, ratification, &scope, &context, &task_id).await
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserMutationReceipt {
    revision: u64,
    etag: String,
    action: crate::HumanRatificationAction,
    receipt_hash: String,
}

#[derive(Clone, Copy)]
enum RatificationHttpError {
    PreconditionFailed,
    Conflict,
    Unprocessable,
    Unavailable,
}

impl RatificationHttpError {
    fn from_a2a(error: &a2a::A2AError) -> Self {
        match error.code {
            -32_620 => Self::PreconditionFailed,
            -32_621 => Self::Conflict,
            -32_600 | -32_602 => Self::Unprocessable,
            _ => Self::Unavailable,
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Unprocessable => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[cfg(test)]
mod ratification_http_error_tests {
    use super::*;

    #[test]
    fn typed_ratification_errors_have_distinct_http_statuses() {
        for (code, expected) in [
            (-32_621, StatusCode::CONFLICT),
            (-32_620, StatusCode::PRECONDITION_FAILED),
            (-32_600, StatusCode::UNPROCESSABLE_ENTITY),
            (-32_602, StatusCode::UNPROCESSABLE_ENTITY),
        ] {
            let error = a2a::A2AError::new(code, "redacted");
            assert_eq!(RatificationHttpError::from_a2a(&error).status(), expected);
        }
    }
}

async fn ratification_result(
    result: Result<crate::HumanRatificationReceipt, a2a::A2AError>,
    ratification: &dyn crate::RatificationAuthority,
    scope: &OwnedTaskScope,
    context: &crate::AuthorizationContext,
    task_id: &str,
) -> Response {
    match result {
        Ok(receipt) => {
            let Ok(Some(view)) = ratification
                .ratification_view_at_generation(scope, task_id, receipt.generation)
                .await
            else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            let Ok(etag) = ratification_etag(&view, context) else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            let response = BrowserMutationReceipt {
                revision: receipt.revision,
                etag: etag.clone(),
                action: receipt.action,
                receipt_hash: receipt.receipt_hash,
            };
            let Ok(etag) = HeaderValue::from_str(&etag) else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            let mut response = (StatusCode::CREATED, axum::Json(response)).into_response();
            response.headers_mut().insert(header::ETAG, etag);
            response
        }
        Err(error) => RatificationHttpError::from_a2a(&error)
            .status()
            .into_response(),
    }
}

fn authentication_method_name(context: &crate::AuthorizationContext) -> String {
    match context.authentication_method() {
        crate::auth::AuthenticationMethod::BearerJwt => "bearer-jwt",
        crate::auth::AuthenticationMethod::MutualTls => "mutual-tls",
    }
    .to_owned()
}

fn ratification_scope(
    context: &crate::AuthorizationContext,
    operation: Operation,
) -> Result<OwnedTaskScope, ()> {
    let visibility = context.visibility(operation).map_err(|_| ())?;
    OwnedTaskScope::new_with_principal_and_authentication(
        context.tenant_id(),
        context.account_id(),
        context.principal_scope(),
        visibility,
        authentication_method_name(context),
    )
    .map_err(|_| ())
}

fn ratification_audit(
    authority: &Arc<dyn DurableAuthority>,
    context: &crate::AuthorizationContext,
    task_id: &str,
    packet_hash: &str,
    operation: &str,
    now: i64,
) -> Result<crate::AuthorizationAuditInput, a2a::A2AError> {
    let resource_digest = authority.authorization_resource_digest(packet_hash)?;
    crate::AuthorizationAuditInput::new(
        content_digest(&rand::random::<[u8; 32]>()),
        context.tenant_id(),
        context.account_id(),
        context.policy_id(),
        context.policy_revision(),
        context.policy_digest(),
        operation,
        crate::AuthorizationDecisionEffect::Allow,
        "authorized",
        "ratification",
        resource_digest,
        Some(task_id.to_owned()),
        now,
    )
}

/// A task store that declares whether completion receipts must use durable key material.
#[async_trait]
pub trait CompletionPolicyStore: TaskStore {
    /// Return the durable receipt key for persistent stores, or `None` for ephemeral stores.
    fn durable_receipt_key(&self) -> Option<[u8; 32]>;

    /// Whether `list` is a repository-owned, self-authenticating snapshot source.
    ///
    /// Generic implementations remain false and are checked against current `get`
    /// rows. The two repository stores return true because the guard calls their
    /// `list` method directly and they authenticate frozen pages internally.
    fn list_pages_are_self_authenticating(&self) -> bool {
        false
    }

    /// Validate that a list page originated from this authoritative store.
    ///
    /// Generic stores use current-row validation. Stores that issue frozen snapshots may
    /// override this hook for follow-up pages while retaining authoritative provenance.
    async fn validate_list_page(
        &self,
        request: &ListTasksRequest,
        response: &ListTasksResponse,
    ) -> Result<(), A2AError> {
        validate_current_list_page(self, request, response).await
    }
}

async fn validate_current_list_page<S: TaskStore + Sync + ?Sized>(
    store: &S,
    request: &ListTasksRequest,
    response: &ListTasksResponse,
) -> Result<(), A2AError> {
    for task in &response.tasks {
        let mut expected = store
            .get(&task.id)
            .await?
            .ok_or_else(|| A2AError::task_not_found(&task.id))?;
        if !request.include_artifacts.unwrap_or(false) {
            expected.artifacts = None;
        }
        if let Some(limit) = request
            .history_length
            .and_then(|value| usize::try_from(value).ok())
        {
            if limit == 0 {
                expected.history = None;
            } else if let Some(history) = expected.history.as_mut()
                && history.len() > limit
            {
                history.drain(..history.len() - limit);
            }
        }
        if &expected != task {
            return Err(A2AError::invalid_agent_response());
        }
    }
    Ok(())
}

#[async_trait]
impl CompletionPolicyStore for BoundedTaskStore {
    fn durable_receipt_key(&self) -> Option<[u8; 32]> {
        None
    }

    fn list_pages_are_self_authenticating(&self) -> bool {
        true
    }
}

#[async_trait]
impl CompletionPolicyStore for SqliteTaskStore {
    fn durable_receipt_key(&self) -> Option<[u8; 32]> {
        Some(self.completion_receipt_key())
    }

    fn list_pages_are_self_authenticating(&self) -> bool {
        true
    }
}

impl<S> Clone for SharedTaskStore<S> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

#[async_trait]
impl<S> TaskStore for SharedTaskStore<S>
where
    S: TaskStore,
{
    async fn create(&self, task: Task) -> Result<u64, A2AError> {
        self.0.create(task).await
    }

    async fn update(&self, task: Task) -> Result<u64, A2AError> {
        self.0.update(task).await
    }

    async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError> {
        self.0.get(task_id).await
    }

    async fn list(&self, request: &ListTasksRequest) -> Result<ListTasksResponse, A2AError> {
        self.0.list(request).await
    }
}

#[async_trait]
impl<S> CompletionPolicyStore for SharedTaskStore<S>
where
    S: CompletionPolicyStore,
{
    fn durable_receipt_key(&self) -> Option<[u8; 32]> {
        self.0.durable_receipt_key()
    }

    fn list_pages_are_self_authenticating(&self) -> bool {
        self.0.list_pages_are_self_authenticating()
    }

    async fn validate_list_page(
        &self,
        request: &ListTasksRequest,
        response: &ListTasksResponse,
    ) -> Result<(), A2AError> {
        self.0.validate_list_page(request, response).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    pub public_base_url: String,
    pub gateway_node_id: String,
    pub input_limits: InputLimits,
    pub max_body_bytes: usize,
    pub max_tasks: usize,
    pub execution_limits: ExecutionLimits,
}

impl GatewayConfig {
    #[must_use]
    pub fn new(public_base_url: impl Into<String>, gateway_node_id: impl Into<String>) -> Self {
        Self {
            public_base_url: public_base_url.into(),
            gateway_node_id: gateway_node_id.into(),
            input_limits: InputLimits::default(),
            max_body_bytes: 128 * 1024,
            max_tasks: 1024,
            execution_limits: ExecutionLimits::default(),
        }
    }
}

/// Structured owner for the durable unary router and its joinable outbox driver.
pub struct DurableGateway {
    router: Option<Router>,
    projector: Option<crate::telemetry::AuditProjectorWorker>,
    callback_worker: Option<crate::CallbackWorkerHandle>,
    push_readiness: Arc<crate::push::PushReadiness>,
    driver: Option<DurableDriverHandle>,
    promoter: Option<ArtifactPromoterHandle>,
    gc: Option<ArtifactGcHandle>,
    orphan_scanner: Option<ArtifactOrphanScannerHandle>,
    authority: Option<Arc<dyn DurableAuthority>>,
    #[cfg(test)]
    shutdown_test_probes: Vec<GatewayShutdownTestProbe>,
}

#[cfg(test)]
struct GatewayShutdownTestProbe {
    cancel: tokio_util::sync::CancellationToken,
    join: Option<tokio::task::JoinHandle<()>>,
}

#[cfg(test)]
impl GatewayShutdownTestProbe {
    fn spawn() -> (
        Self,
        tokio::sync::oneshot::Receiver<()>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let cancel = tokio_util::sync::CancellationToken::new();
        let stopped = cancel.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let joined = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_joined = Arc::clone(&joined);
        let join = tokio::spawn(async move {
            let _ = started_tx.send(());
            stopped.cancelled().await;
            worker_joined.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        (
            Self {
                cancel,
                join: Some(join),
            },
            started_rx,
            joined,
        )
    }

    async fn shutdown(mut self) -> Result<(), A2AError> {
        self.cancel.cancel();
        let mut join = self
            .join
            .take()
            .expect("gateway shutdown test probe owns its join");
        match tokio::time::timeout(Duration::from_secs(5), &mut join).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(A2AError::internal(
                "gateway shutdown test probe join failed",
            )),
            Err(_) => {
                join.abort();
                let _ = join.await;
                Err(A2AError::internal("gateway shutdown test probe timed out"))
            }
        }
    }
}

#[cfg(test)]
impl Drop for GatewayShutdownTestProbe {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

impl DurableGateway {
    #[cfg(test)]
    async fn inject_missing_driver_ownership_for_test(
        &mut self,
        remaining_worker_count: usize,
    ) -> Vec<Arc<std::sync::atomic::AtomicBool>> {
        self.driver
            .take()
            .expect("real gateway owns its required driver before injection")
            .shutdown()
            .await
            .expect("injected ownership loss first joins the real driver");
        let mut joined = Vec::with_capacity(remaining_worker_count);
        for _ in 0..remaining_worker_count {
            let (probe, started, probe_joined) = GatewayShutdownTestProbe::spawn();
            self.shutdown_test_probes.push(probe);
            tokio::time::timeout(Duration::from_secs(5), started)
                .await
                .expect("gateway shutdown test probe start timed out")
                .expect("gateway shutdown test probe exited before start");
            joined.push(probe_joined);
        }
        joined
    }
    #[must_use]
    pub fn push_readiness(&self) -> Arc<crate::push::PushReadiness> {
        Arc::clone(&self.push_readiness)
    }

    /// Transfer ownership of the required production callback worker.
    ///
    /// # Errors
    /// Returns an error if a worker is already owned or the readiness generation differs.
    pub fn own_callback_worker(
        &mut self,
        worker: crate::CallbackWorkerHandle,
    ) -> Result<(), A2AError> {
        if self.callback_worker.is_some() || !Arc::ptr_eq(worker.readiness(), &self.push_readiness)
        {
            return Err(A2AError::internal("callback worker ownership mismatch"));
        }
        self.callback_worker = Some(worker);
        Ok(())
    }

    /// Start the optional projector after both the authority and OTLP owner exist.
    ///
    /// # Errors
    /// Returns an error for invalid configuration or a failed worker spawn.
    pub fn start_audit_projector(
        &mut self,
        telemetry: crate::telemetry::TelemetryHandle,
        config: crate::telemetry::AuditProjectorConfig,
    ) -> Result<bool, crate::telemetry::AuditProjectorError> {
        if self.projector.is_some() {
            return Ok(true);
        }
        let authority = self
            .authority
            .as_ref()
            .ok_or(crate::telemetry::AuditProjectorError::Unsupported)?;
        if authority.audit_projection_authority().is_none() {
            return Ok(false);
        }
        self.projector = Some(crate::telemetry::AuditProjectorWorker::spawn(
            Arc::clone(authority),
            telemetry,
            config,
        )?);
        Ok(true)
    }
    /// Clone the protocol router owned by this live gateway.
    ///
    /// # Panics
    ///
    /// Panics only if called from internal code after the consuming shutdown path
    /// has already taken the router; safe Rust callers cannot retain `self` then.
    pub fn router(&self) -> Router {
        self.router
            .as_ref()
            .expect("durable gateway router is unavailable after shutdown")
            .clone()
    }

    #[doc(hidden)]
    pub async fn wait_for_waiter_count(&self, expected: usize) -> Result<(), A2AError> {
        let driver = self
            .driver
            .as_ref()
            .ok_or_else(|| A2AError::internal("durable gateway is shut down"))?;
        let mut state = driver.control().subscribe();
        tokio::time::timeout(Duration::from_secs(5), async move {
            loop {
                if state.borrow().waiters >= expected {
                    return Ok(());
                }
                state
                    .changed()
                    .await
                    .map_err(|_| A2AError::internal("durable outbox driver stopped"))?;
            }
        })
        .await
        .map_err(|_| A2AError::internal("durable waiter-count wait timed out"))?
    }

    #[doc(hidden)]
    pub async fn durable_effect_count(&self) -> Result<u64, A2AError> {
        self.authority
            .as_ref()
            .ok_or_else(|| A2AError::internal("durable gateway is shut down"))?
            .durable_effect_count()
            .await
    }

    /// Stop claiming work, join the driver, and release the final durable owner.
    ///
    /// # Errors
    ///
    /// Returns an internal protocol error if required driver or authority ownership is missing,
    /// or if an owned shutdown path fails or panics. Every remaining owner is still shut down
    /// and joined before the error is returned.
    pub async fn shutdown(mut self) -> Result<(), A2AError> {
        let callback_result = if let Some(worker) = self.callback_worker.take() {
            worker.shutdown(Duration::from_secs(5)).await
        } else {
            Ok(())
        };
        if callback_result.is_err() {
            self.push_readiness.mark_fatal();
            eprintln!("smesh.callback.shutdown_failed category=worker");
        }
        let projector_result = if let Some(projector) = self.projector.take() {
            projector.shutdown(Duration::from_secs(5)).await
        } else {
            Ok(())
        };
        if projector_result.is_err() {
            eprintln!("smesh.telemetry.shutdown_failed category=audit_projector");
        }
        let driver = self.driver.take();
        let authority = self.authority.take();
        let driver_result = if let Some(driver) = driver {
            driver.shutdown().await
        } else {
            Err(A2AError::internal(
                "durable gateway driver ownership is missing",
            ))
        };
        let promoter_result = if let Some(promoter) = self.promoter.take() {
            promoter.shutdown().await
        } else {
            Ok(())
        };
        let gc_result = if let Some(gc) = self.gc.take() {
            gc.shutdown().await
        } else {
            Ok(())
        };
        let orphan_result = if let Some(orphan_scanner) = self.orphan_scanner.take() {
            orphan_scanner.shutdown().await
        } else {
            Ok(())
        };
        #[cfg(test)]
        let probe_result = {
            let mut result = Ok(());
            for probe in std::mem::take(&mut self.shutdown_test_probes) {
                if let Err(error) = probe.shutdown().await
                    && result.is_ok()
                {
                    result = Err(error);
                }
            }
            result
        };
        // Closing shared state invalidates handler/router clones and drops both
        // SQLite and the process ownership lock before shutdown returns.
        let authority_result = if let Some(authority) = authority {
            authority.shutdown().await
        } else {
            Err(A2AError::internal(
                "durable gateway authority ownership is missing",
            ))
        };
        self.router.take();
        // A callback panic is already contained: readiness stays fatal, every
        // callback task has been joined, and no further callback mutation can
        // be admitted. Preserve that health evidence without converting an
        // otherwise graceful process shutdown into failure.
        drop(callback_result);
        driver_result?;
        promoter_result?;
        gc_result?;
        orphan_result?;
        #[cfg(test)]
        probe_result?;
        authority_result?;
        projector_result.map_err(|_| A2AError::internal("optional telemetry shutdown failed"))?;
        Ok(())
    }
}

impl Drop for DurableGateway {
    fn drop(&mut self) {
        // Drop cannot async-join. Dropping the driver requests cooperative
        // cancellation and transfers its abort-on-drop root join into a bounded
        // Tokio reaper. Closing the authority then rejects new work and closes
        // durable pools; explicit shutdown remains authoritative and joins inline.
        self.projector.take();
        self.callback_worker.take();
        self.driver.take();
        self.promoter.take();
        self.gc.take();
        self.orphan_scanner.take();
        if let Some(authority) = self.authority.as_ref() {
            authority.close_owned_sync();
        }
        self.authority.take();
        self.router.take();
    }
}

/// Build the repository-owned durable loopback gateway.
///
/// Unlike the source-compatible generic builders, this accepts no arbitrary
/// `MeshDispatcher` and never routes send methods through `DefaultRequestHandler`.
/// It applies `public_base_url`, `input_limits`, and `max_body_bytes` from
/// [`GatewayConfig`]. `gateway_node_id` and `execution_limits` do not affect this
/// owned loopback adapter, and `max_tasks` is enforced when opening [`SqliteTaskStore`].
///
/// # Errors
///
/// Returns an error if durable gateway policy construction fails.
pub fn build_durable_loopback_gateway<A: IntoDurableAuthority>(
    config: GatewayConfig,
    store: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
) -> Result<DurableGateway, PolicyError> {
    build_durable_loopback_gateway_with_telemetry(config, store, endpoint, clock, None)
}

/// Build the repository-owned durable gateway with an optional telemetry handle.
///
/// # Errors
/// Returns an error if durable gateway policy construction fails.
pub fn build_durable_loopback_gateway_with_telemetry<A: IntoDurableAuthority>(
    config: GatewayConfig,
    store: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
) -> Result<DurableGateway, PolicyError> {
    let parts = store.into_durable_authority_parts();
    Ok(build_durable_gateway_inner(
        config, parts, endpoint, clock, None, None, telemetry,
    ))
}

/// Build the durable loopback gateway with authentication only.
///
/// # Security
/// This compatibility builder does **not** install tenant authorization and is
/// therefore development-only and non-multitenant. Production callers must use
/// [`build_authorized_durable_loopback_gateway`].
///
/// # Errors
/// Returns an error if durable gateway policy construction fails.
pub fn build_authenticated_durable_loopback_gateway<A: IntoDurableAuthority>(
    config: GatewayConfig,
    store: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: AuthState,
) -> Result<DurableGateway, PolicyError> {
    let parts = store.into_durable_authority_parts();
    Ok(build_durable_gateway_inner(
        config,
        parts,
        endpoint,
        clock,
        Some(auth),
        None,
        None,
    ))
}

/// Build the authenticated durable gateway with server-owned tenant policy.
/// This is the only authenticated builder intended for production use.
///
/// # Errors
/// Returns an error if durable gateway policy construction fails.
pub fn build_authorized_durable_loopback_gateway<A: IntoDurableAuthority>(
    config: GatewayConfig,
    store: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: AuthState,
    policy: Arc<AuthorizationPolicy>,
) -> Result<DurableGateway, PolicyError> {
    let authority = store.into_durable_authority();
    Ok(build_durable_gateway_inner(
        config,
        DurableAuthorityParts {
            authority,
            local: None,
        },
        endpoint,
        clock,
        Some(auth),
        Some(policy),
        None,
    ))
}

/// Build the production authorized durable gateway with the human-ratification API.
///
/// Ratification is provided only by the selected durable authority so packet,
/// decision, task, event, audit, and callback writes share one transaction.
///
/// # Errors
/// Returns an error if durable gateway policy construction fails.
pub fn build_authorized_durable_loopback_gateway_with_ratification<A: IntoDurableAuthority>(
    config: GatewayConfig,
    store: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: AuthState,
    policy: Arc<AuthorizationPolicy>,
) -> Result<DurableGateway, PolicyError> {
    build_authorized_durable_loopback_gateway_with_ratification_and_telemetry(
        config, store, endpoint, clock, auth, policy, None,
    )
}

/// Build the authorized ratification gateway without dropping optional telemetry.
///
/// # Errors
/// Returns an error if durable gateway or ratification route construction fails.
pub fn build_authorized_durable_loopback_gateway_with_ratification_and_telemetry<
    A: IntoDurableAuthority,
>(
    config: GatewayConfig,
    store: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: AuthState,
    policy: Arc<AuthorizationPolicy>,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
) -> Result<DurableGateway, PolicyError> {
    let public_url = url::Url::parse(&config.public_base_url).map_err(|_| {
        PolicyError::InvalidPolicy("ratification public base URL is invalid".to_owned())
    })?;
    let origin = public_url.origin().ascii_serialization();
    if origin == "null" {
        return Err(PolicyError::InvalidPolicy(
            "ratification public base URL has no tuple origin".to_owned(),
        ));
    }
    let origin = RatificationOrigin(Arc::from(origin));
    let route_auth = auth.clone();
    let route_policy = Arc::clone(&policy);
    let mut gateway = build_authorized_durable_loopback_gateway_with_telemetry(
        config,
        store,
        endpoint,
        clock.clone(),
        auth,
        policy,
        telemetry,
    )?;
    let authority = gateway
        .authority
        .as_ref()
        .ok_or_else(|| PolicyError::InvalidPolicy("durable authority unavailable".to_owned()))?
        .clone();
    if authority.ratification_authority().is_none() {
        return Err(PolicyError::InvalidPolicy(
            "durable authority does not support ratification".to_owned(),
        ));
    }
    let authorization =
        AuthorizationMiddlewareState::with_audit(route_policy, authority.clone(), clock.clone());
    let mutations = Router::new()
        .route(
            "/ratification/v1/tasks/{task_id}/review",
            post(ratification_review),
        )
        .route(
            "/ratification/v1/tasks/{task_id}/decision",
            post(ratification_decision),
        )
        .layer(middleware::from_fn(ratification_mutation_policy))
        .layer(RequestBodyLimitLayer::new(128 * 1024));
    let protected = Router::new()
        .route("/ratification/v1/tasks/{task_id}", get(ratification_view))
        .route(
            "/ratification/v1/tasks/{task_id}/generations/{generation}",
            get(ratification_view_at_generation),
        )
        .merge(mutations)
        .layer(Extension(clock))
        .layer(Extension(origin))
        .layer(Extension(authority))
        .layer(middleware::from_fn_with_state(
            authorization,
            authorize_request,
        ))
        .layer(middleware::from_fn_with_state(
            route_auth,
            authenticate_request,
        ));
    let public = Router::new()
        .route("/ratification/console", get(ratification_console))
        .route("/ratification/console.js", get(ratification_console_script));
    let ratification = public
        .merge(protected)
        .layer(middleware::from_fn(ratification_response_headers));
    let router = gateway
        .router
        .take()
        .ok_or_else(|| PolicyError::InvalidPolicy("durable router unavailable".to_owned()))?;
    gateway.router = Some(router.merge(ratification));
    Ok(gateway)
}

/// Build the production authorized durable gateway with an optional telemetry handle.
///
/// # Errors
/// Returns an error if durable gateway policy construction fails.
pub fn build_authorized_durable_loopback_gateway_with_telemetry<A: IntoDurableAuthority>(
    config: GatewayConfig,
    store: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: AuthState,
    policy: Arc<AuthorizationPolicy>,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
) -> Result<DurableGateway, PolicyError> {
    let authority = store.into_durable_authority();
    Ok(build_durable_gateway_inner(
        config,
        DurableAuthorityParts {
            authority,
            local: None,
        },
        endpoint,
        clock,
        Some(auth),
        Some(policy),
        telemetry,
    ))
}

#[allow(clippy::too_many_lines)]
fn build_durable_gateway_inner(
    config: GatewayConfig,
    parts: DurableAuthorityParts,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: Option<AuthState>,
    authorization: Option<Arc<AuthorizationPolicy>>,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
) -> DurableGateway {
    let DurableAuthorityParts { authority, local } = parts;
    let GatewayConfig {
        public_base_url,
        input_limits,
        max_body_bytes,
        ..
    } = config;
    let endpoint = endpoint.with_telemetry(telemetry.clone());
    let driver = if telemetry.is_some() {
        spawn_durable_driver_with_telemetry(
            Arc::clone(&authority),
            endpoint,
            clock.clone(),
            telemetry.clone(),
        )
    } else {
        spawn_durable_driver(Arc::clone(&authority), endpoint, clock.clone())
    };
    let push_readiness = Arc::new(crate::push::PushReadiness::new());
    let jsonrpc_handler = Arc::new(
        DurableRequestHandler::new_with_local(
            Arc::clone(&authority),
            local.clone(),
            driver.control(),
            clock.clone(),
            input_limits,
        )
        .with_telemetry(telemetry.clone())
        .with_push_readiness(Arc::clone(&push_readiness)),
    );
    let rest_handler = Arc::new(
        DurableRequestHandler::new_with_local(
            Arc::clone(&authority),
            local,
            driver.control(),
            clock.clone(),
            input_limits,
        )
        .with_errors_before_stream()
        .with_telemetry(telemetry.clone())
        .with_push_readiness(Arc::clone(&push_readiness)),
    );
    let mut durable_card = if let Some(auth) = auth.as_ref() {
        build_secured_agent_card_with_policy(
            &public_base_url,
            auth.bearer_enabled(),
            auth.mutual_tls_enabled(),
            auth.mutual_tls_required(),
        )
    } else {
        build_agent_card(&public_base_url)
    };
    durable_card.capabilities.streaming = Some(true);
    durable_card.default_output_modes = vec!["application/json".to_owned()];
    for skill in &mut durable_card.skills {
        skill.output_modes = Some(vec!["application/json".to_owned()]);
    }
    let card = Arc::new(LiveAgentCard::new(
        durable_card,
        Arc::clone(&push_readiness),
    ));
    let protocol = if let Some(auth) = auth {
        let jsonrpc = auth.wrap_handler(jsonrpc_handler);
        let rest = auth.wrap_handler(rest_handler);
        let artifacts = Router::new()
            .route(
                "/artifacts/v1/{artifact_id}",
                get(artifact_resolver).head(artifact_resolver),
            )
            .layer(Extension(Arc::clone(&authority)));
        let protocol = Router::new()
            .nest("/jsonrpc", a2a_server::jsonrpc::jsonrpc_router(jsonrpc))
            .nest("/rest", a2a_server::rest::rest_router(rest))
            .merge(artifacts)
            .layer(RequestBodyLimitLayer::new(max_body_bytes));
        let protocol = if let Some(policy) = authorization {
            let state =
                AuthorizationMiddlewareState::with_audit(policy, Arc::clone(&authority), clock);
            protocol.layer(middleware::from_fn_with_state(state, authorize_request))
        } else {
            protocol
        };
        protocol.layer(middleware::from_fn_with_state(auth, authenticate_request))
    } else {
        Router::new()
            .nest(
                "/jsonrpc",
                a2a_server::jsonrpc::jsonrpc_router(jsonrpc_handler),
            )
            .nest("/rest", a2a_server::rest::rest_router(rest_handler))
            .layer(RequestBodyLimitLayer::new(max_body_bytes))
    };
    let protocol = protocol.layer(middleware::from_fn(quota_retry_after_header));
    let router = protocol.merge(a2a_server::agent_card::agent_card_router(card));
    let promoter = if telemetry.is_some() {
        spawn_artifact_promoter_with_telemetry(Arc::clone(&authority), telemetry)
    } else {
        spawn_artifact_promoter(Arc::clone(&authority))
    };
    let gc = spawn_artifact_gc(Arc::clone(&authority));
    let orphan_scanner = spawn_artifact_orphan_scanner(Arc::clone(&authority));
    DurableGateway {
        router: Some(router),
        projector: None,
        callback_worker: None,
        push_readiness,
        driver: Some(driver),
        promoter,
        gc,
        orphan_scanner,
        authority: Some(authority),
        #[cfg(test)]
        shutdown_test_probes: Vec::new(),
    }
}

/// Compose the official A2A routers around a SMESH executor.
pub fn build_router<D>(config: GatewayConfig, dispatcher: D) -> Router
where
    D: MeshDispatcher,
{
    let store = BoundedTaskStore::new(config.max_tasks);
    build_router_with_store(config, dispatcher, store)
}

/// Compose a local compatibility router with an explicit truthful public card.
///
/// This is intended for bounded local topology fixtures whose logical gateway
/// profile differs from the generic SMESH card. It does not add authentication
/// or tenant authorization.
pub(crate) fn build_router_with_agent_card<D>(
    config: GatewayConfig,
    dispatcher: D,
    card: AgentCard,
) -> Router
where
    D: MeshDispatcher,
{
    let store = BoundedTaskStore::new(config.max_tasks);
    compose_router_with_policy_trace_and_card(
        config,
        dispatcher,
        store,
        VersionedCompletionPolicy::default(),
        None,
        Some(card),
    )
}

/// Compose authentication-only official JSON-RPC and REST routers.
///
/// # Security
/// Upstream `DefaultRequestHandler` loses explicit tenant scope after spawning;
/// this compatibility API is development-only and must not be used as a
/// multitenant production boundary. The production binary refuses this path.
pub fn build_authenticated_router<D>(
    config: GatewayConfig,
    dispatcher: D,
    auth: AuthState,
) -> Router
where
    D: MeshDispatcher,
{
    build_authenticated_router_inner(config, dispatcher, auth, None)
}

/// Compose authenticated protocol routers while preserving canonical runtime trace capture.
pub fn build_authenticated_router_with_trace<D>(
    config: GatewayConfig,
    dispatcher: D,
    auth: AuthState,
    trace: Arc<RuntimeEventCapture>,
) -> Router
where
    D: MeshDispatcher,
{
    build_authenticated_router_inner(config, dispatcher, auth, Some(trace))
}

fn build_authenticated_router_inner<D>(
    config: GatewayConfig,
    dispatcher: D,
    auth: AuthState,
    trace: Option<Arc<RuntimeEventCapture>>,
) -> Router
where
    D: MeshDispatcher,
{
    let max_body_bytes = config.max_body_bytes;
    let store = SharedTaskStore(Arc::new(BoundedTaskStore::new(config.max_tasks)));
    let policy = VersionedCompletionPolicy::default();
    let mut executor = SmeshExecutor::new(dispatcher, config.input_limits, config.gateway_node_id)
        .with_execution_limits(config.execution_limits)
        .with_completion_policy(policy.clone());
    if let Some(trace) = trace {
        executor = executor.with_runtime_trace(trace);
    }
    let executor = auth.wrap_executor(executor);
    let inner: Arc<dyn RequestHandler> =
        Arc::new(DefaultRequestHandler::new(executor, store.clone()));
    let guarded: Arc<dyn RequestHandler> =
        Arc::new(GuardedRequestHandler::new(inner, store, policy));
    let handler = auth.wrap_handler(guarded);
    let card = Arc::new(StaticAgentCard::new(build_secured_agent_card_with_policy(
        &config.public_base_url,
        auth.bearer_enabled(),
        auth.mutual_tls_enabled(),
        auth.mutual_tls_required(),
    )));
    let protected = Router::new()
        .nest(
            "/jsonrpc",
            a2a_server::jsonrpc::jsonrpc_router(handler.clone()),
        )
        .nest("/rest", a2a_server::rest::rest_router(handler))
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(middleware::from_fn_with_state(auth, authenticate_request));
    protected.merge(a2a_server::agent_card::agent_card_router(card))
}

/// Compose the official A2A routers with canonical runtime/gateway trace capture.
pub fn build_router_with_trace<D>(
    config: GatewayConfig,
    dispatcher: D,
    trace: Arc<RuntimeEventCapture>,
) -> Router
where
    D: MeshDispatcher,
{
    let store = BoundedTaskStore::new(config.max_tasks);
    compose_router_with_policy_and_trace(
        config,
        dispatcher,
        store,
        VersionedCompletionPolicy::default(),
        Some(trace),
    )
}

fn build_router_with_store<D, S>(config: GatewayConfig, dispatcher: D, store: S) -> Router
where
    D: MeshDispatcher,
    S: CompletionPolicyStore,
{
    compose_router_with_policy_and_trace(
        config,
        dispatcher,
        store,
        VersionedCompletionPolicy::default(),
        None,
    )
}

/// Compose the compatibility/task-snapshot A2A router with SQLite-backed task state.
///
/// This builder still routes through the upstream `DefaultRequestHandler`; it does
/// not provide repository-owned durable dispatch or receiver effect replay. Use
/// `build_durable_loopback_gateway` for that production loopback boundary.
///
/// # Errors
///
/// Returns an error if the built-in completion-policy profile is invalid.
pub fn build_router_with_sqlite<D>(
    config: GatewayConfig,
    dispatcher: D,
    store: SqliteTaskStore,
) -> Result<Router, PolicyError>
where
    D: MeshDispatcher,
{
    let policy = VersionedCompletionPolicy::new_with_receipt_key(
        CompletionPolicySpec::development(),
        store.completion_receipt_key(),
    )?;
    build_router_with_policy(config, dispatcher, store, policy)
}

/// Compose the traced compatibility/task-snapshot router with SQLite-backed task state.
///
/// Like `build_router_with_sqlite`, this is not durable dispatch and does not
/// provide receiver effect idempotency or replay.
///
/// # Errors
///
/// Returns an error if the built-in completion-policy profile is invalid.
pub fn build_router_with_sqlite_and_trace<D>(
    config: GatewayConfig,
    dispatcher: D,
    store: SqliteTaskStore,
    trace: Arc<RuntimeEventCapture>,
) -> Result<Router, PolicyError>
where
    D: MeshDispatcher,
{
    let policy = VersionedCompletionPolicy::new_with_receipt_key(
        CompletionPolicySpec::development(),
        store.completion_receipt_key(),
    )?;
    build_router_with_policy_and_trace(config, dispatcher, store, policy, Some(trace))
}

/// Compose the A2A router with explicit store and completion-policy boundaries.
///
/// # Errors
///
/// Returns an error when a persistent SQLite store and policy use different receipt keys.
pub fn build_router_with_policy<D, S>(
    config: GatewayConfig,
    dispatcher: D,
    store: S,
    policy: VersionedCompletionPolicy,
) -> Result<Router, PolicyError>
where
    D: MeshDispatcher,
    S: CompletionPolicyStore + 'static,
{
    build_router_with_policy_and_trace(config, dispatcher, store, policy, None)
}

/// Compose the traced A2A router with explicit store and completion-policy boundaries.
///
/// # Errors
///
/// Returns an error when a persistent SQLite store and policy use different receipt keys.
pub fn build_router_with_policy_and_trace<D, S>(
    config: GatewayConfig,
    dispatcher: D,
    store: S,
    policy: VersionedCompletionPolicy,
    trace: Option<Arc<RuntimeEventCapture>>,
) -> Result<Router, PolicyError>
where
    D: MeshDispatcher,
    S: CompletionPolicyStore + 'static,
{
    if let Some(receipt_key) = store.durable_receipt_key()
        && receipt_key != policy.receipt_key()
    {
        return Err(PolicyError::InvalidPolicy(
            "persistent task store and completion policy use different receipt keys".to_owned(),
        ));
    }
    Ok(compose_router_with_policy_and_trace(
        config, dispatcher, store, policy, trace,
    ))
}

fn compose_router_with_policy_and_trace<D, S>(
    config: GatewayConfig,
    dispatcher: D,
    store: S,
    policy: VersionedCompletionPolicy,
    trace: Option<Arc<RuntimeEventCapture>>,
) -> Router
where
    D: MeshDispatcher,
    S: CompletionPolicyStore,
{
    compose_router_with_policy_trace_and_card(config, dispatcher, store, policy, trace, None)
}

fn compose_router_with_policy_trace_and_card<D, S>(
    config: GatewayConfig,
    dispatcher: D,
    store: S,
    policy: VersionedCompletionPolicy,
    trace: Option<Arc<RuntimeEventCapture>>,
    card: Option<AgentCard>,
) -> Router
where
    D: MeshDispatcher,
    S: CompletionPolicyStore,
{
    let max_body_bytes = config.max_body_bytes;
    let store = SharedTaskStore(Arc::new(store));
    let guard_policy = policy.clone();
    let mut executor = SmeshExecutor::new(dispatcher, config.input_limits, config.gateway_node_id)
        .with_execution_limits(config.execution_limits)
        .with_completion_policy(policy);
    if let Some(trace) = trace {
        executor = executor.with_runtime_trace(trace);
    }
    let inner: Arc<dyn RequestHandler> =
        Arc::new(DefaultRequestHandler::new(executor, store.clone()));
    let handler = Arc::new(GuardedRequestHandler::new(inner, store, guard_policy));
    let card = Arc::new(StaticAgentCard::new(
        card.unwrap_or_else(|| build_agent_card(&config.public_base_url)),
    ));

    Router::new()
        .nest(
            "/jsonrpc",
            a2a_server::jsonrpc::jsonrpc_router(handler.clone()),
        )
        .nest("/rest", a2a_server::rest::rest_router(handler))
        .merge(a2a_server::agent_card::agent_card_router(card))
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
}

#[cfg(test)]
mod artifact_resolver_path_tests {
    use axum::http::Uri;

    use super::canonical_artifact_resolver_request;

    #[test]
    fn resolver_rejects_noncanonical_and_authority_alias_paths() {
        for uri in [
            "/artifacts/v1/a%23b",
            "/artifacts/v1/a%3Fb",
            "/artifacts/v1/a%2Fb",
            "/artifacts/v1/%2E",
            "/artifacts/v1/%2E%2E",
            "/artifacts/v1/%61",
            "/artifacts/v1/a?b",
        ] {
            let uri: Uri = uri.parse().unwrap();
            assert!(
                !canonical_artifact_resolver_request(&uri, "a"),
                "resolver accepted alternate lookup authority {uri}"
            );
        }
        let canonical: Uri = "/artifacts/v1/artifact-0123_ab.~".parse().unwrap();
        assert!(canonical_artifact_resolver_request(
            &canonical,
            "artifact-0123_ab.~"
        ));
    }
}

#[cfg(test)]
mod durable_gateway_shutdown_tests {
    use std::sync::atomic::Ordering;

    use super::*;

    const WATCHDOG: Duration = Duration::from_secs(10);

    async fn open(path: &std::path::Path) -> SqliteTaskStore {
        tokio::time::timeout(WATCHDOG, SqliteTaskStore::open(path, 16))
            .await
            .expect("SQLite open watchdog expired")
            .expect("SQLite test authority opens")
    }

    fn gateway(store: SqliteTaskStore, generation: i64) -> DurableGateway {
        build_durable_loopback_gateway(
            GatewayConfig::new("http://127.0.0.1:1", format!("shutdown-{generation}")),
            store,
            DurableLoopbackEndpoint::new(),
            InjectedClock::new(generation),
        )
        .expect("real durable gateway builds")
    }

    #[tokio::test]
    async fn missing_driver_ownership_fails_closed_after_reaping_every_remaining_owner() {
        let root = std::env::temp_dir().join(format!(
            "smesh-durable-shutdown-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).expect("create shutdown test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .expect("secure shutdown test root");
        }
        let path = root.join("authority.sqlite3");

        tokio::time::timeout(WATCHDOG, gateway(open(&path).await, 1).shutdown())
            .await
            .expect("normal gateway shutdown watchdog expired")
            .expect("normal gateway shutdown succeeds");

        let mut damaged = gateway(open(&path).await, 2);
        let joined = damaged.inject_missing_driver_ownership_for_test(5).await;
        let error = tokio::time::timeout(WATCHDOG, damaged.shutdown())
            .await
            .expect("fail-closed gateway shutdown watchdog expired")
            .expect_err("missing required driver ownership must fail closed");
        assert_eq!(error.code, -32_603);
        assert_eq!(error.message, "durable gateway driver ownership is missing");
        assert!(
            joined.iter().all(|probe| probe.load(Ordering::SeqCst)),
            "every remaining owned worker must be terminated and joined before the error"
        );

        tokio::time::timeout(WATCHDOG, gateway(open(&path).await, 3).shutdown())
            .await
            .expect("restarted gateway shutdown watchdog expired")
            .expect("gateway reopens and shuts down normally after fail-closed cleanup");
        let reopened = open(&path).await;
        tokio::time::timeout(WATCHDOG, reopened.shutdown_shared())
            .await
            .expect("final authority shutdown watchdog expired")
            .expect("final authority shutdown succeeds");

        for suffix in ["", "-wal", "-shm", ".lock"] {
            let candidate = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
            if candidate.exists() {
                std::fs::remove_file(&candidate).expect("remove shutdown test database fixture");
            }
            assert!(!candidate.exists(), "shutdown test fixture was not removed");
        }
        std::fs::remove_dir(&root).expect("remove shutdown test root");
        assert!(!root.exists(), "shutdown test root was not removed");
    }
}
