//! Authenticated REST adapter for the shared operator-rule service.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE, ETAG, IF_MATCH, LOCATION};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};

use super::operator_rule_jobs::{OperatorRuleJobClient, PreparedPlan, SubmitOutcome};
use super::state::ApiState;
use crate::operator_rules::{
    Actor, BatchRequest, ErrorCode, OperatorRulesError, PageRequest, TransportLimits,
    CONTRACT_VERSION,
};

pub const JSON_BODY_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyRequest {
    pub contract_version: u32,
    pub plan_id: String,
    pub plan_hash: String,
    pub expected_config_revision: String,
    pub request_id: String,
}

#[derive(Serialize)]
struct ApiError {
    code: String,
    error: String,
}

#[derive(Serialize)]
struct PlanResponse {
    plan_id: String,
    plan: crate::operator_rules::PlanSummary,
    impacts: crate::operator_rules::PlanImpactPage,
}

pub async fn capabilities(State(state): State<Arc<ApiState>>) -> Response {
    let client = match jobs(&state) {
        Ok(client) => client,
        Err(response) => return *response,
    };
    bounded_json(StatusCode::OK, &client.capabilities(TransportLimits::REST))
}

pub async fn custom_lists(
    State(state): State<Arc<ApiState>>,
    Query(page): Query<PageRequest>,
) -> Response {
    let client = match jobs(&state) {
        Ok(client) => client,
        Err(response) => return *response,
    };
    match client.lists(page, TransportLimits::REST).await {
        Ok(value) => with_etag(
            bounded_json(StatusCode::OK, &value),
            "config",
            &value.config_revision,
        ),
        Err(error) => error_response(error),
    }
}

pub async fn custom_list(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    if let Err(response) = validate_list_id(&id) {
        return *response;
    }
    let client = match jobs(&state) {
        Ok(client) => client,
        Err(response) => return *response,
    };
    match client.list(id).await {
        Ok(value) => with_etag(
            bounded_json(StatusCode::OK, &value),
            "config",
            &value.config_revision,
        ),
        Err(error) => error_response(error),
    }
}

pub async fn custom_list_rules(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Query(page): Query<PageRequest>,
) -> Response {
    if let Err(response) = validate_list_id(&id) {
        return *response;
    }
    let client = match jobs(&state) {
        Ok(client) => client,
        Err(response) => return *response,
    };
    match client.rules(id, page, TransportLimits::REST).await {
        Ok(value) => with_etag(
            bounded_json(StatusCode::OK, &value),
            "pack",
            &value.pack_revision,
        ),
        Err(error) => error_response(error),
    }
}

pub async fn custom_list_export(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = validate_list_id(&id) {
        return *response;
    }
    let client = match jobs(&state) {
        Ok(client) => client,
        Err(response) => return *response,
    };
    // The core captures revision and bytes under one read guard. The guard is
    // released before this body is created, so a slow client neither blocks a
    // writer nor observes bytes from two pack revisions.
    let export = match client.export_owned(id.clone()).await {
        Ok(export) => export,
        Err(error) => return error_response(error),
    };
    let revision = export.pack_revision;
    let stream = Body::from(export.bytes).into_data_stream();
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    let filename = format!("attachment; filename=\"{id}.txt\"");
    if let Ok(value) = HeaderValue::try_from(filename) {
        response.headers_mut().insert(CONTENT_DISPOSITION, value);
    }
    with_etag(response, "pack", &revision)
}

pub async fn create_plan(
    State(state): State<Arc<ApiState>>,
    Query(page): Query<PageRequest>,
    payload: Result<Json<BatchRequest>, JsonRejection>,
) -> Response {
    if let Some(response) = node_policy_refusal(&state) {
        return response;
    }
    let request = match json(payload) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let client = match jobs(&state) {
        Ok(client) => client,
        Err(response) => return *response,
    };
    match client
        .plan(actor(), request, page, TransportLimits::REST)
        .await
    {
        Ok(PreparedPlan {
            plan_id,
            summary,
            first_impacts,
        }) => {
            let revision = summary.base_config_revision.clone();
            let response = PlanResponse {
                plan_id,
                plan: summary,
                impacts: first_impacts,
            };
            with_etag(bounded_json(StatusCode::OK, &response), "config", &revision)
        }
        Err(error) => error_response(error),
    }
}

pub async fn plan_impacts(
    State(state): State<Arc<ApiState>>,
    Path(plan_id): Path<String>,
    Query(page): Query<PageRequest>,
) -> Response {
    let client = match jobs(&state) {
        Ok(client) => client,
        Err(response) => return *response,
    };
    let actor = actor();
    let summary = match client.stored_plan_summary(&actor, &plan_id) {
        Ok(summary) => summary,
        Err(error) => return error_response(error),
    };
    match client.plan_impacts(&actor, &plan_id, page) {
        Ok(value) => with_etag(
            bounded_json(StatusCode::OK, &value),
            "config",
            &summary.base_config_revision,
        ),
        Err(error) => error_response(error),
    }
}

pub async fn apply(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    payload: Result<Json<ApplyRequest>, JsonRejection>,
) -> Response {
    if let Some(response) = node_policy_refusal(&state) {
        return response;
    }
    let body = match json(payload) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    if body.contract_version != CONTRACT_VERSION {
        return bad_request("supported contract_version is 1");
    }
    let if_match = match typed_header(&headers, IF_MATCH, "config") {
        Ok(Some(value)) => value,
        Ok(None) => {
            return bounded_json(
                StatusCode::PRECONDITION_REQUIRED,
                &ApiError {
                    code: "precondition_required".into(),
                    error: "If-Match with a typed config ETag is required".into(),
                },
            )
        }
        Err(response) => return *response,
    };
    if if_match != body.expected_config_revision {
        return bad_request("If-Match and expected_config_revision disagree");
    }
    let request_id = match plain_header(&headers, "idempotency-key") {
        Ok(Some(value)) => value,
        Ok(None) => return bad_request("Idempotency-Key is required"),
        Err(response) => return *response,
    };
    if request_id != body.request_id {
        return bad_request("Idempotency-Key and request_id disagree");
    }
    let client = match jobs(&state) {
        Ok(client) => client,
        Err(response) => return *response,
    };
    let actor = actor();
    match client
        .submit_with_precondition(
            actor,
            body.plan_id,
            body.plan_hash,
            body.request_id,
            body.expected_config_revision,
        )
        .await
    {
        Ok(outcome @ SubmitOutcome::Accepted { .. })
        | Ok(outcome @ SubmitOutcome::Replay { .. }) => {
            let (location, revision) = match &outcome {
                SubmitOutcome::Accepted {
                    location, prepared, ..
                } => (location.as_str(), prepared.config_revision.as_str()),
                SubmitOutcome::Replay {
                    location, receipt, ..
                } => (location.as_str(), receipt.config_revision.as_str()),
            };
            let mut response = bounded_json(StatusCode::ACCEPTED, &outcome);
            if let Ok(value) = HeaderValue::try_from(location) {
                response.headers_mut().insert(LOCATION, value);
            }
            with_etag(response, "config", revision)
        }
        Err(error) if error.code == ErrorCode::RevisionConflict => bounded_json(
            StatusCode::PRECONDITION_FAILED,
            &ApiError {
                code: "revision_conflict".into(),
                error: shorten(error.message),
            },
        ),
        Err(error) => error_response(error),
    }
}

fn node_policy_refusal(state: &ApiState) -> Option<Response> {
    #[cfg(feature = "cluster")]
    if state
        .cluster_observe
        .as_ref()
        .is_some_and(|observe| observe.role == crate::config::schema::ClusterRole::Secondary)
    {
        return Some(error_response(OperatorRulesError::new(
            ErrorCode::PolicyOwnedByPrimary,
            "policy is read-only on an active secondary; edit it on the primary node",
        )));
    }
    let _ = state;
    None
}

pub async fn operation(
    State(state): State<Arc<ApiState>>,
    Path(operation_id): Path<String>,
) -> Response {
    let client = match jobs(&state) {
        Ok(client) => client,
        Err(response) => return *response,
    };
    match client.operation(&actor(), &operation_id).await {
        Ok(receipt) => with_etag(
            bounded_json(StatusCode::OK, &receipt),
            "config",
            &receipt.config_revision,
        ),
        Err(error) => error_response(error),
    }
}

fn actor() -> Actor {
    Actor {
        identity: "api-admin".into(),
        origin: "rest".into(),
    }
}

fn jobs(state: &ApiState) -> Result<OperatorRuleJobClient, Box<Response>> {
    state
        .operator_rule_jobs
        .clone()
        .ok_or_else(|| Box::new(unavailable("operator-rule service is unavailable")))
}

fn validate_list_id(id: &str) -> Result<(), Box<Response>> {
    crate::config::schema::Id::new(id)
        .map(|_| ())
        .map_err(|error| {
            Box::new(error_response(OperatorRulesError::new(
                ErrorCode::InvalidId,
                error.to_string(),
            )))
        })
}

fn json<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, Box<Response>> {
    payload.map(|Json(value)| value).map_err(|error| {
        let status = if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        };
        Box::new(bounded_json(
            status,
            &ApiError {
                code: if status == StatusCode::PAYLOAD_TOO_LARGE {
                    "transport_limit_exceeded"
                } else {
                    "invalid_json"
                }
                .into(),
                error: shorten(error.body_text()),
            },
        ))
    })
}

fn typed_header(
    headers: &HeaderMap,
    name: axum::http::header::HeaderName,
    kind: &str,
) -> Result<Option<String>, Box<Response>> {
    let mut values = headers.get_all(&name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Box::new(bad_request("header must occur exactly once")));
    }
    let value = value
        .to_str()
        .map_err(|_| Box::new(bad_request("header is not valid ASCII")))?;
    let prefix = format!("\"{kind}:");
    let Some(digest) = value
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix('"'))
    else {
        return Err(Box::new(bad_request("ETag must be a quoted typed digest")));
    };
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Box::new(bad_request("ETag digest must be SHA-256")));
    }
    Ok(Some(digest.to_ascii_lowercase()))
}

fn plain_header(headers: &HeaderMap, name: &'static str) -> Result<Option<String>, Box<Response>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Box::new(bad_request("header must occur exactly once")));
    }
    value
        .to_str()
        .map(str::to_string)
        .map(Some)
        .map_err(|_| Box::new(bad_request("header is not valid ASCII")))
}

fn with_etag(mut response: Response, kind: &str, digest: &str) -> Response {
    if let Ok(value) = HeaderValue::try_from(format!("\"{kind}:{digest}\"")) {
        response.headers_mut().insert(ETAG, value);
    }
    response
}

fn bounded_json(status: StatusCode, value: &impl Serialize) -> Response {
    match serde_json::to_vec(value) {
        Ok(bytes) if bytes.len() <= TransportLimits::REST.max_response_bytes => {
            let mut response = Response::new(Body::from(bytes));
            *response.status_mut() = status;
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            response
        }
        Ok(_) => error_response(OperatorRulesError::new(
            ErrorCode::TransportLimitExceeded,
            "response exceeds the REST response limit",
        )),
        Err(_) => unavailable("operator-rule response encoding failed"),
    }
}

fn error_response(error: OperatorRulesError) -> Response {
    let status = match error.code {
        ErrorCode::UnsupportedContract
        | ErrorCode::InvalidRequest
        | ErrorCode::InvalidId
        | ErrorCode::UnsafePath => StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRule
        | ErrorCode::SchemaUpgradeRequired
        | ErrorCode::BudgetExceeded
        | ErrorCode::ValidationFailed => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::PolicyOwnedByPrimary => StatusCode::FORBIDDEN,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::AlreadyExists
        | ErrorCode::ListMounted
        | ErrorCode::RevisionConflict
        | ErrorCode::RowConflict
        | ErrorCode::PlanConflict
        | ErrorCode::IdempotencyConflict
        | ErrorCode::StaleCursor
        | ErrorCode::TreeChanged => StatusCode::CONFLICT,
        ErrorCode::TransportLimitExceeded => StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::AdmissionRejected => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::StorageUnavailable
        | ErrorCode::RecoveryConflict
        | ErrorCode::RecoveryRequired => StatusCode::SERVICE_UNAVAILABLE,
    };
    bounded_json(
        status,
        &ApiError {
            code: error.code.as_str().into(),
            error: shorten(error.message),
        },
    )
}

fn bad_request(message: impl Into<String>) -> Response {
    bounded_json(
        StatusCode::BAD_REQUEST,
        &ApiError {
            code: "invalid_request".into(),
            error: message.into(),
        },
    )
}

fn unavailable(message: impl Into<String>) -> Response {
    error_response(OperatorRulesError::new(
        ErrorCode::StorageUnavailable,
        message,
    ))
}

fn shorten(mut value: String) -> String {
    const MAX: usize = 4096;
    if value.len() > MAX {
        let mut end = MAX;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
        value.push_str(" [shortened]");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::{Method, Request};
    use tokio::sync::oneshot;
    use tower::ServiceExt;

    use crate::api::operator_rule_jobs::{OperatorRuleJobConfig, OperatorRuleJobSupervisor};
    use crate::operator_rules::{Operation, RuleAction};

    const TOKEN: &str = "operator-rule-rest-token";
    const CONFIG: &str = r#"schema_version = 5
[upstream]
servers = ["192.0.2.1:53"]
[server]
default_profile = "household"
[profiles.household]
display_name = "Household"
lists = {}
"#;

    struct Fixture {
        _temp: tempfile::TempDir,
        router: axum::Router,
        client: OperatorRuleJobClient,
        shutdown: oneshot::Sender<()>,
        supervisor: tokio::task::JoinHandle<()>,
    }

    async fn fixture() -> Fixture {
        fixture_with_packs(CONFIG, Vec::new()).await
    }

    async fn fixture_with_packs(config: &str, packs: Vec<(&str, Vec<u8>)>) -> Fixture {
        fixture_with_job_config(config, packs, OperatorRuleJobConfig::default()).await
    }

    async fn fixture_with_job_config(
        config: &str,
        packs: Vec<(&str, Vec<u8>)>,
        job_config: OperatorRuleJobConfig,
    ) -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let master = temp.path().join("config.toml");
        std::fs::write(&master, config).unwrap();
        if !packs.is_empty() {
            std::fs::create_dir(temp.path().join("packs")).unwrap();
            for (name, bytes) in packs {
                std::fs::write(temp.path().join("packs").join(name), bytes).unwrap();
            }
        }
        let service = Arc::new(crate::operator_rules::OperatorRulesService::new(&master));
        let (supervisor, client) =
            OperatorRuleJobSupervisor::new(service, job_config, None, Arc::new(|_| {}));
        client.recover().await.unwrap();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let supervisor = tokio::spawn(supervisor.run(shutdown_rx));

        let router = test_router(master, client.clone());
        Fixture {
            _temp: temp,
            router,
            client,
            shutdown,
            supervisor,
        }
    }

    fn test_router(master: std::path::PathBuf, client: OperatorRuleJobClient) -> axum::Router {
        let state = crate::api::handlers::tests::test_state_with_stats();
        let mut state = match Arc::try_unwrap(state) {
            Ok(state) => state,
            Err(_) => panic!("test state unexpectedly shared"),
        };
        state.config_path = master;
        state.token_hash = crate::auth::token::hash_token(TOKEN);
        state.operator_rule_jobs = Some(client.clone());
        crate::api::routes::build_router(Arc::new(state), false).layer(MockConnectInfo(
            "192.0.2.10:43100".parse::<std::net::SocketAddr>().unwrap(),
        ))
    }

    fn request(method: Method, uri: &str, body: Body, auth: bool) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if auth {
            builder = builder.header("authorization", format!("Bearer {TOKEN}"));
        }
        builder
            .header("content-type", "application/json")
            .body(body)
            .unwrap()
    }

    async fn json_body(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), JSON_BODY_LIMIT)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn post_plan(fixture: &Fixture, request_id: &str) -> serde_json::Value {
        let inventory = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                "/api/v1/operator-rules/custom-lists",
                Body::empty(),
                true,
            ))
            .await
            .unwrap();
        let revision = json_body(inventory).await["config_revision"]
            .as_str()
            .unwrap()
            .to_string();
        let batch = BatchRequest {
            contract_version: 1,
            request_id: request_id.into(),
            expected_config_revision: revision,
            operations: vec![
                Operation::CreateList {
                    id: "local".into(),
                    display_name: "Local".into(),
                    description: String::new(),
                    into: None,
                },
                Operation::AddDomainRule {
                    id: "local".into(),
                    domain: "ads.example".into(),
                    action: RuleAction::Deny,
                },
                Operation::Mount {
                    id: "local".into(),
                    profile_id: "household".into(),
                },
            ],
            expected_plan_hash: None,
        };
        let response = fixture
            .router
            .clone()
            .oneshot(request(
                Method::POST,
                "/api/v1/operator-rules/plans?limit=1",
                Body::from(serde_json::to_vec(&batch).unwrap()),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("\"config:"));
        json_body(response).await
    }

    fn apply_plan_request(plan: &serde_json::Value, request_id: &str) -> Request<Body> {
        let apply = ApplyRequest {
            contract_version: 1,
            plan_id: plan["plan_id"].as_str().unwrap().into(),
            plan_hash: plan["plan"]["plan_hash"].as_str().unwrap().into(),
            expected_config_revision: plan["plan"]["base_config_revision"]
                .as_str()
                .unwrap()
                .into(),
            request_id: request_id.into(),
        };
        apply_request(&apply)
    }

    fn apply_request(apply: &ApplyRequest) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/operator-rules/apply")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .header(
                IF_MATCH,
                format!("\"config:{}\"", apply.expected_config_revision),
            )
            .header("idempotency-key", &apply.request_id)
            .body(Body::from(serde_json::to_vec(&apply).unwrap()))
            .unwrap()
    }

    #[tokio::test]
    async fn routes_require_auth_and_reject_json_over_one_mibibyte() {
        let fixture = fixture().await;
        let response = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                "/api/v1/operator-rules/capabilities",
                Body::empty(),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = fixture
            .router
            .clone()
            .oneshot(request(
                Method::POST,
                "/api/v1/operator-rules/plans",
                Body::from(vec![b' '; JSON_BODY_LIMIT + 1]),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let _ = fixture.shutdown.send(());
        fixture.supervisor.await.unwrap();
    }

    #[test]
    fn preintent_operator_errors_have_stable_http_statuses() {
        let cases = [
            (ErrorCode::InvalidRequest, StatusCode::BAD_REQUEST),
            (ErrorCode::InvalidId, StatusCode::BAD_REQUEST),
            (ErrorCode::PolicyOwnedByPrimary, StatusCode::FORBIDDEN),
            (ErrorCode::NotFound, StatusCode::NOT_FOUND),
            (ErrorCode::PlanConflict, StatusCode::CONFLICT),
            (
                ErrorCode::TransportLimitExceeded,
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                ErrorCode::ValidationFailed,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (ErrorCode::AdmissionRejected, StatusCode::TOO_MANY_REQUESTS),
            (
                ErrorCode::StorageUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (ErrorCode::RecoveryRequired, StatusCode::SERVICE_UNAVAILABLE),
        ];
        for (code, expected) in cases {
            let response = error_response(OperatorRulesError::new(code, "test"));
            assert_eq!(response.status(), expected, "{}", code.as_str());
        }
    }

    #[tokio::test]
    async fn apply_requires_typed_matching_headers_and_reuses_location() {
        let fixture = fixture().await;
        let plan = post_plan(&fixture, "rest-apply").await;
        let plan_id = plan["plan_id"].as_str().unwrap();
        let plan_hash = plan["plan"]["plan_hash"].as_str().unwrap();
        let revision = plan["plan"]["base_config_revision"].as_str().unwrap();
        let base_policy_hash = plan["plan"]["base_operator_policy_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        let candidate_policy_hash = plan["plan"]["candidate_operator_policy_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        let apply = ApplyRequest {
            contract_version: 1,
            plan_id: plan_id.into(),
            plan_hash: plan_hash.into(),
            expected_config_revision: revision.into(),
            request_id: "rest-apply".into(),
        };
        let bytes = serde_json::to_vec(&apply).unwrap();

        let missing = fixture
            .router
            .clone()
            .oneshot(request(
                Method::POST,
                "/api/v1/operator-rules/apply",
                Body::from(bytes.clone()),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::PRECONDITION_REQUIRED);

        let wrong_type = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/operator-rules/apply")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .header(IF_MATCH, format!("\"pack:{revision}\""))
            .header("idempotency-key", "rest-apply")
            .body(Body::from(bytes.clone()))
            .unwrap();
        let wrong_type = fixture.router.clone().oneshot(wrong_type).await.unwrap();
        assert_eq!(wrong_type.status(), StatusCode::BAD_REQUEST);

        let mut mismatched_revision_body = apply_plan_request(&plan, "rest-apply");
        *mismatched_revision_body.body_mut() = Body::from(
            serde_json::to_vec(&ApplyRequest {
                contract_version: 1,
                plan_id: plan_id.into(),
                plan_hash: plan_hash.into(),
                expected_config_revision: "0".repeat(64),
                request_id: "rest-apply".into(),
            })
            .unwrap(),
        );
        let mismatched_revision = fixture
            .router
            .clone()
            .oneshot(mismatched_revision_body)
            .await
            .unwrap();
        assert_eq!(mismatched_revision.status(), StatusCode::BAD_REQUEST);

        let missing_idempotency = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/operator-rules/apply")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .header(IF_MATCH, format!("\"config:{revision}\""))
            .body(Body::from(bytes.clone()))
            .unwrap();
        let missing_idempotency = fixture
            .router
            .clone()
            .oneshot(missing_idempotency)
            .await
            .unwrap();
        assert_eq!(missing_idempotency.status(), StatusCode::BAD_REQUEST);

        let mismatched_idempotency = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/operator-rules/apply")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .header(IF_MATCH, format!("\"config:{revision}\""))
            .header("idempotency-key", "different-request")
            .body(Body::from(bytes.clone()))
            .unwrap();
        let mismatched_idempotency = fixture
            .router
            .clone()
            .oneshot(mismatched_idempotency)
            .await
            .unwrap();
        assert_eq!(mismatched_idempotency.status(), StatusCode::BAD_REQUEST);

        let submit = || {
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/operator-rules/apply")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .header(IF_MATCH, format!("\"config:{revision}\""))
                .header("idempotency-key", "rest-apply")
                .body(Body::from(bytes.clone()))
                .unwrap()
        };
        let first = fixture.router.clone().oneshot(submit()).await.unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let first_location = first.headers().get(LOCATION).unwrap().clone();
        let second = fixture.router.clone().oneshot(submit()).await.unwrap();
        assert_eq!(second.status(), StatusCode::ACCEPTED);
        assert_eq!(second.headers().get(LOCATION).unwrap(), &first_location);

        let operation = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                first_location.to_str().unwrap(),
                Body::empty(),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(operation.status(), StatusCode::OK);
        let operation = json_body(operation).await;
        assert!(matches!(
            operation["activation"]["state"].as_str(),
            Some("pending" | "unknown")
        ));
        let expected_policy_hash = match operation["persistence"].as_str() {
            Some("prepared") => &base_policy_hash,
            Some("committed") => &candidate_policy_hash,
            other => panic!("unexpected operation persistence: {other:?}"),
        };
        assert_eq!(
            operation["operator_policy_hash"].as_str(),
            Some(expected_policy_hash.as_str()),
            "an operation receipt must report the semantic identity matching its persistence state"
        );
        let _ = fixture.shutdown.send(());
        fixture.supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn durable_apply_replay_survives_restart_without_a_transient_plan() {
        let fixture = fixture().await;
        let plan = post_plan(&fixture, "rest-restart-replay").await;
        let original = ApplyRequest {
            contract_version: 1,
            plan_id: plan["plan_id"].as_str().unwrap().into(),
            plan_hash: plan["plan"]["plan_hash"].as_str().unwrap().into(),
            expected_config_revision: plan["plan"]["base_config_revision"]
                .as_str()
                .unwrap()
                .into(),
            request_id: "rest-restart-replay".into(),
        };
        let first = fixture
            .router
            .clone()
            .oneshot(apply_request(&original))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let location = first.headers().get(LOCATION).unwrap().clone();
        let first = json_body(first).await;
        fixture
            .client
            .wait_terminal(&actor(), first["operation_id"].as_str().unwrap())
            .await
            .unwrap();
        let _ = fixture.shutdown.send(());
        fixture.supervisor.await.unwrap();

        let master = fixture._temp.path().join("config.toml");
        let service = Arc::new(crate::operator_rules::OperatorRulesService::new(&master));
        let (supervisor, client) = OperatorRuleJobSupervisor::new(
            service,
            OperatorRuleJobConfig::default(),
            None,
            Arc::new(|_| {}),
        );
        client.recover().await.unwrap();
        let router = test_router(master, client);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let supervisor = tokio::spawn(supervisor.run(shutdown_rx));

        let replay = router
            .clone()
            .oneshot(apply_request(&original))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::ACCEPTED);
        assert_eq!(replay.headers().get(LOCATION).unwrap(), &location);

        let conflicting_hash = ApplyRequest {
            plan_hash: "0".repeat(64),
            ..original.clone()
        };
        let conflict = router
            .clone()
            .oneshot(apply_request(&conflicting_hash))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert_eq!(json_body(conflict).await["code"], "idempotency_conflict");

        let conflicting_precondition = ApplyRequest {
            expected_config_revision: "0".repeat(64),
            ..original
        };
        let conflict = router
            .oneshot(apply_request(&conflicting_precondition))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert_eq!(json_body(conflict).await["code"], "idempotency_conflict");

        let _ = shutdown.send(());
        supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn durable_apply_replay_survives_plan_and_job_ttl_expiry() {
        // A real-clock TTL must leave enough headroom for this test to run
        // alongside the full parallel suite before the initial apply.
        let ttl = std::time::Duration::from_secs(2);
        let fixture = fixture_with_job_config(
            CONFIG,
            Vec::new(),
            OperatorRuleJobConfig {
                plan_ttl: ttl,
                terminal_job_ttl: ttl,
                ..OperatorRuleJobConfig::default()
            },
        )
        .await;
        let plan = post_plan(&fixture, "rest-expired-replay").await;
        let original = ApplyRequest {
            contract_version: 1,
            plan_id: plan["plan_id"].as_str().unwrap().into(),
            plan_hash: plan["plan"]["plan_hash"].as_str().unwrap().into(),
            expected_config_revision: plan["plan"]["base_config_revision"]
                .as_str()
                .unwrap()
                .into(),
            request_id: "rest-expired-replay".into(),
        };
        let first = fixture
            .router
            .clone()
            .oneshot(apply_request(&original))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let location = first.headers().get(LOCATION).unwrap().clone();
        let first = json_body(first).await;
        fixture
            .client
            .wait_terminal(&actor(), first["operation_id"].as_str().unwrap())
            .await
            .unwrap();
        tokio::time::sleep(ttl + std::time::Duration::from_millis(100)).await;

        let expired_plan = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/api/v1/operator-rules/plans/{}/impacts", original.plan_id),
                Body::empty(),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(expired_plan.status(), StatusCode::CONFLICT);

        let replay = fixture
            .router
            .clone()
            .oneshot(apply_request(&original))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::ACCEPTED);
        assert_eq!(replay.headers().get(LOCATION).unwrap(), &location);

        let conflicting = ApplyRequest {
            plan_hash: "0".repeat(64),
            ..original
        };
        let conflict = fixture
            .router
            .clone()
            .oneshot(apply_request(&conflicting))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert_eq!(json_body(conflict).await["code"], "idempotency_conflict");

        let _ = fixture.shutdown.send(());
        fixture.supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn operation_and_page_limits_map_to_documented_statuses() {
        let fixture = fixture().await;
        let page = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                "/api/v1/operator-rules/custom-lists?limit=501",
                Body::empty(),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let page_error = json_body(page).await;
        assert_eq!(page_error["code"], "transport_limit_exceeded");

        let inventory = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                "/api/v1/operator-rules/custom-lists",
                Body::empty(),
                true,
            ))
            .await
            .unwrap();
        let revision = json_body(inventory).await["config_revision"]
            .as_str()
            .unwrap()
            .to_string();
        let too_many = BatchRequest {
            contract_version: 1,
            request_id: "too-many".into(),
            expected_config_revision: revision,
            operations: (0..257)
                .map(|index| Operation::CreateList {
                    id: format!("list-{index}"),
                    display_name: String::new(),
                    description: String::new(),
                    into: None,
                })
                .collect(),
            expected_plan_hash: None,
        };
        let too_many = fixture
            .router
            .clone()
            .oneshot(request(
                Method::POST,
                "/api/v1/operator-rules/plans",
                Body::from(serde_json::to_vec(&too_many).unwrap()),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(too_many.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let invalid_id = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                "/api/v1/operator-rules/custom-lists/NOT_VALID",
                Body::empty(),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(invalid_id.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(invalid_id).await["code"], "invalid_id");

        let missing = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                "/api/v1/operator-rules/operations/00000000000000000000000000000000",
                Body::empty(),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let _ = fixture.shutdown.send(());
        fixture.supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn unchanged_apply_is_accepted_only_after_durable_intent() {
        let fixture = fixture().await;
        let initial_plan = post_plan(&fixture, "noop-setup").await;
        let initial = fixture
            .router
            .clone()
            .oneshot(apply_plan_request(&initial_plan, "noop-setup"))
            .await
            .unwrap();
        assert_eq!(initial.status(), StatusCode::ACCEPTED);
        let initial = json_body(initial).await;
        fixture
            .client
            .wait_terminal(&actor(), initial["operation_id"].as_str().unwrap())
            .await
            .unwrap();

        let inventory = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                "/api/v1/operator-rules/custom-lists",
                Body::empty(),
                true,
            ))
            .await
            .unwrap();
        let revision = json_body(inventory).await["config_revision"]
            .as_str()
            .unwrap()
            .to_string();
        let noop = BatchRequest {
            contract_version: 1,
            request_id: "noop".into(),
            expected_config_revision: revision,
            operations: vec![Operation::SetMetadata {
                id: "local".into(),
                display_name: Some("Local".into()),
                description: Some(String::new()),
            }],
            expected_plan_hash: None,
        };
        let noop = fixture
            .router
            .clone()
            .oneshot(request(
                Method::POST,
                "/api/v1/operator-rules/plans",
                Body::from(serde_json::to_vec(&noop).unwrap()),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(noop.status(), StatusCode::OK);
        let noop = json_body(noop).await;
        assert_eq!(noop["plan"]["changed"], false);
        assert_eq!(noop["plan"]["semantic_changed"], false);

        let first = fixture
            .router
            .clone()
            .oneshot(apply_plan_request(&noop, "noop"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let location = first.headers().get(LOCATION).unwrap().clone();
        let first = json_body(first).await;
        assert_eq!(first["state"], "accepted");
        assert_eq!(first["prepared"]["changed"], false);
        let terminal = fixture
            .client
            .wait_terminal(&actor(), first["operation_id"].as_str().unwrap())
            .await
            .unwrap();
        assert!(!terminal.changed);
        assert_eq!(terminal.activation.state, "not_required");
        assert!(terminal.activation.correlation_id.is_none());
        assert!(terminal.activation.reload_outcome.is_none());
        assert_eq!(
            terminal.operator_policy_hash.as_deref(),
            noop["plan"]["candidate_operator_policy_hash"].as_str(),
            "a no-op receipt still records the unchanged semantic identity"
        );

        let replay = fixture
            .router
            .clone()
            .oneshot(apply_plan_request(&noop, "noop"))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::ACCEPTED);
        assert_eq!(replay.headers().get(LOCATION).unwrap(), &location);

        let _ = fixture.shutdown.send(());
        fixture.supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn export_stream_is_one_owned_snapshot_while_pack_changes() {
        let fixture = fixture().await;
        let plan = post_plan(&fixture, "export-initial").await;
        let initial_apply = ApplyRequest {
            contract_version: 1,
            plan_id: plan["plan_id"].as_str().unwrap().into(),
            plan_hash: plan["plan"]["plan_hash"].as_str().unwrap().into(),
            expected_config_revision: plan["plan"]["base_config_revision"]
                .as_str()
                .unwrap()
                .into(),
            request_id: "export-initial".into(),
        };
        let initial = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/operator-rules/apply")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .header(
                IF_MATCH,
                format!("\"config:{}\"", initial_apply.expected_config_revision),
            )
            .header("idempotency-key", "export-initial")
            .body(Body::from(serde_json::to_vec(&initial_apply).unwrap()))
            .unwrap();
        let initial = fixture.router.clone().oneshot(initial).await.unwrap();
        assert_eq!(initial.status(), StatusCode::ACCEPTED);
        let initial = json_body(initial).await;
        fixture
            .client
            .wait_terminal(&actor(), initial["operation_id"].as_str().unwrap())
            .await
            .unwrap();

        // Retain the response without polling its body. A subsequent write
        // must not change either these bytes or this pack ETag.
        let captured = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                "/api/v1/operator-rules/custom-lists/local/export",
                Body::empty(),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(captured.status(), StatusCode::OK);
        let captured_etag = captured.headers().get(ETAG).unwrap().clone();
        assert!(captured_etag.to_str().unwrap().starts_with("\"pack:"));

        let inventory = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                "/api/v1/operator-rules/custom-lists",
                Body::empty(),
                true,
            ))
            .await
            .unwrap();
        let revision = json_body(inventory).await["config_revision"]
            .as_str()
            .unwrap()
            .to_string();
        let update = BatchRequest {
            contract_version: 1,
            request_id: "export-update".into(),
            expected_config_revision: revision,
            operations: vec![Operation::AddDomainRule {
                id: "local".into(),
                domain: "tracker.example".into(),
                action: RuleAction::Deny,
            }],
            expected_plan_hash: None,
        };
        let update = fixture
            .router
            .clone()
            .oneshot(request(
                Method::POST,
                "/api/v1/operator-rules/plans",
                Body::from(serde_json::to_vec(&update).unwrap()),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(update.status(), StatusCode::OK);
        let update = json_body(update).await;
        let update_apply = ApplyRequest {
            contract_version: 1,
            plan_id: update["plan_id"].as_str().unwrap().into(),
            plan_hash: update["plan"]["plan_hash"].as_str().unwrap().into(),
            expected_config_revision: update["plan"]["base_config_revision"]
                .as_str()
                .unwrap()
                .into(),
            request_id: "export-update".into(),
        };
        let update_request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/operator-rules/apply")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .header(
                IF_MATCH,
                format!("\"config:{}\"", update_apply.expected_config_revision),
            )
            .header("idempotency-key", "export-update")
            .body(Body::from(serde_json::to_vec(&update_apply).unwrap()))
            .unwrap();
        let updated = fixture
            .router
            .clone()
            .oneshot(update_request)
            .await
            .unwrap();
        assert_eq!(updated.status(), StatusCode::ACCEPTED);
        let updated = json_body(updated).await;
        fixture
            .client
            .wait_terminal(&actor(), updated["operation_id"].as_str().unwrap())
            .await
            .unwrap();

        let captured_bytes = axum::body::to_bytes(captured.into_body(), JSON_BODY_LIMIT)
            .await
            .unwrap();
        assert_eq!(&captured_bytes[..], b"||ads.example^\n");

        let current = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                "/api/v1/operator-rules/custom-lists/local/export",
                Body::empty(),
                true,
            ))
            .await
            .unwrap();
        assert_ne!(current.headers().get(ETAG).unwrap(), &captured_etag);
        let current_bytes = axum::body::to_bytes(current.into_body(), JSON_BODY_LIMIT)
            .await
            .unwrap();
        assert_eq!(&current_bytes[..], b"||ads.example^\n||tracker.example^\n");

        let _ = fixture.shutdown.send(());
        fixture.supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn export_stream_can_exceed_the_one_mibibyte_json_limit() {
        const LARGE_CONFIG: &str = r#"schema_version = 5
[upstream]
servers = ["192.0.2.1:53"]
[server]
default_profile = "household"
[custom_list_limits]
max_file_bytes = 2097152
[[custom_lists]]
id = "large"
[profiles.household]
display_name = "Household"
lists = {}
"#;
        let pack = b"# padding\n".repeat(120_000);
        assert!(pack.len() > JSON_BODY_LIMIT);
        let fixture = fixture_with_packs(LARGE_CONFIG, vec![("large.txt", pack.clone())]).await;
        let response = fixture
            .router
            .clone()
            .oneshot(request(
                Method::GET,
                "/api/v1/operator-rules/custom-lists/large/export",
                Body::empty(),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("\"pack:"));
        let bytes = axum::body::to_bytes(response.into_body(), pack.len())
            .await
            .unwrap();
        assert_eq!(&bytes[..], &pack);

        let _ = fixture.shutdown.send(());
        fixture.supervisor.await.unwrap();
    }
}
