//! Control Plane API v1 (JSON over HTTP).
//!
//! Every `/v1` route except `/v1/info` authenticates first (bearer token or
//! service signature), then authorizes inside its operation. Breaking
//! changes go to `/v2`, never into `/v1`.
//!
//! | Method | Path | |
//! |---|---|---|
//! | GET | `/live`, `/ready` | health (no auth) |
//! | GET | `/metrics` | public in development; in production only with the metrics token (or `ENCOMPUTE_METRICS_PUBLIC=true`) |
//! | GET | `/v1/info` | service ID, public key, API version |
//! | GET | `/v1/whoami` | the caller and its roles |
//! | POST | `/v1/organizations` | platform admins |
//! | GET | `/v1/organizations/{id}` | |
//! | POST | `/v1/organizations/{id}/users` | |
//! | POST | `/v1/organizations/{id}/users/{user}/disable` | |
//! | POST | `/v1/organizations/{id}/memberships/remove` | a principal's role (or all its roles) |
//! | POST | `/v1/organizations/{id}/service-accounts` | |
//! | POST | `/v1/organizations/{id}/service-accounts/{sa}/disable` | |
//! | POST | `/v1/organizations/{id}/key-rotations` | root key rotations, for the audit trail |
//! | POST, GET | `/v1/projects` | |
//! | GET | `/v1/projects/{id}` | |
//! | POST | `/v1/projects/{id}/members` | owners invite, the invited organization accepts |
//! | POST | `/v1/projects/{id}/members/remove`, `/v1/projects/{id}/policies` | |
//! | POST | `/v1/policies/{id}/approve` | |
//! | POST, GET | `/v1/assets` | |
//! | GET | `/v1/assets/{id}`, `/v1/assets/{id}/lineage` | |
//! | POST | `/v1/assets/{id}/approvals`, `/v1/assets/{id}/approvals/withdraw`, `/v1/assets/{id}/revoke` | |
//! | POST | `/v1/plans` | |
//! | POST, GET | `/v1/jobs` | POST needs `Idempotency-Key` |
//! | GET | `/v1/jobs/{id}` | |
//! | POST | `/v1/jobs/{id}/cancel`, `/approve`, `/start`, `/complete`, `/receipt` | |
//! | POST, GET | `/v1/evaluators` | |
//! | POST | `/v1/evaluators/{id}/status` | |
//! | GET | `/v1/privacy/{asset}`, `/v1/privacy/{asset}/ledger` | |
//! | POST | `/v1/privacy/{asset}/events` | |
//! | POST | `/v1/privacy/{asset}/spenders` | owners authorize a SecAgg service |
//! | GET | `/v1/trust/{job}` | |
//! | GET | `/v1/audit?organization=&after=&limit=` | an organization's trail |
//! | GET | `/v1/audit?project=&after=&limit=` | a governed project's events, as every participant sees them |
//! | POST | `/v1/audit/checkpoints` | |
//! | POST | `/v1/messages` | services only |
//! | POST, GET | `/v1/organizations/{id}/governance-keys` | governed projects: an organization's governance public keys |
//! | POST | `/v1/organizations/{id}/governance-keys/{key}/approve`, `.../revoke` | a different security admin approves |
//! | GET | `/v1/organizations/{id}/governance-key-attestation?key_id=` | the control plane's signed attestation of an organization's governance key (active, or the one named), to members of organizations sharing a project with it |
//! | POST, GET | `/v1/projects/{id}/purposes` | governed projects |
//! | GET | `/v1/purposes/{id}` | |
//! | POST | `/v1/purposes/{id}/approve`, `/accept`, `/retire` | acceptance carries the organization's governance-key signature |
//! | POST | `/v1/authorizations` | owner authorizations (v2), proposed without approvals |
//! | GET | `/v1/authorizations/{id}` | to the owner's members: the document to sign |
//! | POST | `/v1/authorizations/{id}/approve`, `/signature`, `/revoke` | four eyes, then the owner's governance-key signature |
//! | GET | `/v1/projects/{id}/audit?after=&limit=` | a governed project's shared log: events with inclusion proofs against the latest signed checkpoint, the checkpoint and its witnesses (members and auditors) |
//! | GET | `/v1/projects/{id}/checkpoints/latest?since=` | the latest signed checkpoint, its witnesses and, from `since`, the control plane's signed consistency proof |
//! | POST | `/v1/projects/{id}/checkpoints/{size}/witnesses` | a member organization's security admin countersigns a checkpoint with the organization's governance key |
//! | POST, GET | `/v1/organizations/{id}/key-brokers` | an organization's own key brokers (sovereign custody); a security admin registers |
//! | POST | `/v1/jobs/{id}/release-ticket` | governed projects: the scheduled evaluator asks for a key-release ticket |
//! | POST | `/v1/jobs/{id}/derived-assets` | governed projects: a person of a recipient records a succeeded job's result as a derived asset |
//! | POST | `/v1/assets/{id}/exports` | governed projects: the custodian of a derived result asks for an export ticket to one recipient |
//! | GET | `/v1/assets/{id}/release-cosignature` | governed projects: the control plane's co-signature of a derived result's release record in force, to its custodian's members |
//! | POST | `/v1/assets/{id}/release-cosignature` | governed projects: a security admin of the custodian has it re-issued with the lineage owners' current governance keys (after a rotation) |
//! | POST | `/v1/assets/{id}/retention` | a dataset version's owner brings its deletion date forward or extends its evidence retention |

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
use encompute_verification::http;
use encompute_verification::service::{sha256_hex, ServiceHeaders};

use crate::audit;
use crate::authn::Credentials;
use crate::authz::{not_found, require};
use crate::control::{Control, Ctx};
use crate::log::LogLine;
use crate::model::{bad, new_id, Role, PLATFORM_ORG};

pub const MAX_BODY: usize = 8 << 20;

/// An HTTP request, independent of the server library.
pub struct Request {
    pub method: String,
    /// Path and query, e.g. `/v1/audit?after=10`.
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

fn json_response(status: u16, v: &Value) -> Response {
    Response {
        status,
        content_type: "application/json",
        body: serde_json::to_vec(v).expect("serializable"),
    }
}

pub fn status_of(code: Code) -> u16 {
    match code {
        Code::Unauthenticated | Code::ServiceAuthentication => 401,
        Code::Forbidden | Code::ExportDenied => 403,
        // Governance refusals (ENC2701..ENC2712): the request is understood
        // and refused by an owner's authorization, purpose or key state.
        Code::GovernanceAuthorizationMissing
        | Code::GovernancePurposeMismatch
        | Code::GovernanceProgramNotAuthorized
        | Code::GovernanceAssetVersionMismatch
        | Code::GovernanceAuthorizationExpired
        | Code::GovernanceAuthorizationRevoked
        | Code::GovernanceFourEyesIncomplete
        | Code::GovernanceKeyRevoked
        | Code::GovernanceReleaseClass
        | Code::GovernanceResidency
        | Code::GovernanceLinkageMismatch
        | Code::GovernanceReleaseTicket
        | Code::GovernanceCustody
        | Code::GovernanceAuditorSeparation => 403,
        Code::NotFound => 404,
        Code::Conflict | Code::PrivacyBudgetExceeded | Code::GovernanceCheckpointWitness => 409,
        Code::PlanningFailed | Code::PlanInvalid => 422,
        Code::Scheduling => 503,
        Code::Remote | Code::InsecureConfiguration | Code::PrivacyLedger => 500,
        _ => 400,
    }
}

fn error_response(e: &Error) -> Response {
    json_response(
        status_of(e.code),
        &json!({"code": e.code.as_str(), "message": e.message}),
    )
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|e| bad(format!("request body: {e}")))
}

/// Whether the query string names a parameter twice. Such a request is
/// refused: a signature covers the query as sent, and two readers could
/// otherwise pick different values of the same name.
fn duplicate_query_key(url: &str) -> bool {
    let Some((_, q)) = url.split_once('?') else {
        return false;
    };
    let mut seen = std::collections::BTreeSet::new();
    q.split('&')
        .filter(|kv| !kv.is_empty())
        .any(|kv| !seen.insert(kv.split_once('=').map_or(kv, |(k, _)| k)))
}

/// Constant-time equality of a presented and the expected secret.
fn same_secret(a: &str, b: &str) -> bool {
    use sha2::{Digest, Sha256};
    // Equal-length digests, compared without an early exit.
    let (x, y) = (Sha256::digest(a.as_bytes()), Sha256::digest(b.as_bytes()));
    x.iter()
        .zip(y.iter())
        .fold(0u8, |acc, (p, q)| acc | (p ^ q))
        == 0
}

fn query(url: &str) -> BTreeMap<String, String> {
    url.split_once('?')
        .map(|(_, q)| {
            q.split('&')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn request_id(r: &Request) -> String {
    r.header("X-Request-Id")
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 64
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .unwrap_or_else(|| new_id("req"))
}

/// Handles one request.
pub fn handle(control: &Control, r: &Request) -> Response {
    let started = Instant::now();
    let rid = request_id(r);
    let path = r.url.split('?').next().unwrap_or("").to_owned();
    let (resp, principal) = dispatch(control, r, &path, &rid);
    let class = format!("{}xx", resp.status / 100);
    control.metrics.inc("encompute_http_requests_total", &class);
    LogLine::new(&control.service_id, "request")
        .id("request_id", Some(&rid))
        .id("principal", principal.as_deref())
        .field("method", &r.method)
        .field("path", &path)
        .field("status", resp.status)
        .field("ms", started.elapsed().as_millis())
        .emit();
    resp
}

fn dispatch(control: &Control, r: &Request, path: &str, rid: &str) -> (Response, Option<String>) {
    match (r.method.as_str(), path) {
        ("GET", "/live") => return (json_response(200, &json!({"live": true})), None),
        ("GET", "/ready") => {
            let ready = control.db.ping();
            let s = if ready { 200 } else { 503 };
            return (json_response(s, &json!({"ready": ready})), None);
        }
        ("GET", "/metrics") => {
            use crate::config::MetricsAccess;
            let allowed = match &control.metrics_access {
                MetricsAccess::Public => true,
                MetricsAccess::Token(t) => {
                    r.header("Authorization")
                        .and_then(|a| a.strip_prefix("Bearer ").map(|x| same_secret(x.trim(), t)))
                        == Some(true)
                }
                MetricsAccess::Closed => false,
            };
            if !allowed {
                return (
                    error_response(&Error::new(
                        Code::Unauthenticated,
                        "metrics need the metrics token",
                    )),
                    None,
                );
            }
            return (
                Response {
                    status: 200,
                    content_type: "text/plain; version=0.0.4",
                    body: control.render_metrics().into_bytes(),
                },
                None,
            );
        }
        ("GET", "/v1/info") => {
            return (
                json_response(
                    200,
                    &json!({"service": control.service_id, "api": "v1",
                            "public_key": control.signer.public_key_hex(),
                            "production": control.env.is_production()}),
                ),
                None,
            )
        }
        _ => {}
    }
    if r.body.len() > MAX_BODY {
        return (error_response(&bad("request body too large")), None);
    }
    if duplicate_query_key(&r.url) {
        return (
            error_response(&bad("a query parameter appears more than once")),
            None,
        );
    }
    // Authenticate.
    let service = match ServiceHeaders::from_lookup(|h| r.header(h)) {
        Ok(s) => s,
        Err(e) => return (error_response(&e), None),
    };
    let authorization = r.header("Authorization");
    let principal = control.db.conn().and_then(|mut c| {
        control.auth.authenticate(
            &mut *c,
            &Credentials {
                authorization: authorization.as_deref(),
                service,
                method: &r.method,
                // The whole target: the query is signed too.
                path: &r.url,
                body: &r.body,
            },
        )
    });
    let principal = match principal {
        Ok(p) => p,
        Err(e) => return (error_response(&e), None),
    };
    let ctx = Ctx {
        principal,
        request_id: rid.to_owned(),
    };
    let who = Some(ctx.principal.id.clone());
    let out = route(control, &ctx, r, path);
    let resp = match out {
        Ok((status, v)) => json_response(status, &v),
        Err(e) => error_response(&e),
    };
    (resp, who)
}

fn route(control: &Control, ctx: &Ctx, r: &Request, path: &str) -> Result<(u16, Value)> {
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let m = r.method.as_str();
    let ok = |v: Value| Ok((200, v));
    let created = |v: Value| Ok((201, v));
    match (m, segs.as_slice()) {
        ("GET", ["v1", "whoami"]) => {
            ok(serde_json::to_value(&ctx.principal).expect("serializable"))
        }

        ("POST", ["v1", "organizations"]) => {
            created(control.create_organization(ctx, parse(&r.body)?)?)
        }
        ("GET", ["v1", "organizations", id]) => ok(control.get_organization(ctx, id)?),
        ("POST", ["v1", "organizations", id, "users"]) => {
            created(control.create_user(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "organizations", id, "service-accounts"]) => {
            let mut v: Value = parse(&r.body)?;
            let url = v.get("url").and_then(|u| u.as_str()).map(str::to_owned);
            if let Some(o) = v.as_object_mut() {
                o.remove("url");
            }
            created(control.create_service_account(
                ctx,
                id,
                serde_json::from_value(v).map_err(|e| bad(e.to_string()))?,
                url,
            )?)
        }
        ("POST", ["v1", "organizations", id, "service-accounts", sa, "disable"]) => {
            ok(control.disable_service_account(ctx, id, sa)?)
        }
        ("POST", ["v1", "organizations", id, "users", user, "disable"]) => {
            ok(control.disable_user(ctx, id, user)?)
        }
        ("POST", ["v1", "organizations", id, "memberships", "remove"]) => {
            ok(control.remove_membership(ctx, id, parse(&r.body)?)?)
        }
        ("GET", ["v1", "security", "legacy-service-admins"]) => {
            ok(control.list_legacy_service_admins(ctx)?)
        }

        ("POST", ["v1", "organizations", id, "key-rotations"]) => {
            created(control.record_key_rotation(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "projects"]) => created(control.create_project(ctx, parse(&r.body)?)?),
        ("GET", ["v1", "projects"]) => ok(control.list_projects(ctx)?),
        ("GET", ["v1", "projects", id]) => ok(control.get_project(ctx, id)?),
        ("POST", ["v1", "projects", id, "members"]) => {
            ok(control.add_project_member(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "projects", id, "members", "remove"]) => {
            ok(control.remove_project_member(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "organizations", id, "governance-keys"]) => {
            created(control.propose_governance_key(ctx, id, parse(&r.body)?)?)
        }
        ("GET", ["v1", "organizations", id, "governance-keys"]) => {
            ok(control.list_governance_keys(ctx, id)?)
        }
        ("GET", ["v1", "organizations", id, "governance-key-attestation"]) => {
            let q = query(&r.url);
            ok(control.governance_key_attestation(ctx, id, q.get("key_id").map(String::as_str))?)
        }
        ("POST", ["v1", "organizations", id, "governance-keys", key, "approve"]) => {
            ok(control.approve_governance_key(ctx, id, key)?)
        }
        ("POST", ["v1", "organizations", id, "governance-keys", key, "revoke"]) => {
            ok(control.revoke_governance_key(ctx, id, key)?)
        }
        ("POST", ["v1", "projects", id, "purposes"]) => {
            created(control.propose_purpose(ctx, id, parse(&r.body)?)?)
        }
        ("GET", ["v1", "projects", id, "purposes"]) => ok(control.list_purposes(ctx, id)?),
        ("GET", ["v1", "purposes", id]) => ok(control.get_purpose(ctx, id)?),
        ("POST", ["v1", "purposes", id, "approve"]) => ok(control.approve_purpose(ctx, id)?),
        ("POST", ["v1", "purposes", id, "accept"]) => {
            ok(control.accept_purpose(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "purposes", id, "retire"]) => ok(control.retire_purpose(ctx, id)?),
        ("POST", ["v1", "authorizations"]) => {
            created(control.propose_authorization(ctx, parse(&r.body)?)?)
        }
        ("GET", ["v1", "authorizations", id]) => ok(control.get_authorization(ctx, id)?),
        ("POST", ["v1", "authorizations", id, "approve"]) => {
            ok(control.approve_authorization(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "authorizations", id, "signature"]) => {
            ok(control.sign_authorization(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "authorizations", id, "revoke"]) => {
            ok(control.revoke_authorization(ctx, id, parse(&r.body)?)?)
        }
        ("GET", ["v1", "projects", id, "audit"]) => {
            let q = query(&r.url);
            let after = number(&q, "after")?.unwrap_or(0);
            let limit = number(&q, "limit")?.unwrap_or(100);
            if limit == 0 {
                return Err(bad("limit is a whole number from 1"));
            }
            let limit = limit.min(crate::ops::PROJECT_LOG_MAX_PAGE as u64) as i64;
            ok(control.project_audit_log(ctx, id, after, limit)?)
        }
        ("GET", ["v1", "projects", id, "checkpoints", "latest"]) => {
            let since = number(&query(&r.url), "since")?;
            ok(control.project_checkpoint_latest(ctx, id, since)?)
        }
        ("POST", ["v1", "projects", id, "checkpoints", size, "witnesses"]) => {
            let size: u64 = size
                .parse()
                .map_err(|_| bad("a checkpoint is named by its size (a whole number)"))?;
            let (new, v) = control.submit_checkpoint_witness(ctx, id, size, parse(&r.body)?)?;
            if new {
                created(v)
            } else {
                ok(v)
            }
        }
        ("POST", ["v1", "organizations", id, "key-brokers"]) => {
            created(control.register_key_broker(ctx, id, parse(&r.body)?)?)
        }
        ("GET", ["v1", "organizations", id, "key-brokers"]) => {
            ok(control.list_key_brokers(ctx, id)?)
        }
        ("POST", ["v1", "projects", id, "policies"]) => {
            created(control.propose_policy(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "policies", id, "approve"]) => ok(control.approve_policy(ctx, id)?),

        ("POST", ["v1", "assets"]) => created(control.register_asset(ctx, parse(&r.body)?)?),
        ("GET", ["v1", "assets"]) => ok(control.list_assets(ctx)?),
        ("GET", ["v1", "assets", id]) => ok(control.get_asset(ctx, id)?),
        ("GET", ["v1", "assets", id, "lineage"]) => ok(control.lineage(ctx, id)?),
        ("POST", ["v1", "assets", id, "approvals"]) => {
            ok(control.approve_asset(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "assets", id, "approvals", "withdraw"]) => {
            ok(control.withdraw_asset_approval(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "assets", id, "revoke"]) => ok(control.revoke_asset(ctx, id)?),
        ("POST", ["v1", "assets", id, "exports"]) => {
            created(control.export_asset(ctx, id, parse(&r.body)?)?)
        }
        ("GET", ["v1", "assets", id, "release-cosignature"]) => {
            ok(control.release_cosignature(ctx, id)?)
        }
        ("POST", ["v1", "assets", id, "release-cosignature"]) => {
            created(control.reissue_release_cosignature(ctx, id)?)
        }
        ("POST", ["v1", "assets", id, "retention"]) => {
            ok(control.update_retention(ctx, id, parse(&r.body)?)?)
        }

        ("POST", ["v1", "plans"]) => created(control.create_plan(ctx, parse(&r.body)?)?),

        ("POST", ["v1", "jobs"]) => {
            let key = r
                .header("Idempotency-Key")
                .ok_or_else(|| bad("POST /v1/jobs needs an Idempotency-Key header"))?;
            let (v, new) = control.submit_job(ctx, parse(&r.body)?, &key, &sha256_hex(&r.body))?;
            Ok((if new { 201 } else { 200 }, v))
        }
        ("GET", ["v1", "jobs"]) => {
            let q = query(&r.url);
            ok(control.list_jobs(ctx, q.get("project").map(String::as_str))?)
        }
        ("GET", ["v1", "jobs", id]) => ok(control.job_view(ctx, id)?),
        ("POST", ["v1", "jobs", id, "cancel"]) => ok(control.cancel_job(ctx, id)?),
        ("POST", ["v1", "jobs", id, "approve"]) => ok(control.approve_job(ctx, id)?),
        ("POST", ["v1", "jobs", id, "start"]) => ok(control.start_job(ctx, id)?),
        ("POST", ["v1", "jobs", id, "release-ticket"]) => {
            created(control.issue_release_ticket(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "jobs", id, "derived-assets"]) => {
            created(control.register_derived_asset(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "jobs", id, "complete"]) => {
            ok(control.complete_job(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "jobs", id, "receipt"]) => {
            if ctx.principal.service_kind() != Some(crate::model::ServiceKind::Evaluator) {
                return Err(crate::authz::forbidden(
                    "only the job's evaluator reports its receipt",
                ));
            }
            let v: Value = parse(&r.body)?;
            ok(control.evaluator_completed(
                ctx.actor(),
                &ctx.request_id,
                id,
                &v["receipt"],
                v["evaluation_ms"].as_u64().map(|ms| ms as f64 / 1000.0),
            )?)
        }

        ("POST", ["v1", "evaluators"]) => {
            created(control.register_evaluator(ctx, parse(&r.body)?)?)
        }
        ("GET", ["v1", "evaluators"]) => ok(control.list_evaluators(ctx)?),
        ("POST", ["v1", "evaluators", id, "status"]) => {
            ok(control.evaluator_status(ctx, id, parse(&r.body)?)?)
        }

        ("GET", ["v1", "privacy", asset]) => ok(control.privacy_view(ctx, asset)?),
        ("GET", ["v1", "privacy", asset, "ledger"]) => ok(control.privacy_export(ctx, asset)?),
        ("POST", ["v1", "privacy", asset, "events"]) => {
            ok(control.privacy_spend(ctx, asset, parse(&r.body)?)?)
        }
        ("POST", ["v1", "privacy", asset, "spenders"]) => {
            let v: Value = parse(&r.body)?;
            let svc = v["service"]
                .as_str()
                .ok_or_else(|| bad("name the SecAgg service"))?;
            ok(control.authorize_privacy_spender(ctx, asset, svc)?)
        }

        ("GET", ["v1", "trust", job]) => ok(control.trust_report(ctx, job)?),

        ("GET", ["v1", "audit"]) => {
            let q = query(&r.url);
            let after = q.get("after").and_then(|v| v.parse().ok()).unwrap_or(0);
            let limit = q
                .get("limit")
                .and_then(|v| v.parse().ok())
                .unwrap_or(200)
                .clamp(1, 1000);
            // A governed project's events, shared by everyone taking part.
            if let Some(project) = q.get("project") {
                if q.contains_key("organization") {
                    return Err(bad("name an organization or a project, not both"));
                }
                return ok(control.project_audit(ctx, project, after, limit)?);
            }
            let org = q
                .get("organization")
                .cloned()
                .or_else(|| ctx.principal.organization.clone())
                .ok_or_else(|| bad("name an organization"))?;
            require(
                &ctx.principal,
                &org,
                &[Role::Auditor, Role::OrganizationAdmin, Role::SecurityAdmin],
                "reading the audit trail",
            )?;
            let mut c = control.db.conn()?;
            // Another organization's people who acted on this one (an
            // invitation, a removal, a revocation that failed its job)
            // appear as `organization/kind`; each event's hash covers the
            // actor as recorded.
            let mut labels = crate::views::Labels::default();
            let mut events = audit::list(&mut *c, Some(&org), after, limit)?;
            for e in &mut events {
                e.actor = labels.label_outside(&mut *c, &e.actor, Some(&org))?;
            }
            ok(serde_json::to_value(events).expect("serializable"))
        }
        ("POST", ["v1", "audit", "checkpoints"]) => {
            require(
                &ctx.principal,
                PLATFORM_ORG,
                &[Role::Operator, Role::Auditor],
                "checkpointing the audit trail",
            )?;
            created(serde_json::to_value(control.checkpoint_audit()?).expect("serializable"))
        }

        ("POST", ["v1", "messages"]) => {
            if ctx.principal.service_kind().is_none() {
                return Err(crate::authz::forbidden("messages come from services"));
            }
            ok(control.receive_message(ctx, &parse(&r.body)?)?)
        }

        _ => Err(not_found("route", &format!("{m} {path}"))),
    }
}

/// A whole-number query parameter: absent is `None`, anything else that
/// does not parse is a refusal (never a silent default).
fn number(q: &BTreeMap<String, String>, name: &str) -> Result<Option<u64>> {
    q.get(name)
        .map(|v| {
            v.parse()
                .map_err(|_| bad(format!("{name} is a whole number")))
        })
        .transpose()
}

/// Every authenticated route of [`route`], as (method, path with `{}` for
/// each ID). Tests enumerate it: every `POST` is a mutation an auditor is
/// refused (`every_mutating_route_refuses_an_auditor`), every `GET` is
/// scanned for other organizations' private metadata
/// (`governance_views_canary_scan`); a unit test keeps it equal to the
/// router, so a new route is covered by both from the start.
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/v1/whoami"),
    ("POST", "/v1/organizations"),
    ("GET", "/v1/organizations/{}"),
    ("POST", "/v1/organizations/{}/users"),
    ("POST", "/v1/organizations/{}/service-accounts"),
    ("POST", "/v1/organizations/{}/service-accounts/{}/disable"),
    ("POST", "/v1/organizations/{}/users/{}/disable"),
    ("POST", "/v1/organizations/{}/memberships/remove"),
    ("GET", "/v1/security/legacy-service-admins"),
    ("POST", "/v1/organizations/{}/key-rotations"),
    ("POST", "/v1/projects"),
    ("GET", "/v1/projects"),
    ("GET", "/v1/projects/{}"),
    ("POST", "/v1/projects/{}/members"),
    ("POST", "/v1/projects/{}/members/remove"),
    ("POST", "/v1/organizations/{}/governance-keys"),
    ("GET", "/v1/organizations/{}/governance-keys"),
    ("GET", "/v1/organizations/{}/governance-key-attestation"),
    ("POST", "/v1/organizations/{}/governance-keys/{}/approve"),
    ("POST", "/v1/organizations/{}/governance-keys/{}/revoke"),
    ("POST", "/v1/projects/{}/purposes"),
    ("GET", "/v1/projects/{}/purposes"),
    ("GET", "/v1/purposes/{}"),
    ("POST", "/v1/purposes/{}/approve"),
    ("POST", "/v1/purposes/{}/accept"),
    ("POST", "/v1/purposes/{}/retire"),
    ("POST", "/v1/authorizations"),
    ("GET", "/v1/authorizations/{}"),
    ("POST", "/v1/authorizations/{}/approve"),
    ("POST", "/v1/authorizations/{}/signature"),
    ("POST", "/v1/authorizations/{}/revoke"),
    ("GET", "/v1/projects/{}/audit"),
    ("GET", "/v1/projects/{}/checkpoints/latest"),
    ("POST", "/v1/projects/{}/checkpoints/{}/witnesses"),
    ("POST", "/v1/organizations/{}/key-brokers"),
    ("GET", "/v1/organizations/{}/key-brokers"),
    ("POST", "/v1/projects/{}/policies"),
    ("POST", "/v1/policies/{}/approve"),
    ("POST", "/v1/assets"),
    ("GET", "/v1/assets"),
    ("GET", "/v1/assets/{}"),
    ("GET", "/v1/assets/{}/lineage"),
    ("POST", "/v1/assets/{}/approvals"),
    ("POST", "/v1/assets/{}/approvals/withdraw"),
    ("POST", "/v1/assets/{}/revoke"),
    ("POST", "/v1/assets/{}/exports"),
    ("GET", "/v1/assets/{}/release-cosignature"),
    ("POST", "/v1/assets/{}/release-cosignature"),
    ("POST", "/v1/assets/{}/retention"),
    ("POST", "/v1/plans"),
    ("POST", "/v1/jobs"),
    ("GET", "/v1/jobs"),
    ("GET", "/v1/jobs/{}"),
    ("POST", "/v1/jobs/{}/cancel"),
    ("POST", "/v1/jobs/{}/approve"),
    ("POST", "/v1/jobs/{}/start"),
    ("POST", "/v1/jobs/{}/release-ticket"),
    ("POST", "/v1/jobs/{}/derived-assets"),
    ("POST", "/v1/jobs/{}/complete"),
    ("POST", "/v1/jobs/{}/receipt"),
    ("POST", "/v1/evaluators"),
    ("GET", "/v1/evaluators"),
    ("POST", "/v1/evaluators/{}/status"),
    ("GET", "/v1/privacy/{}"),
    ("GET", "/v1/privacy/{}/ledger"),
    ("POST", "/v1/privacy/{}/events"),
    ("POST", "/v1/privacy/{}/spenders"),
    ("GET", "/v1/trust/{}"),
    ("GET", "/v1/audit"),
    ("POST", "/v1/audit/checkpoints"),
    ("POST", "/v1/messages"),
];

/// Serves the API on `listen` with `workers` × 4 connection threads until
/// the process exits (see [`encompute_verification::http`] for the limits:
/// slow or oversized requests are refused before they reach the API).
pub fn serve(control: Arc<Control>, listen: &str, workers: usize) -> Result<()> {
    let server = http::Server::http(listen)
        .map_err(|e| Error::new(Code::Remote, format!("listen {listen}: {e}")))?;
    let limits = http::Limits {
        threads: workers.max(1) * 4,
        ..http::Limits::default()
    };
    serve_on(control, server.with_limits(limits));
    Ok(())
}

/// Serves the API on an already bound server (tests choose its limits).
pub fn serve_on(control: Arc<Control>, server: http::Server) {
    LogLine::new(&control.service_id, "listening")
        .field("addr", server.server_addr().to_string())
        .emit();
    server.serve(&Api(control));
}

struct Api(Arc<Control>);

impl http::Handler for Api {
    fn body_limit(&self, _: &http::Request) -> usize {
        MAX_BODY
    }

    fn handle(&self, r: http::Request) -> http::Response {
        let resp = handle(
            &self.0,
            &Request {
                method: r.method,
                url: r.url,
                headers: r.headers,
                body: r.body,
            },
        );
        http::Response::new(resp.status, resp.content_type, resp.body)
    }
}

#[cfg(test)]
mod tests {
    use super::ROUTES;

    /// [`ROUTES`] is exactly the router's table, in order.
    #[test]
    fn routes_list_every_route_of_the_router() {
        let src = include_str!("api.rs");
        let start = src.find("fn route(").expect("the router");
        let end = src[start..].find("pub const ROUTES").expect("the list") + start;
        let mut found = vec![];
        for line in src[start..end].lines().map(str::trim) {
            let Some(method) = ["GET", "POST"]
                .into_iter()
                .find(|m| line.starts_with(&format!("(\"{m}\", [")))
            else {
                continue;
            };
            let segs = &line[line.find('[').unwrap() + 1..line.find(']').unwrap()];
            let path: String = segs
                .split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(|x| {
                    if x.starts_with('"') {
                        format!("/{}", x.trim_matches('"'))
                    } else {
                        "/{}".to_owned()
                    }
                })
                .collect();
            found.push((method.to_owned(), path));
        }
        let listed: Vec<(String, String)> = ROUTES
            .iter()
            .map(|(m, p)| ((*m).to_owned(), (*p).to_owned()))
            .collect();
        assert_eq!(found, listed, "ROUTES must list every route of the router");
    }
}
