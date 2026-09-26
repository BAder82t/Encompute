//! Control Plane API v1 (JSON over HTTP).
//!
//! Every `/v1` route except `/v1/info` authenticates first (bearer token or
//! service signature), then authorizes inside its operation. Breaking
//! changes go to `/v2`, never into `/v1`.
//!
//! | Method | Path | |
//! |---|---|---|
//! | GET | `/live`, `/ready`, `/metrics` | health (no auth) |
//! | GET | `/v1/info` | service ID, public key, API version |
//! | GET | `/v1/whoami` | the caller and its roles |
//! | POST | `/v1/organizations` | platform admins |
//! | GET | `/v1/organizations/{id}` | |
//! | POST | `/v1/organizations/{id}/users` | |
//! | POST | `/v1/organizations/{id}/service-accounts` | |
//! | POST | `/v1/organizations/{id}/service-accounts/{sa}/disable` | |
//! | POST | `/v1/organizations/{id}/key-rotations` | root key rotations, for the audit trail |
//! | POST, GET | `/v1/projects` | |
//! | GET | `/v1/projects/{id}` | |
//! | POST | `/v1/projects/{id}/members`, `/v1/projects/{id}/policies` | |
//! | POST | `/v1/policies/{id}/approve` | |
//! | POST, GET | `/v1/assets` | |
//! | GET | `/v1/assets/{id}`, `/v1/assets/{id}/lineage` | |
//! | POST | `/v1/assets/{id}/approvals`, `/v1/assets/{id}/revoke` | |
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
//! | GET | `/v1/audit?organization=&after=&limit=` | |
//! | POST | `/v1/audit/checkpoints` | |
//! | POST | `/v1/messages` | services only |

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
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
        Code::NotFound => 404,
        Code::Conflict | Code::PrivacyBudgetExceeded => 409,
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
            return (
                Response {
                    status: 200,
                    content_type: "text/plain; version=0.0.4",
                    body: control.metrics.render().into_bytes(),
                },
                None,
            )
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
                path,
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

        ("POST", ["v1", "organizations", id, "key-rotations"]) => {
            created(control.record_key_rotation(ctx, id, parse(&r.body)?)?)
        }
        ("POST", ["v1", "projects"]) => created(control.create_project(ctx, parse(&r.body)?)?),
        ("GET", ["v1", "projects"]) => ok(control.list_projects(ctx)?),
        ("GET", ["v1", "projects", id]) => ok(control.get_project(ctx, id)?),
        ("POST", ["v1", "projects", id, "members"]) => {
            ok(control.add_project_member(ctx, id, parse(&r.body)?)?)
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
        ("POST", ["v1", "assets", id, "revoke"]) => ok(control.revoke_asset(ctx, id)?),

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
            let after = q.get("after").and_then(|v| v.parse().ok()).unwrap_or(0);
            let limit = q
                .get("limit")
                .and_then(|v| v.parse().ok())
                .unwrap_or(200)
                .clamp(1, 1000);
            let mut c = control.db.conn()?;
            ok(
                serde_json::to_value(audit::list(&mut *c, Some(&org), after, limit)?)
                    .expect("serializable"),
            )
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

/// Serves the API with `workers` threads until the process exits.
pub fn serve(control: Arc<Control>, listen: &str, workers: usize) -> Result<()> {
    let server = Arc::new(
        tiny_http::Server::http(listen)
            .map_err(|e| Error::new(Code::Remote, format!("listen {listen}: {e}")))?,
    );
    LogLine::new(&control.service_id, "listening")
        .field("addr", listen)
        .emit();
    let mut handles = vec![];
    for _ in 0..workers.max(1) {
        let (s, c) = (server.clone(), control.clone());
        handles.push(std::thread::spawn(move || {
            for mut req in s.incoming_requests() {
                let mut body = vec![];
                let too_big = req.body_length().is_some_and(|n| n > MAX_BODY);
                if !too_big {
                    use std::io::Read;
                    let _ = req
                        .as_reader()
                        .take(MAX_BODY as u64 + 1)
                        .read_to_end(&mut body);
                }
                let r = Request {
                    method: req.method().as_str().to_owned(),
                    url: req.url().to_owned(),
                    headers: req
                        .headers()
                        .iter()
                        .map(|h| {
                            (
                                h.field.as_str().as_str().to_owned(),
                                h.value.as_str().to_owned(),
                            )
                        })
                        .collect(),
                    body,
                };
                let resp = if too_big {
                    error_response(&bad("request body too large"))
                } else {
                    handle(&c, &r)
                };
                let h = tiny_http::Header::from_bytes(
                    &b"Content-Type"[..],
                    resp.content_type.as_bytes(),
                )
                .expect("valid header");
                let _ = req.respond(
                    tiny_http::Response::from_data(resp.body)
                        .with_status_code(resp.status)
                        .with_header(h),
                );
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}
