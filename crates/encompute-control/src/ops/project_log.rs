//! A governed project's shared governance log: its leaves with inclusion
//! proofs, its signed checkpoints with consistency proofs, and the member
//! organizations' countersignatures (witnesses).
//!
//! Everything here reads or writes one partition, `p:<project>`, and
//! nothing of another project or of an organization's own events. Leaves
//! hold identifiers, the kind of transition and when, so they are the same
//! bytes for every member and auditor; witnesses are public among them.
//!
//! Witnessing is advisory. A checkpoint every member organization
//! countersigned is labelled `witnessed`; any other is labelled
//! `unwitnessed`. The label never blocks a job, an authorization or an
//! export: it tells a reader how many independent parties vouch that the
//! control plane showed them all one history.

use serde_json::{json, Value};

use encompute_ir::{Code, Error, Result};
use encompute_trust::govlog::{
    ConsistencyProof, Partition, SignedCheckpointWitness, SignedProjectCheckpoint,
};
use encompute_verification::service::now;

use crate::audit::{self, Outcome};
use crate::authz::{conflict, deny_auditor, forbidden, not_found, require_human};
use crate::control::{Control, Ctx};
use crate::db::db_err;
use crate::govlog;
use crate::model::{bad, Role};

use super::tenancy::project_reader;

/// The most leaves one page returns.
pub const MAX_PAGE: i64 = 200;
/// Requests per caller per minute the three project log routes allow by
/// default.
pub const DEFAULT_RATE: u32 = 120;

/// A fixed-window limit per caller on the project log routes (a page of
/// proofs is the dearest read the API has).
pub struct RateLimit {
    per_minute: std::sync::atomic::AtomicU32,
    windows: std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, u32)>>,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            per_minute: DEFAULT_RATE.into(),
            windows: Default::default(),
        }
    }
}

impl RateLimit {
    /// A limit of `per_minute` requests per caller per minute.
    pub fn limited(per_minute: u32) -> Self {
        let l = Self::default();
        l.set(per_minute);
        l
    }

    /// Changes the limit (requests per caller per minute).
    pub fn set(&self, per_minute: u32) {
        self.per_minute
            .store(per_minute, std::sync::atomic::Ordering::Relaxed);
    }

    /// Counts a request by `caller`; refused (retry later) past the limit.
    pub fn hit(&self, caller: &str) -> Result<()> {
        let limit = self.per_minute.load(std::sync::atomic::Ordering::Relaxed);
        let now = std::time::Instant::now();
        let mut w = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        if w.len() > 10_000 {
            w.retain(|_, (t, _)| now.duration_since(*t).as_secs() < 60);
        }
        let e = w.entry(caller.to_owned()).or_insert((now, 0));
        if now.duration_since(e.0).as_secs() >= 60 {
            *e = (now, 0);
        }
        e.1 += 1;
        if e.1 > limit {
            return Err(Error::new(
                Code::Scheduling,
                format!("more than {limit} project log requests a minute: retry shortly"),
            ));
        }
        Ok(())
    }
}

/// How far ahead of the control plane's clock a witness may be dated.
const WITNESS_SKEW_SECS: u64 = 300;

fn witness_err(m: impl Into<String>) -> Error {
    Error::new(Code::GovernanceCheckpointWitness, m)
}

/// The checkpoint, its witnesses and the label, as every member sees them.
fn checkpoint_view(
    c: &mut impl postgres::GenericClient,
    project: &str,
    cp: &SignedProjectCheckpoint,
) -> Result<Value> {
    let (state, witnesses) = govlog::witness_state(c, project, &cp.body)?;
    Ok(json!({
        "checkpoint": cp,
        "witnesses": witnesses,
        "witness_status": state.label(),
        "members": state.required,
        "witnessed_by": state.witnessed_by,
        "missing_witnesses": state.missing,
    }))
}

/// What both routes answer before the project has a checkpoint (they add
/// the organizations' latest signed revocation heads).
fn no_checkpoint(id: &str) -> Value {
    json!({"project": id, "checkpoint": null, "witnesses": [], "witness_status": "unwitnessed",
           "members": [], "witnessed_by": [], "missing_witnesses": [],
           "events": [], "next": null, "consistency": null})
}

impl Control {
    /// A governed project's log: the events after position `after` (at
    /// most `limit`, never more than [`MAX_PAGE`]) of the latest signed
    /// checkpoint, each with its inclusion proof in that checkpoint's
    /// tree, and the checkpoint with its witnesses. Members and auditors
    /// of the project read it ([`project_reader`]); anyone else gets 404.
    pub fn project_audit_log(&self, ctx: &Ctx, id: &str, after: u64, limit: i64) -> Result<Value> {
        let mut c = self.db.conn()?;
        project_reader(&mut *c, &ctx.principal, id)?;
        self.project_log_limit.hit(&ctx.principal.id)?;
        let partition = Partition::Project(id.to_owned()).to_string();
        let limit = limit.clamp(1, MAX_PAGE);
        let heads = super::revocation_heads::latest_heads(&mut *c, id)?;
        let Some(cp) = govlog::latest_checkpoint(&mut *c, &partition)? else {
            let mut out = no_checkpoint(id);
            out["revocation_heads"] = json!(heads);
            return Ok(out);
        };
        let size = cp.body.size;
        let page = govlog::leaves(&mut *c, &self.node_cache, &partition, after, size, limit)?;
        let next = page
            .last()
            .map(|(e, _, _)| e.pseq)
            .filter(|last| *last < size);
        let events: Vec<Value> = page
            .iter()
            .map(
                |(e, leaf, proof)| json!({"event": e, "leaf_hash": leaf, "inclusion_proof": proof}),
            )
            .collect();
        let mut out = checkpoint_view(&mut *c, id, &cp)?;
        out["project"] = json!(id);
        out["events"] = json!(events);
        out["next"] = json!(next);
        out["revocation_heads"] = json!(heads);
        Ok(out)
    }

    /// The project's latest signed checkpoint with its witnesses and, when
    /// the caller names the size it last saw (`since`), the control
    /// plane's signed consistency proof from that size to this one.
    pub fn project_checkpoint_latest(
        &self,
        ctx: &Ctx,
        id: &str,
        since: Option<u64>,
    ) -> Result<Value> {
        let mut c = self.db.conn()?;
        project_reader(&mut *c, &ctx.principal, id)?;
        self.project_log_limit.hit(&ctx.principal.id)?;
        let partition = Partition::Project(id.to_owned()).to_string();
        let heads = super::revocation_heads::latest_heads(&mut *c, id)?;
        let Some(cp) = govlog::latest_checkpoint(&mut *c, &partition)? else {
            let mut out = no_checkpoint(id);
            out["revocation_heads"] = json!(heads);
            return Ok(out);
        };
        let mut out = checkpoint_view(&mut *c, id, &cp)?;
        out["project"] = json!(id);
        out["revocation_heads"] = json!(heads);
        out["consistency"] = match since {
            None => Value::Null,
            // The caller saw more than the control plane now has: no proof
            // goes from a larger tree to a smaller one. The checkpoint
            // is the answer; the caller decides what it means (a rollback,
            // if it is signed later than the one it holds).
            Some(first) if first > cp.body.size => Value::Null,
            Some(first) => {
                let proof: ConsistencyProof =
                    govlog::prove_consistency(&mut *c, &partition, first, cp.body.size)?;
                json!(proof.sign(&self.signer)?)
            }
        };
        Ok(out)
    }

    /// A member organization's countersignature of the checkpoint of the
    /// project at `size`: by a person who is a security admin of the
    /// organization (never a service account or an auditor), signed by the
    /// organization's active governance key, for an organization that was
    /// a member when the log had `size` events, and for exactly the stored
    /// checkpoint's size and root (ENC2718 otherwise). Repeating an
    /// accepted witness answers with the stored one.
    pub fn submit_checkpoint_witness(
        &self,
        ctx: &Ctx,
        id: &str,
        size: u64,
        w: SignedCheckpointWitness,
    ) -> Result<(bool, Value)> {
        self.db.tx(|t| {
            let p = crate::authz::project_row(t, id)?.ok_or_else(|| not_found("project", id))?;
            // Those who take part are told what is wrong; a former member
            // reaches only the witness route, for sizes at which it was a
            // member (below), and learns nothing else.
            let visible = p.members.iter().chain(&p.auditors).any(|o| ctx.principal.member_of(o));
            let org = w.body.organization.clone();
            if visible {
                if !p.governed() {
                    return Err(conflict(format!(
                        "project {id} is a standard project: checkpoints belong to governed projects"
                    )));
                }
                deny_auditor(&ctx.principal, &p)?;
            }
            require_human(
                &ctx.principal,
                &org,
                &[Role::SecurityAdmin],
                "witnessing a project checkpoint",
            )?;
            if !p.governed() {
                return Err(not_found("project", id));
            }
            let partition = Partition::Project(id.to_owned()).to_string();
            let cp = govlog::checkpoint_at(t, &partition, size)?;
            let member_then = match &cp {
                Some(_) => govlog::members_at(t, id, size)?.contains(&org),
                None => false,
            };
            if !visible && !member_then {
                return Err(not_found("project", id));
            }
            let cp = cp.ok_or_else(|| not_found("checkpoint", &format!("{id} at size {size}")))?;
            if !member_then {
                return Err(forbidden(format!(
                    "{org} was not a member of project {id} when its log had {size} events"
                )));
            }
            if !w.body.witnesses(&cp.body) {
                return Err(witness_err(format!(
                    "the witness is not of the control plane's checkpoint of {partition} at size {size} with root {}",
                    cp.body.root
                )));
            }
            if w.body.at > now() + WITNESS_SKEW_SECS {
                return Err(bad("a witness is not dated in the future"));
            }
            super::governance::under_active_key(t, &org, &w.public_key, |k| w.verify(k))?;
            let n = t
                .execute(
                    "INSERT INTO checkpoint_witnesses (partition, size, organization_id, signed)
                     VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                    &[
                        &partition,
                        &(size as i64),
                        &org,
                        &serde_json::to_value(&w).map_err(db_err)?,
                    ],
                )
                .map_err(db_err)?;
            if n == 1 {
                audit::append(
                    t,
                    ctx.draft("checkpoint.witnessed", "project", id, Outcome::Succeeded)
                        .org(&org)
                        .project(id)
                        .r#ref("size", size.to_string())
                        .r#ref("root", cp.body.root.clone()),
                )?;
            }
            let mut out = checkpoint_view(t, id, &cp)?;
            out["project"] = json!(id);
            out["organization"] = json!(org);
            Ok((n == 1, out))
        })
    }
}
