//! The control plane service: coordinates, never computes on or holds
//! protected data, and is not a cryptographic trust anchor. Trust results
//! are rebuilt from signed evidence and trusted keys.

use std::path::Path;
use std::time::Duration;

use postgres::GenericClient;

use encompute_ir::{Code, Error, Result};
use encompute_privacy::{Checkpoint, Entry, Genesis, LedgerView};
use encompute_verification::ServiceSigner;

use crate::anchor::{open_store, Anchor, AnchorStore};
use crate::audit::{self, AuditDraft, Outcome};
use crate::authn::{Authenticator, Principal};
use crate::config::{AnchorConfig, Config, Env, MetricsAccess};
use crate::db::{db_err, Db};
use crate::log::LogLine;
use crate::metrics::Metrics;
use crate::transport::{HttpTransport, MessageTransport};

/// The context of one API call.
pub struct Ctx {
    pub principal: Principal,
    pub request_id: String,
}

impl Ctx {
    pub fn actor(&self) -> &str {
        &self.principal.id
    }

    pub fn draft(
        &self,
        action: &'static str,
        resource_type: &'static str,
        resource_id: &str,
        result: Outcome,
    ) -> AuditDraft {
        AuditDraft::new(
            &self.principal.id,
            &self.request_id,
            action,
            resource_type,
            resource_id,
            result,
        )
    }
}

pub struct Control {
    pub env: Env,
    pub service_id: String,
    pub db: Db,
    pub auth: Authenticator,
    pub signer: ServiceSigner,
    pub anchor: Anchor,
    pub metrics: Metrics,
    pub transport: Box<dyn MessageTransport>,
    pub audit_every: u64,
    /// Who may read `/metrics`.
    pub metrics_access: MetricsAccess,
    /// Ledgers this process created whose creation committed but whose
    /// anchoring failed (an anchor-store outage): the checkpoint the call
    /// itself computed, anchored again by the background tick. The memory is
    /// the process's own, which a database writer cannot touch; a crash
    /// loses it, and the operator then anchors the ledger deliberately
    /// (`anchor_unanchored`).
    pub pending_genesis: std::sync::Mutex<std::collections::BTreeMap<String, Checkpoint>>,
    /// Set when [`Control::enforce`] found the database undoing a
    /// transition the anchor holds: the first alarm's message. While set,
    /// every request (but `/live`, `/metrics`, `/v1/info`) is refused
    /// (ENC2202) and `/ready` answers 503. Cleared only by a restart (whose
    /// start-up check refuses a database that still undoes the anchor).
    pub latch: std::sync::Mutex<Option<String>>,
    /// Negatives a call found undone in its own commit-to-anchor window and
    /// refused (never acknowledged): tolerated by [`Control::enforce`] until
    /// the retry commits them again. Process memory.
    pub refused_negatives: std::sync::Mutex<std::collections::BTreeSet<String>>,
    /// When [`Control::enforce`] last ran, and what it cost.
    enforced: std::sync::Mutex<(Option<std::time::Instant>, Duration)>,
}

pub fn rollback(what: &str, detail: impl std::fmt::Display) -> Error {
    Error::new(
        Code::PrivacyLedger,
        format!("{what} STATE ROLLBACK: {detail}. STARTUP REFUSED: restore the missing entries, or run `encompute-control recover` (see docs/deployment.md)"),
    )
}

/// A rollback found while the service runs: the operation is refused (and
/// nothing is anchored).
pub fn runtime_rollback(what: &str, detail: impl std::fmt::Display) -> Error {
    Error::new(
        Code::PrivacyLedger,
        format!("{what} STATE ROLLBACK: {detail}. REFUSED: the database no longer extends the state anchor; stop the service, then restore the missing entries or run `encompute-control recover` (see docs/deployment.md)"),
    )
}

/// The error every request gets once the control plane is latched.
pub fn latched(first: &str) -> Error {
    Error::new(
        Code::PrivacyLedger,
        format!("CONTROL PLANE LATCHED after a STATE ROLLBACK was found while running: {first}. Every request is refused until the database is restored (or `encompute-control recover` is run) and the service restarted"),
    )
}

/// The security-negative transitions one call committed (see
/// [`Control::anchor_negatives`]): the IDs its own transaction wrote.
#[derive(Debug, Default, Clone)]
pub struct Negatives {
    pub revoked: Vec<String>,
    pub disabled_services: Vec<String>,
    pub disabled_users: Vec<String>,
    pub ended_jobs: Vec<String>,
    pub withdrawn_grants: Vec<String>,
    pub removed_memberships: Vec<String>,
    pub removed_roles: Vec<String>,
}

impl Negatives {
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
            && self.disabled_services.is_empty()
            && self.disabled_users.is_empty()
            && self.ended_jobs.is_empty()
            && self.withdrawn_grants.is_empty()
            && self.removed_memberships.is_empty()
            && self.removed_roles.is_empty()
    }
}

/// The control plane's signing key: from the configured secret file; in
/// development, created next to a directory anchor on first start.
pub fn load_signer(cfg: &Config) -> Result<ServiceSigner> {
    if let Some(f) = &cfg.signing_key_file {
        return ServiceSigner::from_file(&cfg.service_id, f);
    }
    if cfg.env.is_production() {
        return Err(Error::new(
            Code::InsecureConfiguration,
            "production mode needs ENCOMPUTE_SIGNING_KEY_FILE",
        ));
    }
    let AnchorConfig::Dir(d) = &cfg.anchor else {
        return Err(Error::new(
            Code::InsecureConfiguration,
            "set ENCOMPUTE_SIGNING_KEY_FILE",
        ));
    };
    let p = d.join("development-signing.key");
    if !p.exists() {
        std::fs::create_dir_all(d)
            .map_err(|e| Error::new(Code::Artifact, format!("{}: {e}", d.display())))?;
        let s = ServiceSigner::generate(&cfg.service_id)?;
        write_secret(
            &p,
            encompute_verification::hex(s.seed().as_ref()).as_bytes(),
        )?;
    }
    ServiceSigner::from_file(&cfg.service_id, &p)
}

fn write_secret(p: &Path, b: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(p)
        .and_then(|mut f| f.write_all(b))
        .map_err(|e| Error::new(Code::Artifact, format!("{}: {e}", p.display())))
}

impl Control {
    /// Connects, migrates, opens the anchor and refuses to start on any
    /// rollback of privacy or audit state.
    pub fn start(cfg: &Config) -> Result<Self> {
        let db = Db::connect(&cfg.database_url)?;
        db.migrate()?;
        let signer = load_signer(cfg)?;
        let store = open_store(&cfg.anchor)?;
        let mut c = Self::with_parts(
            cfg.env,
            &cfg.service_id,
            db,
            Authenticator::new(
                cfg.env,
                &cfg.service_id,
                cfg.oidc.clone(),
                cfg.dev_token_secret.clone(),
            )
            .with_max_token_lifetime(cfg.max_token_lifetime_secs),
            signer,
            store,
            None,
            cfg.audit_checkpoint_every,
        )?;
        c.metrics_access = cfg.metrics.clone();
        Ok(c)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_parts(
        env: Env,
        service_id: &str,
        db: Db,
        auth: Authenticator,
        signer: ServiceSigner,
        store: Box<dyn AnchorStore>,
        transport: Option<Box<dyn MessageTransport>>,
        audit_every: u64,
    ) -> Result<Self> {
        let (anchor, existed) = Anchor::open(store, &signer)?;
        let transport = transport.unwrap_or_else(|| {
            Box::new(HttpTransport::new(
                ServiceSigner::from_seed(signer.id(), &signer.seed()).expect("valid ID"),
            ))
        });
        let c = Self {
            env,
            service_id: service_id.into(),
            db,
            auth,
            signer,
            anchor,
            metrics: Metrics::default(),
            transport,
            audit_every: audit_every.max(1),
            metrics_access: MetricsAccess::default_for(env),
            pending_genesis: Default::default(),
            latch: Default::default(),
            refused_negatives: Default::default(),
            enforced: std::sync::Mutex::new((None, Duration::ZERO)),
        };
        c.ensure_self_registered()?;
        c.verify_state(existed)?;
        if !existed {
            // A fresh deployment: write the initial anchor now, so any later
            // start compares against it.
            c.anchor.update(&c.signer, |_| {})?;
        }
        c.note_anchor_size();
        c.alarm_unanchored_ledgers("startup");
        crate::anchor::warn_if_large(&c.service_id, "startup", c.anchor.bytes());
        c.warn_legacy_service_admins()?;
        LogLine::new(&c.service_id, "started")
            .field("anchor", c.anchor.describe())
            .field("env", format!("{:?}", c.env))
            .emit();
        Ok(c)
    }

    /// Sets the `encompute_anchor_bytes` gauge to the anchor's serialized
    /// size as last loaded or written (every write measures it).
    pub fn note_anchor_size(&self) {
        self.metrics.set(
            "encompute_anchor_bytes",
            "all",
            i64::try_from(self.anchor.bytes()).unwrap_or(i64::MAX),
        );
    }

    /// The `/metrics` exposition, with the gauges read at scrape time.
    pub fn render_metrics(&self) -> String {
        self.note_anchor_size();
        self.metrics.render()
    }

    /// Service accounts that still hold security_admin (granted before the
    /// role was refused to services) are accepted in 0.3.x, loudly: a
    /// warning log line naming them, one audit event per affected
    /// organization per start (only when there are any) and the
    /// `encompute_legacy_service_admins` gauge. They never count as a
    /// policy's second pair of eyes. Refused from 0.4.0.
    pub fn warn_legacy_service_admins(&self) -> Result<Vec<serde_json::Value>> {
        let accounts = {
            let mut c = self.db.conn()?;
            crate::ops::legacy_service_admins(&mut *c, None)?
        };
        self.metrics.set(
            "encompute_legacy_service_admins",
            "all",
            accounts.len() as i64,
        );
        if accounts.is_empty() {
            return Ok(accounts);
        }
        let label = |a: &serde_json::Value| {
            format!(
                "{}/{}",
                a["organization"].as_str().unwrap_or(""),
                a["id"].as_str().unwrap_or("")
            )
        };
        LogLine::new(&self.service_id, "legacy_service_admins")
            .field("count", accounts.len())
            .field(
                "service_accounts",
                accounts.iter().map(label).collect::<Vec<_>>().join(","),
            )
            .field(
                "action",
                format!(
                    "remove security_admin from these service accounts (POST /v1/organizations/{{organization}}/memberships/remove {{\"principal\": ID, \"role\": \"security_admin\"}}): accepted with this warning in 0.3.x, refused from {}",
                    crate::ops::LEGACY_SERVICE_ADMINS_REFUSED_FROM
                ),
            )
            .emit();
        let mut by_org: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for a in &accounts {
            by_org
                .entry(a["organization"].as_str().unwrap_or("").to_owned())
                .or_default()
                .push(a["id"].as_str().unwrap_or("").to_owned());
        }
        self.db.tx(|t| {
            for (org, ids) in &by_org {
                // Audit references are at most 256 bytes: as many IDs as
                // fit (the count is always exact).
                let mut listed = String::new();
                for id in ids {
                    let sep = usize::from(!listed.is_empty());
                    if listed.len() + sep + id.len() > 256 {
                        break;
                    }
                    if sep == 1 {
                        listed.push('+');
                    }
                    listed.push_str(id);
                }
                audit::append(
                    t,
                    AuditDraft::new(
                        &self.service_id,
                        "startup",
                        "security.legacy_service_admins",
                        "organization",
                        org,
                        Outcome::Allowed,
                    )
                    .org(org)
                    .r#ref("count", ids.len().to_string())
                    .r#ref("service_accounts", listed)
                    .r#ref(
                        "refused_from",
                        crate::ops::LEGACY_SERVICE_ADMINS_REFUSED_FROM,
                    ),
                )?;
            }
            Ok(())
        })?;
        Ok(accounts)
    }

    /// Opens for `recover` without refusing on a rollback (that is what
    /// recovery repairs).
    pub fn for_recovery(
        cfg: &Config,
        db: Db,
        signer: ServiceSigner,
        store: Box<dyn AnchorStore>,
    ) -> Result<Self> {
        let (anchor, _) = Anchor::open(store, &signer)?;
        Ok(Self {
            env: cfg.env,
            service_id: cfg.service_id.clone(),
            db,
            auth: Authenticator::new(cfg.env, &cfg.service_id, vec![], None),
            transport: Box::new(HttpTransport::new(
                ServiceSigner::from_seed(signer.id(), &signer.seed()).expect("valid ID"),
            )),
            signer,
            anchor,
            metrics: Metrics::default(),
            audit_every: cfg.audit_checkpoint_every.max(1),
            metrics_access: MetricsAccess::Closed,
            pending_genesis: Default::default(),
            latch: Default::default(),
            refused_negatives: Default::default(),
            enforced: std::sync::Mutex::new((None, Duration::ZERO)),
        })
    }

    /// The control plane's own service account (so its messages and
    /// requests verify like any other service's).
    fn ensure_self_registered(&self) -> Result<()> {
        self.db.tx(|t| {
            let pk = self.signer.public_key_hex();
            let existing = t
                .query_opt(
                    "SELECT public_key FROM service_accounts WHERE id = $1",
                    &[&self.service_id],
                )
                .map_err(db_err)?;
            match existing {
                Some(r) if r.get::<_, String>(0) == pk => Ok(()),
                Some(_) => Err(Error::new(
                    Code::InsecureConfiguration,
                    format!(
                        "service account {} is registered with another key: this is not the same control plane (wrong signing key file?)",
                        self.service_id
                    ),
                )),
                None => {
                    t.execute(
                        "INSERT INTO service_accounts (id, organization_id, kind, public_key, status)
                         VALUES ($1, NULL, 'control', $2, 'active')",
                        &[&self.service_id, &pk],
                    )
                    .map_err(db_err)?;
                    Ok(())
                }
            }
        })
    }

    /// The database must extend the anchor: nothing anchored may be missing,
    /// and no anchored security-negative transition (freeze, revocation,
    /// disable, cancellation, approval withdrawal, membership or role
    /// removal) may be undone.
    pub fn verify_state(&self, anchor_existed: bool) -> Result<()> {
        let a = self.anchor.snapshot();
        let mut c = self.db.conn()?;
        let (seq, _root) = audit::verify_chain(&mut *c)?;
        if !anchor_existed {
            let spent: i64 = c
                .query_one("SELECT count(*) FROM privacy_entries", &[])
                .map_err(db_err)?
                .get(0);
            if seq > 0 || spent > 0 {
                return Err(rollback(
                    "ANCHOR",
                    format!(
                        "the database holds {seq} audit events and {spent} privacy entries but the state anchor ({}) is missing",
                        self.anchor.describe()
                    ),
                ));
            }
            return Ok(());
        }
        if a.audit_seq > seq
            || audit::hash_at(&mut *c, a.audit_seq)?.as_deref() != Some(a.audit_root.as_str())
        {
            return Err(rollback(
                "AUDIT",
                format!(
                    "the anchor recorded audit event {} but the database's chain ends at {seq} or differs",
                    a.audit_seq
                ),
            ));
        }
        for (asset, cp) in &a.ledgers {
            let Some(view) = load_ledger(&mut *c, asset)? else {
                // A frozen ledger whose asset the database does not hold
                // either cannot be spent (asset IDs are never reissued).
                if a.frozen.contains(asset) && revoked_status(&mut *c, asset)?.is_none() {
                    continue;
                }
                return Err(rollback(
                    "PRIVACY",
                    format!("the privacy ledger of {asset} is missing"),
                ));
            };
            view.verify()?;
            view.extends(cp).map_err(|e| {
                rollback(
                    "PRIVACY",
                    format!("the privacy ledger of {asset}: {}", e.message),
                )
            })?;
        }
        // A ledger the anchor froze stays frozen, whatever the database says.
        for asset in &a.frozen {
            let row = c
                .query_opt(
                    "SELECT frozen_reason FROM privacy_ledgers WHERE asset_id = $1",
                    &[asset],
                )
                .map_err(db_err)?;
            if let Some(r) = row {
                if r.get::<_, Option<String>>(0).is_none() {
                    return Err(rollback(
                        "FREEZE",
                        format!("the privacy ledger of {asset} was frozen, but the database shows it spendable"),
                    ));
                }
            }
        }
        check_negatives(&mut c, &a, &|_| false, &rollback)?;
        Ok(())
    }

    /// Explicit recovery after a detected rollback. Ledgers behind the
    /// anchor are **frozen**: treated as exhausted, so spending the
    /// database forgot can never be spent again; ledgers the anchor froze
    /// before are frozen again; a ledger whose row the database lost (its
    /// asset still held) is re-created frozen. A rewound audit chain is recorded as a
    /// gap. Anchored revocations, disables, job cancellations, approval
    /// withdrawals, membership removals and role removals the database
    /// forgot are applied again. All of it is audited, then the
    /// anchor is re-signed.
    pub fn recover(&self, operator: &str) -> Result<Vec<String>> {
        let a = self.anchor.snapshot();
        let mut notes = vec![];
        let mut frozen = vec![];
        {
            let mut c = self.db.conn()?;
            for (asset, cp) in &a.ledgers {
                let behind = match load_ledger(&mut *c, asset)? {
                    None => true,
                    Some(v) => v.extends(cp).is_err(),
                };
                if behind {
                    frozen.push((
                        asset.clone(),
                        cp.clone(),
                        "rolled back behind anchored entry",
                    ));
                }
            }
            for asset in &a.frozen {
                if frozen.iter().any(|(x, _, _)| x == asset) {
                    continue;
                }
                let unfrozen = c
                    .query_opt(
                        "SELECT 1 FROM privacy_ledgers WHERE asset_id = $1 AND frozen_reason IS NULL",
                        &[asset],
                    )
                    .map_err(db_err)?
                    .is_some();
                if unfrozen {
                    let cp =
                        a.ledgers
                            .get(asset)
                            .cloned()
                            .unwrap_or(encompute_privacy::Checkpoint {
                                seq: 0,
                                root: String::new(),
                            });
                    frozen.push((asset.clone(), cp, "frozen in the state anchor at entry"));
                }
            }
        }
        self.db.tx(|t| {
            for (asset, cp, why) in &frozen {
                let reason = format!("{why} {} (root {}); frozen by {operator}", cp.seq, cp.root);
                let updated = t
                    .execute(
                        "UPDATE privacy_ledgers SET frozen_reason = $2 WHERE asset_id = $1",
                        &[asset, &reason],
                    )
                    .map_err(db_err)?;
                // The database lost the ledger's row but still holds the
                // asset: the row is re-created, frozen (see
                // `recreate_frozen_ledger`). Without the asset nothing can
                // spend it (asset IDs are never reissued) and the anchor's
                // freeze holds.
                let recreated =
                    updated == 0 && recreate_frozen_ledger(t, asset, &reason)?.is_some();
                let mut d = AuditDraft::new(
                    operator,
                    "recovery",
                    "privacy.ledger.frozen",
                    "asset",
                    asset,
                    Outcome::Succeeded,
                )
                .r#ref("anchored_seq", cp.seq.to_string())
                .r#ref("anchored_root", cp.root.clone());
                if recreated {
                    d = d.r#ref("ledger", "recreated_missing_row");
                }
                audit::append(t, d)?;
                notes.push(if recreated {
                    format!(
                        "privacy ledger {asset}: missing from the database; re-created frozen (treated as exhausted; its original budget is unknown)"
                    )
                } else {
                    format!("privacy ledger {asset}: frozen (treated as exhausted)")
                });
            }
            let head = t
                .query_one("SELECT seq FROM audit_head WHERE id", &[])
                .map_err(db_err)?
                .get::<_, i64>(0);
            let rewound = a.audit_seq > head
                || audit::hash_at(t, a.audit_seq)?.as_deref() != Some(a.audit_root.as_str());
            if rewound {
                audit::append(
                    t,
                    AuditDraft::new(
                        operator,
                        "recovery",
                        "audit.gap.recorded",
                        "audit",
                        "chain",
                        Outcome::Succeeded,
                    )
                    .r#ref("anchored_seq", a.audit_seq.to_string())
                    .r#ref("anchored_root", a.audit_root.clone()),
                )?;
                notes.push(format!(
                    "audit chain: events after {} were lost; the gap is recorded",
                    head
                ));
            }
            Ok(())
        })?;
        // Revocations the restored database forgot are applied again: the
        // asset is revoked, jobs not yet running fail, the broker is told.
        for asset in &a.revoked {
            self.db.tx(|t| {
                let Some(row) = crate::authz::asset_row(t, asset)? else {
                    return Ok(());
                };
                if row.status != "revoked" {
                    self.revoke_in(
                        t,
                        operator,
                        "recovery",
                        &row,
                        Some("anchored_revocation_reapplied"),
                    )?;
                    notes.push(format!("asset {asset}: revocation re-applied"));
                }
                Ok(())
            })?;
        }
        // Disabled service accounts and users are disabled again.
        for (table, action, rtype, ids) in [
            (
                "service_accounts",
                "service_account.disabled",
                "service_account",
                &a.disabled_services,
            ),
            ("users", "user.disabled", "user", &a.disabled_users),
        ] {
            if ids.is_empty() {
                continue;
            }
            let ids: Vec<&String> = ids.iter().collect();
            self.db.tx(|t| {
                let rows = t
                    .query(
                        &format!(
                            "UPDATE {table} SET status = 'disabled' WHERE id = ANY($1) AND status <> 'disabled'
                             RETURNING id, organization_id"
                        ),
                        &[&ids],
                    )
                    .map_err(db_err)?;
                for r in rows {
                    let (id, org): (String, Option<String>) = (r.get(0), r.get(1));
                    let mut d = AuditDraft::new(operator, "recovery", action, rtype, &id, Outcome::Succeeded)
                        .r#ref("reason", "anchored_disable_reapplied");
                    if let Some(o) = &org {
                        d = d.org(o);
                    }
                    audit::append(t, d)?;
                    notes.push(format!("{rtype} {id}: disable re-applied"));
                }
                Ok(())
            })?;
        }
        // Cancelled and failed jobs end again (never run twice).
        if !a.ended_jobs.is_empty() {
            let ids: Vec<&String> = a.ended_jobs.iter().collect();
            self.db.tx(|t| {
                let rows: Vec<(String, String, String)> = t
                    .query(
                        "SELECT id, state, organization_id FROM jobs
                          WHERE id = ANY($1) AND state NOT IN ('failed', 'cancelled') ORDER BY id FOR UPDATE",
                        &[&ids],
                    )
                    .map_err(db_err)?
                    .iter()
                    .map(|r| (r.get(0), r.get(1), r.get(2)))
                    .collect();
                let why = "cancelled or failed before the database was restored; not run again";
                for (id, state, org) in rows {
                    if crate::model::JobState::parse(&state)?.is_terminal() {
                        // Only a write to the database gets here (succeeded
                        // after it ended): ended wins.
                        t.execute(
                            "UPDATE jobs SET state = 'failed', error = $2, updated_at = now() WHERE id = $1",
                            &[&id, &why],
                        )
                        .map_err(db_err)?;
                    } else {
                        self.transition_in(t, operator, "recovery", &id, crate::model::JobState::Failed, Some(why))?;
                    }
                    audit::append(
                        t,
                        AuditDraft::new(operator, "recovery", "job.failed", "job", &id, Outcome::Failed)
                            .org(&org)
                            .r#ref("reason", "anchored_termination_reapplied"),
                    )?;
                    notes.push(format!("job {id}: termination re-applied"));
                }
                Ok(())
            })?;
        }
        // Withdrawn approvals and ended grants are withdrawn again.
        if !a.withdrawn_grants.is_empty() {
            let ids: Vec<&String> = a.withdrawn_grants.iter().collect();
            self.db.tx(|t| {
                let owners = |t: &mut postgres::Transaction<'_>, sql: &str| -> Result<Vec<(String, String, String)>> {
                    Ok(t.query(sql, &[&ids])
                        .map_err(db_err)?
                        .iter()
                        .map(|r| (r.get(0), r.get(1), r.get(2)))
                        .collect())
                };
                let held = owners(
                    t,
                    "SELECT ap.approval_id, ap.asset_id, a.organization_id FROM asset_approvals ap
                       JOIN assets a ON a.id = ap.asset_id WHERE ap.approval_id = ANY($1)
                     UNION ALL
                     SELECT am.grant_id, am.asset_id, a.organization_id FROM asset_approval_members am
                       JOIN assets a ON a.id = am.asset_id WHERE am.grant_id = ANY($1)
                     ORDER BY 1",
                )?;
                if held.is_empty() {
                    return Ok(());
                }
                crate::ops::withdraw_grants(t, operator, "approval_id = ANY($1)", "grant_id = ANY($1)", &[&ids])?;
                for (id, asset, org) in held {
                    audit::append(
                        t,
                        AuditDraft::new(operator, "recovery", "asset.approval_withdrawn", "asset", &asset, Outcome::Succeeded)
                            .org(&org)
                            .r#ref("approval", id.clone())
                            .r#ref("reason", "anchored_withdrawal_reapplied"),
                    )?;
                    notes.push(format!("approval {id} of asset {asset}: withdrawal re-applied"));
                }
                Ok(())
            })?;
        }
        // Removed project memberships are removed again. (The grants and
        // jobs the removal ended are anchored on their own, above.)
        if !a.removed_memberships.is_empty() {
            let ids: Vec<&String> = a.removed_memberships.iter().collect();
            self.db.tx(|t| {
                let held: Vec<(String, String, String, String)> = t
                    .query(
                        "DELETE FROM project_members m USING projects p
                          WHERE p.id = m.project_id AND m.membership_id = ANY($1)
                         RETURNING m.membership_id, m.project_id, m.organization_id, p.organization_id",
                        &[&ids],
                    )
                    .map_err(db_err)?
                    .iter()
                    .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
                    .collect();
                for (id, project, member, owner) in held {
                    t.execute(
                        "INSERT INTO removed_memberships (id, project_id, organization_id, removed_by)
                         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                        &[&id, &project, &member, &operator],
                    )
                    .map_err(db_err)?;
                    audit::append(
                        t,
                        AuditDraft::new(operator, "recovery", "project.member_removed", "project", &project, Outcome::Succeeded)
                            .org(&owner)
                            .project(&project)
                            .r#ref("member", member.clone())
                            .r#ref("membership", id.clone())
                            .r#ref("reason", "anchored_removal_reapplied"),
                    )?;
                    notes.push(format!(
                        "membership {id} ({member} in project {project}): removal re-applied"
                    ));
                }
                Ok(())
            })?;
        }
        // Removed organization roles are removed again.
        if !a.removed_roles.is_empty() {
            let ids: Vec<&String> = a.removed_roles.iter().collect();
            self.db.tx(|t| {
                let held: Vec<(String, String, String, String)> = t
                    .query(
                        "DELETE FROM memberships WHERE membership_id = ANY($1)
                         RETURNING membership_id, principal_id, organization_id, role",
                        &[&ids],
                    )
                    .map_err(db_err)?
                    .iter()
                    .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
                    .collect();
                for (id, principal, org, role) in held {
                    t.execute(
                        "INSERT INTO removed_roles (id, principal_id, organization_id, role, removed_by)
                         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                        &[&id, &principal, &org, &role, &operator],
                    )
                    .map_err(db_err)?;
                    audit::append(
                        t,
                        AuditDraft::new(operator, "recovery", "membership.removed", "principal", &principal, Outcome::Succeeded)
                            .org(&org)
                            .r#ref("roles", role.clone())
                            .r#ref("memberships", id.clone())
                            .r#ref("reason", "anchored_removal_reapplied"),
                    )?;
                    notes.push(format!(
                        "role {id} ({role} of {principal} in {org}): removal re-applied"
                    ));
                }
                Ok(())
            })?;
        }
        let (seq, root, ledgers) = {
            let mut c = self.db.conn()?;
            let (seq, root) = audit::verify_chain(&mut *c)?;
            let mut ledgers = a.ledgers.clone();
            for (asset, _, _) in &frozen {
                if let Some(v) = load_ledger(&mut *c, asset)? {
                    ledgers.insert(asset.clone(), v.checkpoint()?);
                }
            }
            (seq, root, ledgers)
        };
        self.anchor.update(&self.signer, |x| {
            x.audit_seq = seq;
            x.audit_root = root.clone();
            x.ledgers = ledgers.clone();
            for (asset, _, _) in &frozen {
                x.frozen.insert(asset.clone());
            }
        })?;
        self.sync_anchor()?;
        Ok(notes)
    }

    /// The spendable ledgers the state anchor holds no checkpoint for: a
    /// creation whose anchoring failed, or a ledger row a database writer
    /// inserted. Their genesis is not authenticated by anything outside the
    /// database, so [`Control::privacy_spend`] refuses them (ENC2202) until
    /// an operator anchors them ([`Control::anchor_unanchored`]). Ledgers
    /// the anchor froze or the database froze never spend.
    pub fn unanchored_ledgers(&self) -> Result<Vec<String>> {
        let ids: Vec<String> = {
            let mut c = self.db.conn()?;
            c.query(
                "SELECT asset_id FROM privacy_ledgers WHERE frozen_reason IS NULL ORDER BY asset_id",
                &[],
            )
            .map_err(db_err)?
            .iter()
            .map(|r| r.get(0))
            .collect()
        };
        let pending = self
            .pending_genesis
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        Ok(self.anchor.with_state(|a| {
            ids.into_iter()
                .filter(|id| !a.ledgers.contains_key(id) && !a.frozen.contains(id))
                .filter(|id| !pending.contains(id))
                .collect()
        }))
    }

    /// Sets the `encompute_unanchored_ledgers` gauge and, when there are
    /// any, logs the alarm naming them and the operator's step. Never
    /// refuses to start: the ledgers refuse spends.
    pub fn alarm_unanchored_ledgers(&self, when: &str) {
        let Ok(ids) = self.unanchored_ledgers() else {
            return;
        };
        self.metrics
            .set("encompute_unanchored_ledgers", "all", ids.len() as i64);
        if ids.is_empty() {
            return;
        }
        LogLine::new(&self.service_id, "unanchored_ledgers")
            .field("when", when)
            .field("count", ids.len())
            .field("assets", ids.join(","))
            .field(
                "action",
                "these privacy ledgers refuse every spend (ENC2202): their genesis was never recorded in the state anchor; check each genesis against the data owner's records, then run `encompute-control anchor-ledgers --operator NAME --asset ID` (see docs/deployment.md)",
            )
            .emit();
    }

    /// The deliberate, audited step that makes unanchored ledgers spendable:
    /// anchors each one's checkpoint as the database holds it now. Trusts
    /// the database for these ledgers (the operator vouches for the genesis,
    /// having compared it with the owner's records): each is audited
    /// (`privacy.ledger.genesis_anchored`, with the checkpoint root and
    /// budget) before it is anchored, and each is reported. `assets` names
    /// them; `None` anchors every unanchored ledger. A named ledger that is
    /// not unanchored is refused.
    pub fn anchor_unanchored(
        &self,
        operator: &str,
        assets: Option<&[String]>,
    ) -> Result<Vec<String>> {
        let unanchored = self.unanchored_ledgers()?;
        let targets: Vec<String> = match assets {
            None => unanchored,
            Some(named) => {
                for a in named {
                    if !unanchored.contains(a) {
                        return Err(Error::new(
                            Code::BadInput,
                            format!("{a} is not an unanchored privacy ledger"),
                        ));
                    }
                }
                named.to_vec()
            }
        };
        let mut notes = vec![];
        for asset in targets {
            let view = {
                let mut c = self.db.conn()?;
                load_ledger(&mut *c, &asset)?
            }
            .ok_or_else(|| Error::new(Code::NotFound, format!("privacy ledger of {asset}")))?;
            view.verify()?;
            let cp = view.checkpoint()?;
            let b = &view.genesis.budget;
            let describe = format!(
                "epsilon {} delta {} per {:?}, {} entries, checkpoint root {}",
                b.epsilon,
                b.delta,
                b.unit,
                view.entries.len(),
                cp.root
            );
            self.db.tx(|t| {
                let org: Option<String> = t
                    .query_opt(
                        "SELECT organization_id FROM assets WHERE id = $1",
                        &[&asset],
                    )
                    .map_err(db_err)?
                    .map(|r| r.get(0));
                let mut d = AuditDraft::new(
                    operator,
                    "recovery",
                    "privacy.ledger.genesis_anchored",
                    "asset",
                    &asset,
                    Outcome::Succeeded,
                )
                .r#ref("checkpoint_seq", cp.seq.to_string())
                .r#ref("checkpoint_root", cp.root.clone())
                .r#ref("epsilon", b.epsilon.to_string())
                .r#ref("delta", b.delta.to_string());
                if let Some(o) = &org {
                    d = d.org(o);
                }
                audit::append(t, d).map(|_| ())
            })?;
            self.anchor.try_update(&self.signer, |a| {
                if a.ledgers.contains_key(&asset) {
                    return Ok(false);
                }
                a.ledgers.insert(asset.clone(), cp.clone());
                Ok(true)
            })?;
            self.pending_genesis
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&asset);
            LogLine::new(&self.service_id, "ledger_genesis_anchored")
                .field("operator", operator)
                .field("asset", &asset)
                .field("ledger", &describe)
                .emit();
            notes.push(format!("privacy ledger {asset}: anchored ({describe})"));
        }
        self.alarm_unanchored_ledgers("anchor-ledgers");
        Ok(notes)
    }

    /// Anchors again the creations whose anchoring failed (an outage) and
    /// that this process still remembers: what was committed, verified
    /// against the database as in [`Control::anchor_committed`].
    pub fn anchor_pending_genesis(&self) -> Result<()> {
        let pending: Vec<(String, Checkpoint)> = self
            .pending_genesis
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (asset, cp) in pending {
            let held = self.anchor.with_state(|a| a.ledgers.contains_key(&asset));
            if !held {
                // A failed store keeps it pending; a refusal (the database
                // no longer holds what was committed) anchors the committed
                // genesis and raises the alarm, as at creation.
                match self.anchor_committed(&asset, &cp, true) {
                    Ok(()) => {}
                    Err(e) if e.code == Code::PrivacyLedger => {}
                    Err(e) => return Err(e),
                }
            }
            if self.anchor.with_state(|a| a.ledgers.contains_key(&asset)) {
                self.pending_genesis
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&asset);
            }
        }
        Ok(())
    }

    /// Anchors the privacy ledger of `asset` as the database now holds it.
    /// Under the anchor's lock, the ledger must extend the anchored
    /// checkpoint: one that does not (rolled back, reset or rewritten while
    /// the service runs) is refused and never anchored, so the anchor only
    /// moves forward along the same chain.
    ///
    /// This follows the database head and so cannot tell that an entry a
    /// call committed was erased since: a call that acknowledges anything
    /// anchors with [`Control::anchor_committed`] instead.
    pub fn anchor_ledger(&self, asset: &str) -> Result<()> {
        self.anchor
            .try_update(&self.signer, |a| {
                let view = {
                    let mut c = self.db.conn()?;
                    load_ledger(&mut *c, asset)?
                }
                .ok_or_else(|| {
                    runtime_rollback(
                        "PRIVACY",
                        format!("the privacy ledger of {asset} is missing"),
                    )
                })?;
                view.verify()?;
                let cp = view.checkpoint()?;
                if let Some(anchored) = a.ledgers.get(asset) {
                    view.extends(anchored).map_err(|e| {
                        self.rollback_alarm("privacy", asset);
                        runtime_rollback(
                            "PRIVACY",
                            format!("the privacy ledger of {asset}: {}", e.message),
                        )
                    })?;
                    if anchored.seq >= cp.seq {
                        return Ok(false);
                    }
                }
                a.ledgers.insert(asset.to_owned(), cp);
                Ok(true)
            })
            .map(|_| ())
    }

    /// Anchors what a call just committed, and fails unless the database
    /// still holds exactly that. `committed` is the checkpoint the call
    /// computed inside its own transaction (the entry it appended, the
    /// entry a duplicate answer returns, or the genesis of a new ledger).
    ///
    /// Under the anchor's lock the ledger is read again: it must extend
    /// `committed` (the hash at that position is the committed one) and the
    /// anchored checkpoint. One that does not was changed between the commit
    /// and now (an entry erased, a genesis rewritten): the rollback alarm is
    /// raised and the call is refused, so the caller never acknowledges
    /// state the ledger no longer holds. What is recorded is `committed`,
    /// never whatever the database shows now, so a change after this write is
    /// refused at the next spend and at start-up.
    ///
    /// A refused `creation` whose ledger row exists but differs still anchors
    /// the genesis the call committed (when nothing is anchored yet), so the
    /// rewritten ledger the attacker left behind can never be spent on.
    pub fn anchor_committed(
        &self,
        asset: &str,
        committed: &Checkpoint,
        creation: bool,
    ) -> Result<()> {
        let mut refused = None;
        self.anchor.try_update(&self.signer, |a| {
            refused = None;
            let view = {
                let mut c = self.db.conn()?;
                load_ledger(&mut *c, asset)?
            }
            .ok_or_else(|| {
                runtime_rollback(
                    "PRIVACY",
                    format!("the privacy ledger of {asset} is missing"),
                )
            })?;
            view.verify()
                .inspect_err(|_| self.rollback_alarm("privacy", asset))?;
            if let Err(e) = view.extends(committed) {
                self.rollback_alarm("privacy", asset);
                refused = Some(runtime_rollback(
                    "PRIVACY",
                    format!(
                        "the privacy ledger of {asset} no longer holds what was committed: {}",
                        e.message
                    ),
                ));
                if creation && !a.ledgers.contains_key(asset) {
                    a.ledgers.insert(asset.to_owned(), committed.clone());
                    return Ok(true);
                }
                return Ok(false);
            }
            if let Some(anchored) = a.ledgers.get(asset) {
                view.extends(anchored).map_err(|e| {
                    self.rollback_alarm("privacy", asset);
                    runtime_rollback(
                        "PRIVACY",
                        format!("the privacy ledger of {asset}: {}", e.message),
                    )
                })?;
                if anchored.seq >= committed.seq {
                    return Ok(false);
                }
            }
            a.ledgers.insert(asset.to_owned(), committed.clone());
            Ok(true)
        })?;
        refused.map_or(Ok(()), Err)
    }

    /// Anchors the security-negative transitions a call just committed, and
    /// fails unless the database still holds them. `n` is what the call
    /// itself wrote in its own transaction (the asset it revoked, the
    /// account it disabled, the jobs it failed, the grants it withdrew, the
    /// memberships and roles it removed), never a re-read of whatever the
    /// database shows now: a database writer who undoes the transition
    /// between the commit and this call would otherwise leave nothing to
    /// anchor and the call acknowledged.
    ///
    /// The anchor records `n` first (it only ever adds), so a restart refuses
    /// a database that undoes it. Then the database is checked as at
    /// start-up, restricted to `n`: one that undoes it raises the rollback
    /// alarm and the call is refused (ENC2202), so the caller never
    /// acknowledges a transition the database no longer holds. Retrying is
    /// correct: the transition is committed again.
    pub fn anchor_negatives(&self, n: &Negatives) -> Result<()> {
        if n.is_empty() {
            return Ok(());
        }
        self.anchor.try_update(&self.signer, |a| {
            let mut changed = false;
            for (set, ids) in [
                (&mut a.revoked, &n.revoked),
                (&mut a.disabled_services, &n.disabled_services),
                (&mut a.disabled_users, &n.disabled_users),
                (&mut a.ended_jobs, &n.ended_jobs),
                (&mut a.withdrawn_grants, &n.withdrawn_grants),
                (&mut a.removed_memberships, &n.removed_memberships),
                (&mut a.removed_roles, &n.removed_roles),
            ] {
                for id in ids {
                    changed |= set.insert(id.clone());
                }
            }
            Ok(changed)
        })?;
        let mut probe = crate::anchor::StateAnchor::empty(&self.signer);
        probe.revoked = n.revoked.iter().cloned().collect();
        probe.disabled_services = n.disabled_services.iter().cloned().collect();
        probe.disabled_users = n.disabled_users.iter().cloned().collect();
        probe.ended_jobs = n.ended_jobs.iter().cloned().collect();
        probe.withdrawn_grants = n.withdrawn_grants.iter().cloned().collect();
        probe.removed_memberships = n.removed_memberships.iter().cloned().collect();
        probe.removed_roles = n.removed_roles.iter().cloned().collect();
        let mut c = self.db.conn()?;
        let ids: Vec<&String> = [
            &n.revoked,
            &n.disabled_services,
            &n.disabled_users,
            &n.ended_jobs,
            &n.withdrawn_grants,
            &n.removed_memberships,
            &n.removed_roles,
        ]
        .into_iter()
        .flatten()
        .collect();
        let r = check_negatives(&mut c, &probe, &|_| false, &|what, detail| {
            self.rollback_alarm("security-negative", what);
            runtime_rollback(
                what,
                format!(
                    "{detail}; the call is not acknowledged and the anchor holds the transition"
                ),
            )
        });
        let mut tolerated = self
            .refused_negatives
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match &r {
            // The call was refused and told so: the retry commits the
            // transition again, which the live enforcement waits for.
            Err(_) => tolerated.extend(ids.into_iter().cloned()),
            Ok(()) => {
                for id in ids {
                    tolerated.remove(id);
                }
            }
        }
        r
    }

    /// Continuous enforcement: the database must still extend every
    /// security-negative transition the anchor holds, as at start-up. Run
    /// before every request (so a restored revocation, disable, cancellation,
    /// withdrawal or removal never permits the operation it denied) and by
    /// the background tick. A database that undoes one raises the rollback
    /// alarm and LATCHES the control plane: this and every later request is
    /// refused (ENC2202) and `/ready` answers 503, until the state is
    /// restored (or `recover` is run) and the service restarted.
    ///
    /// The check is one indexed query per transition kind over the anchored
    /// IDs, cheap while the sets are small. Once a check costs more than
    /// 20 ms the next one waits ten times as long (at most 2 s), so
    /// enforcement never takes more than a tenth of the service's time; the
    /// window that leaves is that wait. `force` ignores the wait (the tick).
    pub fn enforce(&self, force: bool) -> Result<()> {
        if let Some(m) = self.latch.lock().unwrap_or_else(|p| p.into_inner()).clone() {
            return Err(latched(&m));
        }
        let (last, cost) = *self.enforced.lock().unwrap_or_else(|p| p.into_inner());
        if !force {
            if let Some(l) = last {
                if cost > Duration::from_millis(20)
                    && l.elapsed() < (cost * 10).min(Duration::from_secs(2))
                {
                    return Ok(());
                }
            }
        }
        let started = std::time::Instant::now();
        let tolerated = self
            .refused_negatives
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let r = self.anchor.with_state(|a| {
            let mut c = self.db.conn()?;
            check_negatives(&mut c, a, &|id| tolerated.contains(id), &runtime_rollback)
        });
        *self.enforced.lock().unwrap_or_else(|p| p.into_inner()) =
            (Some(std::time::Instant::now()), started.elapsed());
        match r {
            Ok(()) => Ok(()),
            Err(e) if e.code == Code::PrivacyLedger => {
                self.rollback_alarm("live-negative", "anchor");
                LogLine::new(&self.service_id, "control_plane_latched")
                    .field("reason", &e.message)
                    .emit();
                let mut l = self.latch.lock().unwrap_or_else(|p| p.into_inner());
                let m = l.get_or_insert_with(|| e.message.clone()).clone();
                Err(latched(&m))
            }
            // A database error is not a rollback: the request fails on its own.
            Err(e) => Err(e),
        }
    }

    /// The latch's message, if the control plane is latched.
    pub fn latched(&self) -> Option<String> {
        self.latch.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Anchors the security-negative state the database holds and the
    /// anchor does not yet: revoked assets, disabled service accounts and
    /// users, cancelled and failed jobs, withdrawn asset approvals, removed
    /// project memberships and organization roles. Only ever adds. Runs after the
    /// operations that make such transitions and in the background (a
    /// crash between a commit and its anchoring is caught up here).
    pub fn sync_anchor(&self) -> Result<()> {
        let (revoked, services, users, jobs, withdrawn, removed, roles) = {
            let mut c = self.db.conn()?;
            let ids = |c: &mut crate::db::Conn, sql: &str| -> Result<Vec<String>> {
                Ok(c.query(sql, &[])
                    .map_err(db_err)?
                    .iter()
                    .map(|r| r.get(0))
                    .collect())
            };
            (
                ids(&mut c, "SELECT id FROM assets WHERE status = 'revoked'")?,
                ids(
                    &mut c,
                    "SELECT id FROM service_accounts WHERE status = 'disabled'",
                )?,
                ids(&mut c, "SELECT id FROM users WHERE status = 'disabled'")?,
                ids(
                    &mut c,
                    "SELECT id FROM jobs WHERE state IN ('failed', 'cancelled')",
                )?,
                ids(&mut c, "SELECT id FROM withdrawn_grants")?,
                ids(&mut c, "SELECT id FROM removed_memberships")?,
                ids(&mut c, "SELECT id FROM removed_roles")?,
            )
        };
        self.anchor
            .try_update(&self.signer, |a| {
                let before = a.revoked.len()
                    + a.disabled_services.len()
                    + a.disabled_users.len()
                    + a.ended_jobs.len()
                    + a.withdrawn_grants.len()
                    + a.removed_memberships.len()
                    + a.removed_roles.len();
                a.revoked.extend(revoked.iter().cloned());
                a.disabled_services.extend(services.iter().cloned());
                a.disabled_users.extend(users.iter().cloned());
                a.ended_jobs.extend(jobs.iter().cloned());
                a.withdrawn_grants.extend(withdrawn.iter().cloned());
                a.removed_memberships.extend(removed.iter().cloned());
                a.removed_roles.extend(roles.iter().cloned());
                Ok(before
                    != a.revoked.len()
                        + a.disabled_services.len()
                        + a.disabled_users.len()
                        + a.ended_jobs.len()
                        + a.withdrawn_grants.len()
                        + a.removed_memberships.len()
                        + a.removed_roles.len())
            })
            .map(|_| ())
    }

    /// Logs and counts a rollback found while the service runs.
    pub fn rollback_alarm(&self, what: &str, resource: &str) {
        self.metrics.inc("encompute_state_rollback_total", what);
        LogLine::new(&self.service_id, "state_rollback_detected")
            .field("state", what)
            .field("resource", resource)
            .emit();
    }

    /// Signs and anchors the audit head, only if the chain extends the
    /// anchored root (the events from the anchored one to the head link
    /// and hash correctly, and the anchored event is still there). Under
    /// the anchor's lock, so two checkpoints never race.
    pub fn checkpoint_audit(&self) -> Result<audit::AuditCheckpoint> {
        let mut out = None;
        self.anchor.try_update(&self.signer, |a| {
            let cp = self
                .db
                .tx(|t| audit::checkpoint_extending(t, &self.signer, a.audit_seq, &a.audit_root))
                .map_err(|e| {
                    if e.code == Code::TrustEvidence {
                        self.rollback_alarm("audit", "chain");
                        runtime_rollback(
                            "AUDIT",
                            format!(
                                "the chain does not extend anchored audit event {}: {}",
                                a.audit_seq, e.message
                            ),
                        )
                    } else {
                        e
                    }
                })?;
            let newer = cp.seq > a.audit_seq;
            if newer {
                a.audit_seq = cp.seq;
                a.audit_root = cp.root.clone();
            }
            out = Some(cp);
            Ok(newer)
        })?;
        out.ok_or_else(|| Error::new(Code::Remote, "no audit checkpoint"))
    }

    /// Checkpoints when enough events accumulated since the last one; a
    /// chain that fell behind the anchor raises an alarm (the checkpoint
    /// refuses it).
    pub fn maybe_checkpoint(&self) {
        let a = self.anchor.snapshot();
        let head = self
            .db
            .conn()
            .and_then(|mut c| {
                c.query_one("SELECT seq FROM audit_head WHERE id", &[])
                    .map_err(db_err)
            })
            .map(|r| r.get::<_, i64>(0));
        if let Ok(h) = head {
            let due = h < a.audit_seq || h.abs_diff(a.audit_seq) >= self.audit_every;
            if due {
                if let Err(e) = self.checkpoint_audit() {
                    LogLine::new(&self.service_id, "audit_checkpoint_failed")
                        .field("error", e.message)
                        .emit();
                }
            }
        }
    }

    /// Records a denial in its own transaction (the denied operation's
    /// transaction rolled back).
    pub fn audit_denied(&self, draft: AuditDraft) {
        let _ = self.db.tx(|t| audit::append(t, draft.clone()).map(|_| ()));
    }

    /// Periodic work: scheduling, message delivery, evaluator health,
    /// nonce cleanup, audit checkpoints. Runs until the process exits.
    pub fn run_background(self: &std::sync::Arc<Self>) {
        let me = self.clone();
        std::thread::spawn(move || loop {
            me.tick();
            std::thread::sleep(Duration::from_secs(2));
        });
    }

    pub fn tick(&self) {
        let report = |what: &str, r: Result<()>| {
            if let Err(e) = r {
                LogLine::new(&self.service_id, "background_error")
                    .field("task", what)
                    .field("error", e.message)
                    .emit();
            }
        };
        report("health", self.expire_evaluators());
        report("schedule", self.schedule_pending());
        report("enforce", self.enforce(true));
        report("anchor", self.anchor_pending_genesis());
        report("anchor", self.sync_anchor());
        report("outbox", self.deliver_outbox());
        report(
            "nonces",
            self.db
                .conn()
                .and_then(|mut c| crate::authn::prune_nonces(&mut *c))
                .map(|_| ()),
        );
        self.maybe_checkpoint();
        self.note_anchor_size();
        if let Ok(ids) = self.unanchored_ledgers() {
            self.metrics
                .set("encompute_unanchored_ledgers", "all", ids.len() as i64);
        }
        if let Ok(mut c) = self.db.conn() {
            if let Ok(r) = c.query_one(
                "SELECT count(*) FROM jobs WHERE state IN ('authorized', 'queued')",
                &[],
            ) {
                self.metrics.set("encompute_queue_depth", "all", r.get(0));
            }
            if let Ok(r) = c.query_one(
                "SELECT count(*) FROM memberships m JOIN service_accounts s ON s.id = m.principal_id
                  WHERE m.role = 'security_admin'",
                &[],
            ) {
                self.metrics
                    .set("encompute_legacy_service_admins", "all", r.get(0));
            }
        }
    }
}

/// Re-creates the `privacy_ledgers` row of `asset`, **frozen**, when the
/// database lost it but still holds the asset (recovery). A frozen ledger
/// never spends, so only its identity must be right: the asset, its
/// organization and its policy's ID are the asset's; the budget, which
/// only the lost genesis recorded, is a placeholder that could not afford
/// any release either (the smallest positive epsilon and delta, per
/// organization), and the freeze reason says so. It has no entries: the
/// anchor is re-pointed to it afterwards, like any ledger recovery froze.
/// `None` when the asset is not held either.
fn recreate_frozen_ledger(
    t: &mut impl GenericClient,
    asset: &str,
    reason: &str,
) -> Result<Option<Genesis>> {
    let Some(r) = t
        .query_opt(
            "SELECT organization_id, policy FROM assets WHERE id = $1",
            &[&asset],
        )
        .map_err(db_err)?
    else {
        return Ok(None);
    };
    let org: String = r.get(0);
    let policy: serde_json::Value = r.get(1);
    let genesis = Genesis {
        version: encompute_privacy::ledger::LEDGER_VERSION,
        asset_id: asset.to_owned(),
        budget: encompute_ir::confidentiality::PrivacyBudget {
            unit: encompute_ir::confidentiality::PrivacyUnit::Organization,
            epsilon: f64::MIN_POSITIVE,
            delta: f64::MIN_POSITIVE,
        },
        privacy_policy_id: encompute_verification::service::sha256_hex(
            &encompute_verification::canonical::canonical_json(&policy)?,
        ),
    };
    let reason = format!(
        "{reason}; the database had lost this ledger: re-created by recovery with its entries and budget unknown (placeholder budget)"
    );
    t.execute(
        "INSERT INTO privacy_ledgers (asset_id, organization_id, genesis, frozen_reason)
         VALUES ($1, $2, $3, $4)",
        &[
            &asset,
            &org,
            &serde_json::to_value(&genesis).map_err(db_err)?,
            &reason,
        ],
    )
    .map_err(db_err)?;
    Ok(Some(genesis))
}

/// Fails with `fail(what, detail)` when the database undoes a security-negative
/// transition `a` records: a revoked asset that is not revoked, a disabled
/// service account or user that is not disabled, a cancelled or failed job
/// that is not ended, a withdrawn approval, a removed project membership or a
/// removed role that the database holds again. Run at start-up over the whole
/// anchor, and by [`Control::anchor_negatives`] over what a call committed.
fn check_negatives(
    c: &mut crate::db::Conn,
    a: &crate::anchor::StateAnchor,
    skip: &dyn Fn(&str) -> bool,
    fail: &dyn Fn(&str, String) -> Error,
) -> Result<()> {
    // The first row of `sql` over `ids` that `skip` does not excuse (absent
    // rows are fine: IDs are never reissued, so an absent one cannot act,
    // run or be used).
    let undone = |c: &mut crate::db::Conn,
                  sql: &str,
                  ids: &std::collections::BTreeSet<String>|
     -> Result<Option<(String, String)>> {
        if ids.is_empty() {
            return Ok(None);
        }
        let ids: Vec<&String> = ids.iter().collect();
        Ok(c.query(sql, &[&ids])
            .map_err(db_err)?
            .iter()
            .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
            .find(|(id, _)| !skip(id)))
    };
    // A revoked asset must still be revoked. Disabled principals stay
    // disabled; cancelled and failed jobs stay ended.
    for (what, sql, ids) in [
        (
            "REVOCATION",
            "SELECT id, status FROM assets WHERE id = ANY($1) AND status <> 'revoked' ORDER BY id",
            &a.revoked,
        ),
        (
            "SERVICE ACCOUNT",
            "SELECT id, status FROM service_accounts WHERE id = ANY($1) AND status <> 'disabled' ORDER BY id",
            &a.disabled_services,
        ),
        (
            "USER",
            "SELECT id, status FROM users WHERE id = ANY($1) AND status <> 'disabled' ORDER BY id",
            &a.disabled_users,
        ),
        (
            "JOB",
            "SELECT id, state FROM jobs WHERE id = ANY($1) AND state NOT IN ('failed', 'cancelled') ORDER BY id",
            &a.ended_jobs,
        ),
    ] {
        if let Some((id, status)) = undone(c, sql, ids)? {
            let detail = match what {
                "REVOCATION" => format!("asset {id} was revoked, but the database shows it {status}"),
                "JOB" => format!("job {id} was cancelled or failed, but the database shows it {status}"),
                _ => format!("{} {id} was disabled, but the database shows it {status}", what.to_lowercase()),
            };
            return Err(fail(what, detail));
        }
    }
    // A withdrawn approval (or ended grant) stays withdrawn: its ID is
    // never reused, so a database holding it again was restored.
    if let Some((id, asset)) = undone(
        c,
        "SELECT approval_id, asset_id FROM asset_approvals WHERE approval_id = ANY($1)
             UNION ALL
             SELECT grant_id, asset_id FROM asset_approval_members WHERE grant_id = ANY($1)
             ORDER BY 1",
        &a.withdrawn_grants,
    )? {
        return Err(fail(
            "APPROVAL",
            format!("approval {id} of asset {asset} was withdrawn, but the database holds it"),
        ));
    }
    // A removed project membership stays removed, likewise: the
    // organization would see the project, submit jobs in it and be
    // covered by approvals given to its members again.
    if let Some((id, who)) = undone(
        c,
        "SELECT membership_id, organization_id || ' in project ' || project_id FROM project_members
              WHERE membership_id = ANY($1) ORDER BY 1",
        &a.removed_memberships,
    )? {
        return Err(fail(
            "MEMBERSHIP",
            format!("membership {id} ({who}) was removed, but the database holds it"),
        ));
    }
    // A removed organization role stays removed, likewise: the
    // principal would act with it again.
    if let Some((id, who)) = undone(
        c,
        "SELECT membership_id, role || ' of ' || principal_id || ' in ' || organization_id FROM memberships
              WHERE membership_id = ANY($1) ORDER BY 1",
        &a.removed_roles,
    )? {
        return Err(fail(
            "ROLE",
            format!("role {id} ({who}) was removed, but the database holds it"),
        ));
    }
    Ok(())
}

/// An asset's status, or `None` if the database does not hold it.
fn revoked_status(c: &mut impl GenericClient, asset: &str) -> Result<Option<String>> {
    Ok(
        c.query_opt("SELECT status FROM assets WHERE id = $1", &[&asset])
            .map_err(db_err)?
            .map(|r| r.get(0)),
    )
}

/// A privacy ledger's view from the database, or `None`.
pub fn load_ledger(c: &mut impl GenericClient, asset: &str) -> Result<Option<LedgerView>> {
    let Some(g) = c
        .query_opt(
            "SELECT genesis FROM privacy_ledgers WHERE asset_id = $1",
            &[&asset],
        )
        .map_err(db_err)?
    else {
        return Ok(None);
    };
    let genesis: Genesis = serde_json::from_value(g.get(0)).map_err(db_err)?;
    let entries: Vec<Entry> = c
        .query(
            "SELECT entry FROM privacy_entries WHERE asset_id = $1 ORDER BY seq",
            &[&asset],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| serde_json::from_value(r.get(0)).map_err(db_err))
        .collect::<Result<_>>()?;
    Ok(Some(LedgerView { genesis, entries }))
}
