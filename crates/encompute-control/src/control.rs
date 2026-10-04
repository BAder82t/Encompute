//! The control plane service: coordinates, never computes on or holds
//! protected data, and is not a cryptographic trust anchor. Trust results
//! are rebuilt from signed evidence and trusted keys.

use std::path::Path;
use std::time::Duration;

use postgres::GenericClient;

use encompute_ir::{Code, Error, Result};
use encompute_privacy::{Entry, Genesis, LedgerView};
use encompute_verification::ServiceSigner;

use crate::anchor::{open_store, Anchor, AnchorStore, Opened};
use crate::audit::{self, AuditDraft, Outcome};
use crate::authn::{Authenticator, Principal};
use crate::config::{AnchorConfig, Config, Env, MetricsAccess};
use crate::db::{db_err, Db};
use crate::govlog;
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
    /// Compiled execution specs of plans, by plan row (release tickets).
    pub plan_specs:
        std::sync::Mutex<std::collections::BTreeMap<String, encompute_verification::ExecutionSpec>>,
    /// The key approver pseudonyms are computed under (derived from the
    /// signing key; never leaves the process).
    pub pseudonyms: crate::views::PseudonymKey,
    /// The governance log mirror's end as written last.
    pub mirror: crate::mirror::TailCache,
    /// Complete subtrees of the governance log's trees read before (they
    /// never change), for the project log routes.
    pub node_cache: crate::govlog::NodeCache,
    /// The project log routes' per-caller limit.
    pub project_log_limit: crate::ops::RateLimit,
    /// Privacy spends per actor and asset a minute (each is an event of
    /// the governance log and its mirror).
    pub spend_limit: crate::ops::RateLimit,
    /// The governance bundle route's per-caller limit.
    pub bundle_limit: crate::ops::RateLimit,
    /// The most events of a project's log one bundle carries.
    pub bundle_max_events: std::sync::atomic::AtomicU64,
    /// Bundles being built now.
    pub bundle_slots: std::sync::atomic::AtomicUsize,
    /// Privacy population and scope allocations per caller a minute.
    pub scope_limit: crate::ops::RateLimit,
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

/// Recovery cannot proceed: the governance log does not hold the anchored
/// head (or does not verify), and recovery cannot re-apply what it does
/// not know.
pub fn recovery_refused(detail: impl std::fmt::Display) -> Error {
    Error::new(
        Code::PrivacyLedger,
        format!("GOVERNANCE LOG STATE ROLLBACK: {detail}. RECOVERY REFUSED: the database's governance log must hold the anchored head before recovery can re-apply what it records; restore the governance log tables from a newer backup, or pass an export holding the missing events (`encompute-control recover --governance-log FILE`, see docs/deployment.md)"),
    )
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
        let (anchor, opened) = Anchor::open(store, &signer)?;
        let pseudonyms = crate::views::PseudonymKey::derive(&signer.seed());
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
            plan_specs: Default::default(),
            pseudonyms,
            mirror: Default::default(),
            node_cache: Default::default(),
            project_log_limit: Default::default(),
            spend_limit: crate::ops::RateLimit::new("privacy spend", crate::ops::SPEND_RATE),
            bundle_limit: crate::ops::RateLimit::new("governance bundle", crate::ops::BUNDLE_RATE),
            bundle_max_events: crate::ops::MAX_BUNDLE_EVENTS.into(),
            bundle_slots: 0.into(),
            scope_limit: crate::ops::RateLimit::new("privacy scope", crate::ops::SCOPE_RATE),
        };
        c.ensure_self_registered()?;
        let existed = match opened {
            Opened::Fresh => false,
            Opened::Existing => true,
            // An anchor of 0.3.0: its sets move into the governance log,
            // once, before anything else (see `migrate_v1_anchor`).
            Opened::V1(v1) => {
                c.migrate_v1_anchor(&v1)?;
                true
            }
        };
        c.verify_state(existed)?;
        if !existed {
            // A fresh deployment: write the initial anchor now, so any later
            // start compares against it.
            c.anchor.update(&c.signer, |_| {})?;
        }
        c.note_anchor_size();
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
        let (anchor, opened) = Anchor::open(store, &signer)?;
        if let Opened::V1(_) = opened {
            return Err(Error::new(
                Code::PrivacyLedger,
                "the state anchor is version 1 (0.3.0): this release migrates it at its first start, which refuses a database that does not extend it; recover with the release that wrote it, then upgrade (see docs/deployment.md)",
            ));
        }
        let pseudonyms = crate::views::PseudonymKey::derive(&signer.seed());
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
            plan_specs: Default::default(),
            pseudonyms,
            mirror: Default::default(),
            node_cache: Default::default(),
            project_log_limit: Default::default(),
            spend_limit: crate::ops::RateLimit::new("privacy spend", crate::ops::SPEND_RATE),
            bundle_limit: crate::ops::RateLimit::new("governance bundle", crate::ops::BUNDLE_RATE),
            bundle_max_events: crate::ops::MAX_BUNDLE_EVENTS.into(),
            bundle_slots: 0.into(),
            scope_limit: crate::ops::RateLimit::new("privacy scope", crate::ops::SCOPE_RATE),
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

    /// The database must extend the anchor: nothing anchored may be
    /// missing, and no security-negative transition the governance log
    /// records (freeze, revocation, disable, cancellation, approval
    /// withdrawal, membership or role removal, authorization revocation,
    /// asset expiry, purpose retirement, governance-key revocation) may be
    /// undone. The log itself must verify and contain the anchored head at
    /// the anchored size, and each partition's latest signed checkpoint
    /// must still be its root.
    pub fn verify_state(&self, anchor_existed: bool) -> Result<()> {
        let a = self.anchor.snapshot();
        let mut c = self.db.conn()?;
        let (seq, _root) = audit::verify_chain(&mut *c)?;
        let glog = govlog::verify_chain(&mut *c);
        if !anchor_existed {
            let spent: i64 = c
                .query_one("SELECT count(*) FROM privacy_entries", &[])
                .map_err(db_err)?
                .get(0);
            // A log that does not verify holds something too.
            let events = glog.as_ref().map_or(1, |(n, _)| *n);
            if seq > 0 || spent > 0 || events > 0 {
                return Err(rollback(
                    "ANCHOR",
                    format!(
                        "the database holds {seq} audit events, {spent} privacy entries and {events} governance events but the state anchor ({}) is missing",
                        self.anchor.describe()
                    ),
                ));
            }
            return Ok(());
        }
        // The governance log first: everything below reads it.
        check_log_extends(&mut *c, &a, glog, &self.signer.public_key_hex(), rollback)?;
        self.check_mirror(a.glog_size, &a.glog_head, a.seal.as_ref()).map_err(|e| {
            rollback(
                "GOVERNANCE LOG",
                format!(
                    "{} (the mirror in the anchor store, {}; `encompute-control recover` rebuilds it from a database that extends the anchor)",
                    e.message,
                    self.anchor.describe()
                ),
            )
        })?;
        // Each ledger's floor is its latest checkpoint event in the log
        // (which the checks above showed extends the anchored head).
        let frozen = govlog::negative_set(&mut *c, govlog::NegSet::FrozenLedgers)?;
        for (asset, cp) in &govlog::ledger_floors(&mut *c)? {
            let Some(view) = load_ledger(&mut *c, asset)? else {
                // A frozen ledger whose asset the database does not hold
                // either cannot be spent (asset IDs are never reissued).
                if frozen.binary_search(asset).is_ok() && revoked_status(&mut *c, asset)?.is_none()
                {
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
        // A row a negative set names must still be there: deleting it
        // undoes the transition as surely as changing it back (a deleted
        // revoked authorization frees its signed document to come back
        // under another row; a deleted disabled service frees its ID).
        // Only recovery's `row.lost` event excuses a loss.
        if let Some((set, id)) = missing_rows(&mut *c)?.into_iter().next() {
            return Err(rollback(
                set.state(),
                format!("{id} is in the governance log, but the database no longer holds it"),
            ));
        }
        if let Some((set, id, shows)) = undone(&mut *c)? {
            return Err(rollback(set.state(), undone_message(set, &id, &shows)));
        }
        // A project's placement tightenings and an evaluator's location
        // evidence are events of the log too.
        if let Some(loss) = crate::ops::placement::placement_losses(&mut *c)?
            .into_iter()
            .next()
        {
            return Err(rollback(loss.state(), loss.message()));
        }
        // The audit chain last: a restore reaches the governed state and the
        // audit chain together (every deny checkpoint anchors both), and the
        // refusal that names what the log says was undone is the more useful
        // one.
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
        Ok(())
    }

    /// Explicit recovery after a detected rollback (see
    /// [`Self::recover_importing`]), with the governance log as the
    /// database holds it.
    pub fn recover(&self, operator: &str) -> Result<Vec<String>> {
        self.recover_importing(operator, None)
    }

    /// Explicit recovery after a detected rollback. First the governance
    /// log: it must contain the anchored head, after appending the events
    /// of `governance_log` (an export, JSON lines) that it lacks; recovery
    /// is refused otherwise, since it cannot re-apply transitions it does
    /// not know. Ledgers behind the anchor are **frozen**: treated as
    /// exhausted, so spending the database forgot can never be spent
    /// again; ledgers frozen before are frozen again; a ledger whose row
    /// the database lost (its asset still held) is re-created frozen. A
    /// rewound audit chain is recorded as a gap. Every transition the log
    /// records and the database forgot is applied again: revocations,
    /// disables, job cancellations, approval withdrawals, membership and
    /// role removals, authorization revocations, asset expiries, purpose
    /// retirements and governance-key revocations (a revocation or expiry
    /// re-applied is recorded at the time of recovery, and its key brokers
    /// are told again; a retirement or key revocation keeps its original
    /// time). Each is recorded in the log (`<kind>.reapplied`, or the
    /// transition's own kind where the usual path re-applies it), rows the
    /// database lost as `row.lost` (their IDs stay blocked). All of it is
    /// audited, then the log is checkpointed and the anchor re-signed.
    pub fn recover_importing(
        &self,
        operator: &str,
        governance_log: Option<&str>,
    ) -> Result<Vec<String>> {
        self.recover_with(operator, governance_log, None)
    }

    /// [`Self::recover_importing`], with the archive a compaction of the
    /// governance log mirror wrote (`recover --archive-dir`): read only if
    /// the restored database ends inside the sealed prefix, and checked
    /// against the anchor's seal.
    pub fn recover_with(
        &self,
        operator: &str,
        governance_log: Option<&str>,
        archive: Option<&Path>,
    ) -> Result<Vec<String>> {
        use govlog::NegSet;
        let a = self.anchor.snapshot();
        let mut notes = vec![];
        if let Some(lines) = governance_log {
            let added = self.db.tx(|t| govlog::import(t, lines)).map_err(|e| {
                recovery_refused(format!("the governance log export: {}", e.message))
            })?;
            if added > 0 {
                notes.push(format!(
                    "governance log: {added} missing events restored from the export"
                ));
            }
        }
        let extends = |me: &Self| -> Result<()> {
            let mut c = me.db.conn()?;
            let glog = govlog::verify_chain(&mut *c);
            check_log_extends(&mut *c, &a, glog, &me.signer.public_key_hex(), |_, d| {
                recovery_refused(d)
            })
        };
        if let Err(behind) = extends(self) {
            // The anchored events from the mirror in the anchor store,
            // exactly up to the anchored head (never an orphaned suffix).
            let added = self.import_from_mirror(&a, archive).map_err(|e| {
                recovery_refused(format!(
                    "{}; the governance log mirror cannot supply the missing events either: {}",
                    behind.message, e.message
                ))
            })?;
            notes.push(format!(
                "governance log: {added} missing events restored from the mirror in the anchor store, up to the anchored head (event {})",
                a.glog_size
            ));
            extends(self)?;
        }
        // A damaged mirror is rebuilt from the database's log, which now
        // extends the anchor.
        if let Err(e) = self.check_mirror(a.glog_size, &a.glog_head, a.seal.as_ref()) {
            let size = {
                let mut c = self.db.conn()?;
                govlog::verify_chain(&mut *c)?.0
            };
            self.rebuild_mirror(size, a.seal.as_ref())?;
            notes.push(format!(
                "governance log mirror: rebuilt from the database ({}); {size} events",
                e.message
            ));
        }
        let set = |s: NegSet| -> Result<Vec<String>> {
            let mut c = self.db.conn()?;
            govlog::negative_set(&mut *c, s)
        };
        let already_frozen = set(NegSet::FrozenLedgers)?;
        let mut frozen = vec![];
        {
            let mut c = self.db.conn()?;
            let floors = govlog::ledger_floors(&mut *c)?;
            for (asset, cp) in &floors {
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
            for asset in &already_frozen {
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
                    let cp = floors
                        .iter()
                        .find(|(x, _)| x == asset)
                        .map(|(_, cp)| cp.clone())
                        .unwrap_or(encompute_privacy::Checkpoint {
                            seq: 0,
                            root: String::new(),
                        });
                    frozen.push((
                        asset.clone(),
                        cp,
                        "frozen after a detected rollback at entry",
                    ));
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
                // spend it (asset IDs are never reissued) and the log's
                // freeze holds.
                let recreated =
                    updated == 0 && recreate_frozen_ledger(t, asset, &reason)?.is_some();
                if already_frozen.binary_search(asset).is_err() {
                    let seq = cp.seq.to_string();
                    govlog::append_routed(
                        t,
                        NegSet::FrozenLedgers,
                        govlog::extra_kind::LEDGER_FROZEN,
                        asset,
                        &[("anchored_seq", &seq)],
                    )?;
                }
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
        for asset in &set(NegSet::RevokedAssets)? {
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
        for (table, action, rtype, which) in [
            (
                "service_accounts",
                "service_account.disabled",
                "service_account",
                NegSet::DisabledServices,
            ),
            ("users", "user.disabled", "user", NegSet::DisabledUsers),
        ] {
            let ids = set(which)?;
            if ids.is_empty() {
                continue;
            }
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
                    govlog::append_reapplied(t, which, &id, &[])?;
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
        let ended = set(NegSet::EndedJobs)?;
        if !ended.is_empty() {
            self.db.tx(|t| {
                let rows: Vec<(String, String, String)> = t
                    .query(
                        "SELECT id, state, organization_id FROM jobs
                          WHERE id = ANY($1) AND state NOT IN ('failed', 'cancelled') ORDER BY id FOR UPDATE",
                        &[&ended],
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
                        let project: String = t
                            .query_one("SELECT project_id FROM jobs WHERE id = $1", &[&id])
                            .map_err(db_err)?
                            .get(0);
                        govlog::append_reapplied(t, NegSet::EndedJobs, &id, &[("project", &project)])?;
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
        let withdrawn = set(NegSet::WithdrawnGrants)?;
        if !withdrawn.is_empty() {
            let ids = &withdrawn;
            self.db.tx(|t| {
                let owners = |t: &mut postgres::Transaction<'_>, sql: &str| -> Result<Vec<(String, String, String)>> {
                    Ok(t.query(sql, &[ids])
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
                crate::ops::withdraw_grants(t, operator, "approval_id = ANY($1)", "grant_id = ANY($1)", &[ids])?;
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
        // jobs the removal ended are in the log on their own, above.)
        let removed = set(NegSet::RemovedMemberships)?;
        if !removed.is_empty() {
            self.db.tx(|t| {
                let held: Vec<(String, String, String, String)> = t
                    .query(
                        "DELETE FROM project_members m USING projects p
                          WHERE p.id = m.project_id AND m.membership_id = ANY($1)
                         RETURNING m.membership_id, m.project_id, m.organization_id, p.organization_id",
                        &[&removed],
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
                    govlog::append_reapplied(t, NegSet::RemovedMemberships, &id, &[("project", &project)])?;
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
        let roles = set(NegSet::RemovedRoles)?;
        if !roles.is_empty() {
            self.db.tx(|t| {
                let held: Vec<(String, String, String, String)> = t
                    .query(
                        "DELETE FROM memberships WHERE membership_id = ANY($1)
                         RETURNING membership_id, principal_id, organization_id, role",
                        &[&roles],
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
                    govlog::append_reapplied(t, NegSet::RemovedRoles, &id, &[("role", &role)])?;
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
        // Revoked owner authorizations are revoked again, and their
        // brokers told again (idempotent there).
        let authorizations = set(NegSet::RevokedAuthorizations)?;
        if !authorizations.is_empty() {
            self.db.tx(|t| {
                let held: Vec<(String, String, String)> = t
                    .query(
                        "SELECT id, organization_id, project_id FROM authorizations
                          WHERE (id = ANY($1) OR authorization_id = ANY($1)) AND status <> 'revoked'
                          ORDER BY id FOR UPDATE",
                        &[&authorizations],
                    )
                    .map_err(db_err)?
                    .iter()
                    .map(|r| (r.get(0), r.get(1), r.get(2)))
                    .collect();
                let at = i64::try_from(encompute_verification::service::now()).unwrap_or(i64::MAX);
                for (id, org, project) in held {
                    t.execute(
                        "UPDATE authorizations SET status = 'revoked', revoked_by = $2,
                                revoked_at = to_timestamp($3::bigint) WHERE id = $1",
                        &[&id, &operator, &at],
                    )
                    .map_err(db_err)?;
                    let authorization_id: Option<String> = t
                        .query_one(
                            "SELECT authorization_id FROM authorizations WHERE id = $1",
                            &[&id],
                        )
                        .map_err(db_err)?
                        .get(0);
                    let mut refs = vec![("project", project.as_str())];
                    if let Some(a) = &authorization_id {
                        refs.push(("authorization_id", a.as_str()));
                    }
                    govlog::append_reapplied(t, NegSet::RevokedAuthorizations, &id, &refs)?;
                    audit::append(
                        t,
                        AuditDraft::new(
                            operator,
                            "recovery",
                            "authorization.revoked",
                            "authorization",
                            &id,
                            Outcome::Succeeded,
                        )
                        .org(&org)
                        .project(&project)
                        .r#ref("reason", "anchored_revocation_reapplied"),
                    )?;
                    self.queue_authorization_revoked(t, operator, "recovery", &id)?;
                    notes.push(format!("authorization {id}: revocation re-applied"));
                }
                Ok(())
            })?;
        }
        // Expired assets expire again.
        for asset in &set(NegSet::ExpiredAssets)? {
            self.db.tx(|t| {
                let Some(row) = crate::authz::asset_row(t, asset)? else {
                    return Ok(());
                };
                if self.expire_in(
                    t,
                    operator,
                    "recovery",
                    &row,
                    Some("anchored_expiry_reapplied"),
                )? {
                    notes.push(format!("asset {asset}: expiry re-applied"));
                }
                Ok(())
            })?;
        }
        // Retired purposes are retired again, and revoked governance keys
        // revoked again, each at its first recorded time (what was signed
        // or used before it stays valid history; nothing after it).
        for (which, table, done, action, rtype, column) in [
            (
                NegSet::RetiredPurposes,
                "purposes",
                "retired",
                "purpose.retired",
                "purpose",
                "retired",
            ),
            (
                NegSet::RevokedKeys,
                "governance_keys",
                "revoked",
                "governance_key.revoked",
                "governance_key",
                "revoked",
            ),
        ] {
            let ids = set(which)?;
            if ids.is_empty() {
                continue;
            }
            self.db.tx(|t| {
                let now = i64::try_from(encompute_verification::service::now()).unwrap_or(i64::MAX);
                let rows = t
                    .query(
                        &format!(
                            "UPDATE {table} x SET status = '{done}', {column}_by = $2,
                                    {column}_at = to_timestamp(COALESCE(
                                        (SELECT min((e.body ->> 'at')::bigint) FROM governance_events e
                                          WHERE e.kind = ANY($3) AND e.subject_id = x.id), $4))
                              WHERE x.id = ANY($1) AND x.status <> '{done}'
                             RETURNING x.id, x.organization_id"
                        ),
                        &[&ids, &operator, &which.kinds(), &now],
                    )
                    .map_err(db_err)?;
                for r in rows {
                    let (id, org): (String, String) = (r.get(0), r.get(1));
                    govlog::append_reapplied(t, which, &id, &[])?;
                    audit::append(
                        t,
                        AuditDraft::new(operator, "recovery", action, rtype, &id, Outcome::Succeeded)
                            .org(&org)
                            .r#ref("reason", format!("anchored_{column}_reapplied")),
                    )?;
                    notes.push(format!("{rtype} {id}: {} re-applied", if column == "retired" { "retirement" } else { "revocation" }));
                }
                Ok(())
            })?;
        }
        // Rows the database lost are recorded as lost in the log (their
        // IDs stay blocked), and audited.
        let lost = {
            let mut c = self.db.conn()?;
            missing_rows(&mut *c)?
        };
        if !lost.is_empty() {
            self.db.tx(|t| {
                for (which, id) in &lost {
                    govlog::append_lost(t, *which, id)?;
                    audit::append(
                        t,
                        AuditDraft::new(
                            operator,
                            "recovery",
                            "anchor.row_lost",
                            "anchor",
                            id,
                            Outcome::Succeeded,
                        )
                        .r#ref("state", which.lost_state()),
                    )?;
                }
                Ok(())
            })?;
            for (which, id) in &lost {
                notes.push(format!(
                    "{} {id}: the database lost its row; recorded as lost in the governance log (the ID stays blocked)",
                    which.state().to_lowercase()
                ));
            }
        }
        // Placement versions and location evidence the restore dropped or
        // brought back.
        notes.extend(self.recover_placement(operator)?);
        // The frozen ledgers' floors move to where the database holds them
        // now (a forward step along the log, like every checkpoint), so the
        // next start accepts the recovered database.
        let (seq, root) = {
            let mut c = self.db.conn()?;
            audit::verify_chain(&mut *c)?
        };
        if !frozen.is_empty() {
            self.db.tx(|t| {
                govlog::lock_head(t)?;
                for (asset, _, _) in &frozen {
                    if let Some(v) = load_ledger(t, asset)? {
                        govlog::append_ledger_checkpoint(t, asset, &v.checkpoint()?)?;
                    }
                }
                Ok(())
            })?;
        }
        self.anchor.update(&self.signer, |x| {
            x.audit_seq = seq;
            x.audit_root = root.clone();
        })?;
        self.checkpoint_log()?;
        Ok(notes)
    }

    /// Anchors the privacy ledger of `asset` as the database now holds it:
    /// its checkpoint is appended to the governance log
    /// (`privacy.ledger_checkpoint`, platform partition) and the log is
    /// checkpointed (mirror, then anchor) before this returns. Under the
    /// log's head lock, the ledger must extend the latest checkpoint of
    /// it: one that does not (rolled back, reset or rewritten while the
    /// service runs) is refused and never recorded, so the floor only
    /// moves forward along the same chain. A ledger no further than its
    /// latest checkpoint appends nothing (a retry), but still settles the
    /// log's checkpoint. Concurrent spends batch: the appends do not wait
    /// for the anchor, and whoever checkpoints first covers the others'
    /// events (the rest find theirs anchored already).
    pub fn anchor_ledger(&self, asset: &str) -> Result<()> {
        let missing = || {
            runtime_rollback(
                "PRIVACY",
                format!("the privacy ledger of {asset} is missing"),
            )
        };
        // The ledger is read and verified before the log's head is locked
        // (verifying walks every entry; appends elsewhere must not wait
        // for it).
        let mut view = {
            let mut c = self.db.conn()?;
            load_ledger(&mut *c, asset)?.ok_or_else(missing)?
        };
        view.verify()?;
        let appended = self.db.tx(|t| {
            govlog::lock_head(t)?;
            let mut cp = view.checkpoint()?;
            if let Some(floor) = govlog::latest_ledger_checkpoint(t, asset)? {
                if view.extends(&floor).is_err() {
                    // Behind the floor or forked: or another spend moved
                    // the ledger on since it was read? Read it again, under
                    // the lock.
                    view = load_ledger(t, asset)?.ok_or_else(missing)?;
                    view.verify()?;
                    cp = view.checkpoint()?;
                    view.extends(&floor).map_err(|e| {
                        self.rollback_alarm("privacy", asset);
                        runtime_rollback(
                            "PRIVACY",
                            format!("the privacy ledger of {asset}: {}", e.message),
                        )
                    })?;
                }
                if floor.seq >= cp.seq {
                    return Ok(None);
                }
            }
            Ok(Some(govlog::append_ledger_checkpoint(t, asset, &cp)?.gseq))
        })?;
        // Whoever checkpointed past this event already anchored it.
        self.retry_concurrent_mirror(|| self.checkpoint_log_once(appended))
    }

    /// The latest checkpoint of `asset`'s privacy ledger the governance log
    /// holds (the floor the ledger must still extend).
    pub fn ledger_floor(&self, asset: &str) -> Result<Option<encompute_privacy::Checkpoint>> {
        let mut c = self.db.conn()?;
        govlog::latest_ledger_checkpoint(&mut *c, asset)
    }

    /// Runs `f` in a transaction like `self.db.tx`; if any security deny
    /// event was appended meanwhile (a job ended, an asset revoked, an
    /// account disabled, whichever path), the log is then checkpointed
    /// (mirror, then anchor) before this returns, so the call does not
    /// succeed before the deny state is anchored. A failed checkpoint
    /// fails the call and keeps the obligation, so a retry (or the
    /// background task) anchors it; the database enforces the change
    /// meanwhile.
    pub fn tx_anchored<T>(
        &self,
        f: impl FnMut(&mut postgres::Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        // A flag left by an earlier call on this thread that did not use
        // this wrapper (a plain `db.tx`) must not leak into this one: it is
        // cleared first. An obligation a failed checkpoint left
        // (`RETRY_CHECKPOINT`) is kept and settled by this call.
        let retry = govlog::RETRY_CHECKPOINT.with(|d| d.replace(false));
        govlog::DENY_PENDING.with(|d| d.set(false));
        let out = self.db.tx(f)?;
        if govlog::DENY_PENDING.with(|d| d.replace(false)) || retry {
            if let Err(e) = self.checkpoint_log() {
                govlog::RETRY_CHECKPOINT.with(|d| d.set(true));
                return Err(e);
            }
        }
        Ok(out)
    }

    /// Checkpoints the governance log and anchors its head: the log must
    /// extend the anchored head (the events after it link and hash
    /// correctly, and the anchored event is still there), each partition
    /// it grew in gets a signed checkpoint, and the anchor records the new
    /// size and head. Under the anchor's lock, so two never race; a log
    /// that does not extend the anchored head is refused (GOVERNANCE LOG
    /// STATE ROLLBACK) and never anchored. Runs after the operations that
    /// make security-negative transitions (before their key brokers are
    /// told) and in the background (a crash between a commit and its
    /// checkpoint is caught up here).
    pub fn checkpoint_log(&self) -> Result<()> {
        self.retry_concurrent_mirror(|| self.checkpoint_log_once(None))
    }

    /// Runs `f` again (a few times at most) when a mirror segment another
    /// writer took first made it fail, like an anchor update that lost its
    /// compare-and-set.
    fn retry_concurrent_mirror(&self, f: impl Fn() -> Result<()>) -> Result<()> {
        let mut attempt = 0;
        loop {
            match f() {
                Err(e) if attempt < 3 && e.message.contains("written concurrently") => {
                    attempt += 1;
                    // A little jitter, so two writers do not collide again.
                    let ns = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.subsec_nanos() as u64);
                    std::thread::sleep(Duration::from_millis(5 * attempt + ns % 11));
                }
                r => return r,
            }
        }
    }

    /// A log that does not extend the anchored head is a rollback found
    /// while the service runs; any other error passes.
    fn log_rollback(&self, a: &crate::anchor::StateAnchor, e: Error) -> Error {
        if e.code == Code::TrustEvidence {
            self.rollback_alarm("governance", "log");
            runtime_rollback(
                "GOVERNANCE LOG",
                format!(
                    "the log does not extend anchored governance event {}: {}",
                    a.glog_size, e.message
                ),
            )
        } else {
            e
        }
    }

    /// Moves the anchor's log head forward to (`size`, `head`) once the
    /// mirror holds it; `false` (nothing to store) when it is no further.
    fn advance_log(
        &self,
        a: &mut crate::anchor::StateAnchor,
        size: i64,
        head: String,
    ) -> Result<bool> {
        if size <= a.glog_size {
            return Ok(false);
        }
        // The mirror first: the anchor's compare-and-set is the commit
        // point, and the anchor store must then hold every anchored event.
        self.mirror_through(a.glog_size, size, a.seal.as_ref().map_or(0, |s| s.size))?;
        a.glog_size = size;
        a.glog_head = head;
        Ok(true)
    }

    /// One checkpoint of the log. With `covered`, the event that needs
    /// anchoring: nothing is done when the anchor already holds it.
    ///
    /// The audit chain's head is anchored in the same compare-and-set
    /// (one signed anchor, one commit point), so a checkpoint that makes a
    /// deny event durable also covers every audit event committed before
    /// it (the deny's own audit event, written in its transaction,
    /// included). The audit chain has no mirror: the anchor detects a
    /// truncated or rewritten chain, it cannot restore one.
    fn checkpoint_log_once(&self, covered: Option<i64>) -> Result<()> {
        self.anchor
            .try_update(&self.signer, |a| {
                if covered.is_some_and(|g| g <= a.glog_size) {
                    return Ok(false);
                }
                let audit_due = self.audit_head_differs(a);
                let (size, head, audit) = self.db.tx(|t| {
                    let (size, head) =
                        govlog::checkpoint_extending(t, &self.signer, a.glog_size, &a.glog_head)
                            .map_err(|e| self.log_rollback(a, e))?;
                    let audit = if audit_due {
                        Some(
                            audit::checkpoint_extending(
                                t,
                                &self.signer,
                                a.audit_seq,
                                &a.audit_root,
                            )
                            .map_err(|e| self.audit_rollback(a, e))?,
                        )
                    } else {
                        None
                    };
                    Ok((size, head, audit))
                })?;
                let mut moved = false;
                if let Some(cp) = audit {
                    if cp.seq > a.audit_seq {
                        a.audit_seq = cp.seq;
                        a.audit_root = cp.root;
                        moved = true;
                    }
                }
                Ok(self.advance_log(a, size, head)? || moved)
            })
            .map(|_| ())
    }

    /// Whether the audit head is not the anchored event (a read, no lock):
    /// ahead of it, or behind or different, which the checkpoint then
    /// refuses.
    fn audit_head_differs(&self, a: &crate::anchor::StateAnchor) -> bool {
        let head = self.db.conn().and_then(|mut c| {
            c.query_one("SELECT seq, hash FROM audit_head WHERE id", &[])
                .map_err(db_err)
        });
        match head {
            Ok(r) => r.get::<_, i64>(0) != a.audit_seq || r.get::<_, String>(1) != a.audit_root,
            Err(_) => true,
        }
    }

    /// An audit chain that does not extend the anchored root is a rollback
    /// found while the service runs; any other error passes.
    fn audit_rollback(&self, a: &crate::anchor::StateAnchor, e: Error) -> Error {
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
    }

    /// Whether the transition that put `id` in `set` is anchored: the
    /// governance log's event of it lies within the anchored size.
    pub fn anchored(&self, set: govlog::NegSet, id: &str) -> Result<bool> {
        let size = self.anchor.snapshot().glog_size;
        let mut c = self.db.conn()?;
        Ok(govlog::first_gseq(&mut *c, set, id)?.is_some_and(|g| g <= size))
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
                .map_err(|e| self.audit_rollback(a, e))?;
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

    /// Periodic work: scheduling, retention (expiring versions past their
    /// deletion date), message delivery, evaluator health, nonce cleanup,
    /// audit checkpoints. Runs until the process exits.
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
        report("retention", self.expire_assets().map(|_| ()));
        report("anchor", self.checkpoint_log());
        // Spends and starts that committed but failed to anchor.
        // (every fifth pass: it reads every ledger's entry count)
        static PASSES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if PASSES
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .is_multiple_of(5)
        {
            report("ledgers", self.anchor_pending_ledgers().map(|_| ()));
        }
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
        scoping: None,
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

/// The governance log must verify (`glog`, from [`govlog::verify_chain`])
/// and contain the anchored head at the anchored size; a migrated anchor's
/// genesis event must still be there with the version-1 anchor it
/// recorded; and each partition's latest signed checkpoint must verify and
/// still be its root. `refuse` builds the error.
fn check_log_extends(
    c: &mut impl GenericClient,
    a: &crate::anchor::StateAnchor,
    glog: Result<(i64, String)>,
    control_key: &str,
    refuse: impl Fn(&str, String) -> Error,
) -> Result<()> {
    const WHAT: &str = "GOVERNANCE LOG";
    let (size, _) =
        glog.map_err(|e| refuse(WHAT, format!("the log does not verify: {}", e.message)))?;
    if a.glog_size > size
        || govlog::hash_at(c, a.glog_size)?.as_deref() != Some(a.glog_head.as_str())
    {
        return Err(refuse(
            WHAT,
            format!(
                "the anchor recorded governance event {} but the database's log ends at {size} or differs there",
                a.glog_size
            ),
        ));
    }
    if let Some(m) = &a.migrated_from {
        let kept = govlog::genesis(c)?;
        let ok = kept.as_ref().is_some_and(|(g, digest, anchor)| {
            *g <= a.glog_size
                && *digest == m.digest
                && anchor
                    .as_deref()
                    .map(|x| encompute_verification::service::sha256_hex(x.as_bytes()))
                    == Some(m.digest.clone())
        });
        if !ok {
            return Err(refuse(
                WHAT,
                "the migration's genesis event, or the version-1 anchor kept with it, is missing or differs".into(),
            ));
        }
    }
    for (partition, size, root, signed) in govlog::latest_checkpoints(c)? {
        let bad = |m: &str| {
            refuse(
                WHAT,
                format!("the checkpoint of {partition} at size {size}: {m}"),
            )
        };
        let cp: encompute_trust::govlog::SignedProjectCheckpoint =
            serde_json::from_value(signed).map_err(|e| bad(&e.to_string()))?;
        cp.verify(control_key).map_err(|e| bad(&e.message))?;
        if cp.body.partition != partition || cp.body.size as i64 != size || cp.body.root != root {
            return Err(bad("its row differs from its signed body"));
        }
        if size as u64 > govlog::partition_size(c, &partition)? {
            return Err(bad("the partition is shorter"));
        }
        let now =
            encompute_trust::govlog::hash_hex(&govlog::partition_root(c, &partition, size as u64)?);
        if now != root {
            return Err(bad("the partition's root there differs"));
        }
    }
    Ok(())
}

/// The sets whose rows must stay: (set, table, how a row matches `s.x`).
/// Withdrawn approvals, removed memberships and removed roles are absent
/// rows; frozen ledgers are checked with the ledgers.
const PRESENT: &[(govlog::NegSet, &str, &str)] = &[
    (govlog::NegSet::RevokedAssets, "assets", "t.id = s.x"),
    (
        govlog::NegSet::DisabledServices,
        "service_accounts",
        "t.id = s.x",
    ),
    (govlog::NegSet::DisabledUsers, "users", "t.id = s.x"),
    (govlog::NegSet::EndedJobs, "jobs", "t.id = s.x"),
    (
        govlog::NegSet::RevokedAuthorizations,
        "authorizations",
        "t.id = s.x OR t.authorization_id = s.x",
    ),
    (govlog::NegSet::ExpiredAssets, "assets", "t.id = s.x"),
    (govlog::NegSet::RetiredPurposes, "purposes", "t.id = s.x"),
    (govlog::NegSet::RevokedKeys, "governance_keys", "t.id = s.x"),
];

/// The IDs of the negative sets that the database does not hold, and that
/// recovery has not acknowledged as lost (`row.lost`): (set, ID).
fn missing_rows(c: &mut impl GenericClient) -> Result<Vec<(govlog::NegSet, String)>> {
    let mut out = vec![];
    for (set, table, matches) in PRESENT {
        let rows = c
            .query(
                &format!(
                    "SELECT s.x FROM ({}) AS s(x)
                      WHERE NOT EXISTS (SELECT 1 FROM {table} t WHERE {matches})
                        AND NOT EXISTS (SELECT 1 FROM governance_events l
                                         WHERE l.kind = $2 AND l.subject_id = s.x
                                           AND l.body #>> '{{refs,state}}' = $3)
                      ORDER BY 1",
                    set.ids_sql()
                ),
                &[
                    &set.kinds(),
                    &govlog::extra_kind::ROW_LOST,
                    &set.lost_state(),
                ],
            )
            .map_err(db_err)?;
        out.extend(rows.iter().map(|r| (*set, r.get::<_, String>(0))));
    }
    Ok(out)
}

/// For each set, the rows that show its transition undone: (ID, what the
/// row shows), with `IDS` standing for the set's IDs.
const UNDONE: &[(govlog::NegSet, &str)] = &[
    (
        govlog::NegSet::FrozenLedgers,
        "SELECT asset_id, 'spendable' FROM privacy_ledgers WHERE frozen_reason IS NULL AND asset_id IN (IDS) ORDER BY 1",
    ),
    (
        govlog::NegSet::RevokedAssets,
        "SELECT id, status FROM assets WHERE status <> 'revoked' AND id IN (IDS) ORDER BY 1",
    ),
    (
        govlog::NegSet::DisabledServices,
        "SELECT id, status FROM service_accounts WHERE status <> 'disabled' AND id IN (IDS) ORDER BY 1",
    ),
    (
        govlog::NegSet::DisabledUsers,
        "SELECT id, status FROM users WHERE status <> 'disabled' AND id IN (IDS) ORDER BY 1",
    ),
    (
        govlog::NegSet::EndedJobs,
        "SELECT id, state FROM jobs WHERE state NOT IN ('failed', 'cancelled') AND id IN (IDS) ORDER BY 1",
    ),
    (
        govlog::NegSet::WithdrawnGrants,
        "SELECT approval_id, asset_id FROM asset_approvals WHERE approval_id IN (IDS)
         UNION ALL
         SELECT grant_id, asset_id FROM asset_approval_members WHERE grant_id IN (IDS)
         ORDER BY 1",
    ),
    (
        govlog::NegSet::RemovedMemberships,
        "SELECT membership_id, organization_id || ' in project ' || project_id FROM project_members
          WHERE membership_id IN (IDS) ORDER BY 1",
    ),
    (
        govlog::NegSet::RemovedRoles,
        "SELECT membership_id, role || ' of ' || principal_id || ' in ' || organization_id FROM memberships
          WHERE membership_id IN (IDS) ORDER BY 1",
    ),
    (
        govlog::NegSet::RevokedAuthorizations,
        "SELECT id, status FROM authorizations
          WHERE status <> 'revoked' AND (id IN (IDS) OR authorization_id IN (IDS)) ORDER BY 1",
    ),
    (
        govlog::NegSet::ExpiredAssets,
        "SELECT id, status FROM assets WHERE expired_at IS NULL AND id IN (IDS) ORDER BY 1",
    ),
    (
        govlog::NegSet::RetiredPurposes,
        "SELECT id, status FROM purposes WHERE status <> 'retired' AND id IN (IDS) ORDER BY 1",
    ),
    (
        govlog::NegSet::RevokedKeys,
        "SELECT id, status FROM governance_keys WHERE status <> 'revoked' AND id IN (IDS) ORDER BY 1",
    ),
];

/// The first row that shows a negative set's transition undone: (set,
/// ID, what it shows). One query per set, each a semi-join on the log's
/// index of kinds.
fn undone(c: &mut impl GenericClient) -> Result<Option<(govlog::NegSet, String, String)>> {
    for (set, sql) in UNDONE {
        let r = c
            .query(&sql.replace("IDS", set.ids_sql()), &[&set.kinds()])
            .map_err(db_err)?;
        if let Some(r) = r.first() {
            return Ok(Some((*set, r.get(0), r.get(1))));
        }
    }
    Ok(None)
}

fn undone_message(set: govlog::NegSet, id: &str, shows: &str) -> String {
    use govlog::NegSet as N;
    match set {
        N::FrozenLedgers => {
            format!("the privacy ledger of {id} was frozen, but the database shows it spendable")
        }
        N::RevokedAssets => format!("asset {id} was revoked, but the database shows it {shows}"),
        N::DisabledServices => {
            format!("service account {id} was disabled, but the database shows it {shows}")
        }
        N::DisabledUsers => format!("user {id} was disabled, but the database shows it {shows}"),
        N::EndedJobs => {
            format!("job {id} was cancelled or failed, but the database shows it {shows}")
        }
        N::WithdrawnGrants => {
            format!("approval {id} of asset {shows} was withdrawn, but the database holds it")
        }
        N::RemovedMemberships => {
            format!("membership {id} ({shows}) was removed, but the database holds it")
        }
        N::RemovedRoles => format!("role {id} ({shows}) was removed, but the database holds it"),
        N::RevokedAuthorizations => {
            format!("authorization {id} was revoked, but the database shows it {shows}")
        }
        N::ExpiredAssets => {
            format!("asset {id} expired, but the database shows it {shows} and not expired")
        }
        N::RetiredPurposes => {
            format!("purpose {id} was retired, but the database shows it {shows}")
        }
        N::RevokedKeys => {
            format!("governance key {id} was revoked, but the database shows it {shows}")
        }
    }
}

/// An asset's status, or `None` if the database does not hold it.
pub(crate) fn revoked_status(c: &mut impl GenericClient, asset: &str) -> Result<Option<String>> {
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
