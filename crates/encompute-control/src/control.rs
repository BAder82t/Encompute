//! The control plane service: coordinates, never computes on or holds
//! protected data, and is not a cryptographic trust anchor. Trust results
//! are rebuilt from signed evidence and trusted keys.

use std::path::Path;
use std::time::Duration;

use postgres::GenericClient;

use encompute_ir::{Code, Error, Result};
use encompute_privacy::{Entry, Genesis, LedgerView};
use encompute_verification::ServiceSigner;

use crate::anchor::{open_store, Anchor, AnchorStore};
use crate::audit::{self, AuditDraft, Outcome};
use crate::authn::{Authenticator, Principal};
use crate::config::{AnchorConfig, Config, Env};
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
}

pub fn rollback(what: &str, detail: impl std::fmt::Display) -> Error {
    Error::new(
        Code::PrivacyLedger,
        format!("{what} STATE ROLLBACK: {detail}. STARTUP REFUSED: restore the missing entries, or run `encompute-control recover` (see docs/deployment.md)"),
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
        Self::with_parts(
            cfg.env,
            &cfg.service_id,
            db,
            Authenticator::new(
                cfg.env,
                &cfg.service_id,
                cfg.oidc.clone(),
                cfg.dev_token_secret.clone(),
            ),
            signer,
            store,
            None,
            cfg.audit_checkpoint_every,
        )
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
        };
        c.ensure_self_registered()?;
        c.verify_state(existed)?;
        if !existed {
            // A fresh deployment: write the initial anchor now, so any later
            // start compares against it.
            c.anchor.update(&c.signer, |_| {})?;
        }
        LogLine::new(&c.service_id, "started")
            .field("anchor", c.anchor.describe())
            .field("env", format!("{:?}", c.env))
            .emit();
        Ok(c)
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

    /// The database must extend the anchor: nothing anchored may be missing.
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
            if a.frozen.contains(asset) {
                continue;
            }
            let view = load_ledger(&mut *c, asset)?.ok_or_else(|| {
                rollback(
                    "PRIVACY",
                    format!("the privacy ledger of {asset} is missing"),
                )
            })?;
            view.verify()?;
            view.extends(cp).map_err(|e| {
                rollback(
                    "PRIVACY",
                    format!("the privacy ledger of {asset}: {}", e.message),
                )
            })?;
        }
        Ok(())
    }

    /// Explicit recovery after a detected rollback. Ledgers behind the
    /// anchor are **frozen**: treated as exhausted, so spending the
    /// database forgot can never be spent again. A rewound audit chain is
    /// recorded as a gap. Both are audited, then the anchor is re-signed.
    pub fn recover(&self, operator: &str) -> Result<Vec<String>> {
        let a = self.anchor.snapshot();
        let mut notes = vec![];
        let mut frozen = vec![];
        {
            let mut c = self.db.conn()?;
            for (asset, cp) in &a.ledgers {
                if a.frozen.contains(asset) {
                    continue;
                }
                let behind = match load_ledger(&mut *c, asset)? {
                    None => true,
                    Some(v) => v.extends(cp).is_err(),
                };
                if behind {
                    frozen.push((asset.clone(), cp.clone()));
                }
            }
        }
        self.db.tx(|t| {
            for (asset, cp) in &frozen {
                let reason = format!(
                    "rolled back behind anchored entry {} (root {}); frozen by {operator}",
                    cp.seq, cp.root
                );
                t.execute(
                    "UPDATE privacy_ledgers SET frozen_reason = $2 WHERE asset_id = $1",
                    &[asset, &reason],
                )
                .map_err(db_err)?;
                audit::append(
                    t,
                    AuditDraft::new(
                        operator,
                        "recovery",
                        "privacy.ledger.frozen",
                        "asset",
                        asset,
                        Outcome::Succeeded,
                    )
                    .r#ref("anchored_seq", cp.seq.to_string())
                    .r#ref("anchored_root", cp.root.clone()),
                )?;
                notes.push(format!(
                    "privacy ledger {asset}: frozen (treated as exhausted)"
                ));
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
        let mut c = self.db.conn()?;
        let (seq, root) = audit::verify_chain(&mut *c)?;
        let mut ledgers = a.ledgers.clone();
        for (asset, _) in &frozen {
            if let Some(v) = load_ledger(&mut *c, asset)? {
                ledgers.insert(asset.clone(), v.checkpoint()?);
            }
        }
        self.anchor.update(&self.signer, |x| {
            x.audit_seq = seq;
            x.audit_root = root;
            x.ledgers = ledgers;
            for (asset, _) in &frozen {
                x.frozen.insert(asset.clone());
            }
        })?;
        Ok(notes)
    }

    /// Anchors the audit head (after a signed checkpoint).
    pub fn checkpoint_audit(&self) -> Result<audit::AuditCheckpoint> {
        let cp = self.db.tx(|t| audit::checkpoint(t, &self.signer))?;
        self.anchor.update(&self.signer, |a| {
            if cp.seq >= a.audit_seq {
                a.audit_seq = cp.seq;
                a.audit_root = cp.root.clone();
            }
        })?;
        Ok(cp)
    }

    /// Checkpoints when enough events accumulated since the last one.
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
            if (h - a.audit_seq) as u64 >= self.audit_every {
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
        report("outbox", self.deliver_outbox());
        report(
            "nonces",
            self.db
                .conn()
                .and_then(|mut c| crate::authn::prune_nonces(&mut *c))
                .map(|_| ()),
        );
        self.maybe_checkpoint();
        if let Ok(mut c) = self.db.conn() {
            if let Ok(r) = c.query_one(
                "SELECT count(*) FROM jobs WHERE state IN ('authorized', 'queued')",
                &[],
            ) {
                self.metrics.set("encompute_queue_depth", "all", r.get(0));
            }
        }
    }
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
