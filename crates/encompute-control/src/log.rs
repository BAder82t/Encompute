//! Structured JSON logs on stderr: one object per line, always with the
//! service, and the request, job, project and organization IDs where they
//! apply. Only identifiers and outcomes are logged: never request bodies,
//! tokens, keys or payloads.

use std::collections::BTreeMap;

#[derive(Default)]
pub struct LogLine {
    fields: BTreeMap<&'static str, String>,
}

impl LogLine {
    pub fn new(service: &str, event: &str) -> Self {
        let mut l = Self::default();
        l.fields.insert("service", service.into());
        l.fields.insert("event", event.into());
        l.fields.insert(
            "ts",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis().to_string())
                .unwrap_or_default(),
        );
        l
    }

    /// Adds an identifier field (skipped when `None`).
    pub fn id(mut self, k: &'static str, v: Option<&str>) -> Self {
        if let Some(v) = v {
            self.fields.insert(k, v.into());
        }
        self
    }

    pub fn field(mut self, k: &'static str, v: impl ToString) -> Self {
        self.fields.insert(k, v.to_string());
        self
    }

    pub fn emit(self) {
        eprintln!(
            "{}",
            serde_json::to_string(&self.fields).unwrap_or_default()
        );
    }
}
