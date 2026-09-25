//! Secure aggregation for compiled programs (ADR-012).

use encompute_analysis::confidentiality::analyze;
use encompute_ir::{Code, Error, Result};
use encompute_secagg::AggregationPlan;

use crate::model::Model;

impl Model {
    /// The aggregation plan for `output` (default: the only aggregated
    /// output), lowered from the program's checked `aggregate` declaration.
    pub fn aggregation_plan(&self, output: Option<&str>) -> Result<AggregationPlan> {
        let report = analyze(self.program())?;
        let bounds = report.map(|r| r.aggregations).unwrap_or_default();
        let b = match output {
            Some(o) => bounds.iter().find(|b| b.output == o),
            None if bounds.len() == 1 => bounds.first(),
            None => None,
        }
        .ok_or_else(|| {
            Error::new(
                Code::AggregationPlan,
                match (output, bounds.len()) {
                    (_, 0) => format!("{} declares no aggregation", self.program().name()),
                    (Some(o), _) => format!("no aggregation for output {o:?}"),
                    (None, _) => "several aggregations: name the output".to_owned(),
                },
            )
        })?;
        let ids = self.ids();
        Ok(AggregationPlan::from_boundary(
            &ids.program_id,
            ids.policy_id.as_deref(),
            ids.privacy_policy_id.as_deref(),
            b,
        ))
    }
}
