use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct DiagnosticReport {
    pub check: String,
    pub target: String,
    pub success: bool,
    pub elapsed_ms: u128,
    pub details: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl DiagnosticReport {
    pub fn success(check: &str, target: &str, elapsed_ms: u128, details: Value) -> Self {
        Self {
            check: check.to_owned(),
            target: target.to_owned(),
            success: true,
            elapsed_ms,
            details,
            error: None,
        }
    }

    pub fn failure(check: &str, target: &str, elapsed_ms: u128, error: impl ToString) -> Self {
        Self {
            check: check.to_owned(),
            target: target.to_owned(),
            success: false,
            elapsed_ms,
            details: Value::Null,
            error: Some(error.to_string()),
        }
    }
}

pub fn emit(report: &DiagnosticReport, json: bool) {
    if json {
        match serde_json::to_string_pretty(report) {
            Ok(output) => println!("{output}"),
            Err(error) => eprintln!("Could not serialize report: {error}"),
        }
        return;
    }

    let state = if report.success { "SUCCESS" } else { "FAILED" };
    println!("[{state}] {} — {}", report.check, report.target);
    println!("Elapsed: {} ms", report.elapsed_ms);
    if !report.details.is_null() {
        println!("Details: {}", report.details);
    }
    if let Some(error) = &report.error {
        println!("Error: {error}");
    }
}

pub fn emit_analysis(report: &crate::diagnostics::analyzer::ProtocolAnalysisReport, json: bool) {
    if json {
        match serde_json::to_string_pretty(report) {
            Ok(output) => println!("{output}"),
            Err(error) => eprintln!("Could not serialize analysis report: {error}"),
        }
        return;
    }

    let state = if report.success { "SUCCESS" } else { "INCOMPLETE" };
    println!("[{state}] {} — {}", report.check, report.target);
    for stage in &report.stages {
        let stage_state = if stage.success { "PASS" } else { "FAIL" };
        println!("  [{stage_state}] {} — {} ms", stage.check, stage.elapsed_ms);
        if let Some(error) = &stage.error {
            println!("    Error: {error}");
        }
        if !stage.details.is_null() {
            println!("    Details: {}", stage.details);
        }
    }
    println!("Summary: {}", report.summary);
}
