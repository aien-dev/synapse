use serde_json::Value;

fn validate(report: &Value) -> Result<(), &'static str> {
    if report["qualified"].as_bool() != Some(true) {
        return Err("qualification verdict must be true");
    }
    for component in ["suite", "parity", "interop"] {
        if report[component]["exit"].as_i64() != Some(0) {
            return Err("every qualification component must exit successfully");
        }
    }
    let scenarios = report["scenarios"]
        .as_array()
        .ok_or("qualification scenarios must be an array")?;
    if scenarios.len() != 12 {
        return Err("qualification must contain exactly twelve scenarios");
    }
    for i in 1..=12 {
        let id = format!("S{i:02}");
        let mut matches = scenarios
            .iter()
            .filter(|scenario| scenario["id"].as_str() == Some(id.as_str()));
        let scenario = matches.next().ok_or("missing required scenario")?;
        if matches.next().is_some() {
            return Err("duplicate qualification scenario");
        }
        match scenario["status"].as_str() {
            Some("PASS") => {}
            Some("KNOWN-GAP") if i != 5 => {}
            _ => return Err("scenario must pass or name an allowed gap; S05 must pass"),
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: verify-qualification results.json")?;
    if args.next().is_some() {
        return Err("usage: verify-qualification results.json".into());
    }
    let report: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    validate(&report)?;
    println!("SYNAPSE_QUALIFICATION_REPORT: PASS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn passing() -> Value {
        json!({
            "qualified": true,
            "suite": {"exit": 0}, "parity": {"exit": 0}, "interop": {"exit": 0},
            "scenarios": (1..=12).map(|i| json!({"id": format!("S{i:02}"), "status": "PASS"})).collect::<Vec<_>>()
        })
    }

    #[test]
    fn accepts_pass_and_declared_gaps_outside_s05() {
        let mut report = passing();
        assert!(validate(&report).is_ok());
        report["scenarios"][0]["status"] = json!("KNOWN-GAP");
        assert!(validate(&report).is_ok());
    }

    #[test]
    fn refuses_unqualified_or_missing_verdict() {
        for verdict in [Value::Null, json!(false), json!("true")] {
            let mut report = passing();
            report["qualified"] = verdict;
            assert!(validate(&report).is_err());
        }
    }

    #[test]
    fn refuses_failed_or_missing_component_results() {
        for component in ["suite", "parity", "interop"] {
            for exit in [Value::Null, json!(1), json!("0")] {
                let mut report = passing();
                report[component]["exit"] = exit;
                assert!(validate(&report).is_err());
            }
        }
    }

    #[test]
    fn refuses_missing_duplicate_or_unknown_scenarios() {
        let mut report = passing();
        report["scenarios"].as_array_mut().unwrap().pop();
        assert!(validate(&report).is_err());
        let mut report = passing();
        report["scenarios"][11]["id"] = json!("S01");
        assert!(validate(&report).is_err());
        report["scenarios"][11]["id"] = json!("S13");
        assert!(validate(&report).is_err());
        let mut report = passing();
        let duplicate = report["scenarios"][0].clone();
        report["scenarios"].as_array_mut().unwrap().push(duplicate);
        assert!(validate(&report).is_err());
    }

    #[test]
    fn refuses_bad_status_and_s05_gap() {
        for status in [Value::Null, json!("FAIL"), json!("NOT_RUN")] {
            let mut report = passing();
            report["scenarios"][0]["status"] = status;
            assert!(validate(&report).is_err());
        }
        let mut report = passing();
        report["scenarios"][4]["status"] = json!("KNOWN-GAP");
        assert!(validate(&report).is_err());
    }

    #[test]
    fn refuses_missing_scenario_array() {
        let mut report = passing();
        report["scenarios"] = Value::Null;
        assert!(validate(&report).is_err());
    }
}
