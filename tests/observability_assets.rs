use std::collections::BTreeSet;
use std::path::PathBuf;

use smesh_a2a::telemetry::{AttributeKey, MetricName};

fn expressions_from_rules(rules: &str) -> Result<Vec<String>, String> {
    let expressions: Vec<_> = rules
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix("expr:")
                .map(|expression| expression.trim().to_owned())
        })
        .collect();
    if expressions.len() != rules.matches("expr:").count()
        || expressions.iter().any(String::is_empty)
    {
        return Err("every Prometheus rule must have one inline expression".to_owned());
    }
    Ok(expressions)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Ident(String),
    Number,
    String,
    LeftParen,
    RightParen,
    LeftBrace,
    RightBrace,
    LeftBracket,
    RightBracket,
    Comma,
    Operator(String),
}

#[allow(clippy::too_many_lines)]
fn tokenize(expression: &str) -> Result<Vec<Token>, String> {
    let bytes = expression.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte.is_ascii_whitespace() => index += 1,
            b'a'..=b'z' | b'A'..=b'Z' | b'_' | b':' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b':'))
                {
                    index += 1;
                }
                tokens.push(Token::Ident(expression[start..index].to_owned()));
            }
            b'0'..=b'9' | b'.' => {
                let start = index;
                index += 1;
                while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.')
                {
                    index += 1;
                }
                if index < bytes.len() && matches!(bytes[index], b'e' | b'E') {
                    index += 1;
                    if index < bytes.len() && matches!(bytes[index], b'+' | b'-') {
                        index += 1;
                    }
                    let exponent = index;
                    while index < bytes.len() && bytes[index].is_ascii_digit() {
                        index += 1;
                    }
                    if exponent == index {
                        return Err(format!("invalid exponent in PromQL: {expression}"));
                    }
                }
                expression[start..index]
                    .parse::<f64>()
                    .map_err(|_| format!("invalid number in PromQL: {expression}"))?;
                tokens.push(Token::Number);
            }
            b'"' => {
                index += 1;
                let mut closed = false;
                while index < bytes.len() {
                    match bytes[index] {
                        b'\\' => {
                            index += 2;
                        }
                        b'"' => {
                            index += 1;
                            closed = true;
                            break;
                        }
                        b'\n' | b'\r' => {
                            return Err(format!("newline in PromQL string: {expression}"));
                        }
                        _ => index += 1,
                    }
                }
                if !closed {
                    return Err(format!("unterminated PromQL string: {expression}"));
                }
                tokens.push(Token::String);
            }
            b'(' => {
                tokens.push(Token::LeftParen);
                index += 1;
            }
            b')' => {
                tokens.push(Token::RightParen);
                index += 1;
            }
            b'{' => {
                tokens.push(Token::LeftBrace);
                index += 1;
            }
            b'}' => {
                tokens.push(Token::RightBrace);
                index += 1;
            }
            b'[' => {
                tokens.push(Token::LeftBracket);
                index += 1;
            }
            b']' => {
                tokens.push(Token::RightBracket);
                index += 1;
            }
            b',' => {
                tokens.push(Token::Comma);
                index += 1;
            }
            b'+' | b'-' | b'*' | b'/' | b'%' | b'^' | b'>' | b'<' | b'=' | b'!' => {
                let start = index;
                index += 1;
                if index < bytes.len()
                    && (bytes[index] == b'='
                        || (matches!(bytes[start], b'=' | b'!') && bytes[index] == b'~'))
                {
                    index += 1;
                }
                tokens.push(Token::Operator(expression[start..index].to_owned()));
            }
            other => {
                return Err(format!(
                    "unsupported byte {:?} in PromQL: {expression}",
                    char::from(other)
                ));
            }
        }
    }
    if tokens.is_empty() {
        return Err("empty PromQL expression".to_owned());
    }
    Ok(tokens)
}

#[derive(Debug, Default, Eq, PartialEq)]
struct References {
    metrics: BTreeSet<String>,
    labels: BTreeSet<String>,
}

struct PromqlParser {
    tokens: Vec<Token>,
    index: usize,
    references: References,
}

impl PromqlParser {
    fn new(expression: &str) -> Result<Self, String> {
        Ok(Self {
            tokens: tokenize(expression)?,
            index: 0,
            references: References::default(),
        })
    }

    fn parse(mut self) -> Result<References, String> {
        self.parse_expression(0)?;
        if self.index != self.tokens.len() {
            return Err(format!("unparsed PromQL token: {:?}", self.peek()));
        }
        Ok(self.references)
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn take(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.index).cloned();
        self.index += usize::from(token.is_some());
        token
    }

    fn consume(&mut self, expected: &Token) -> bool {
        if self.peek() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: &Token) -> Result<(), String> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(format!("expected {expected:?}, found {:?}", self.peek()))
        }
    }

    fn parse_expression(&mut self, minimum_precedence: u8) -> Result<(), String> {
        if matches!(self.peek(), Some(Token::Operator(operator)) if operator == "+" || operator == "-")
        {
            self.take();
        }
        self.parse_primary()?;
        while let Some((precedence, right_associative)) = self.binary_precedence() {
            if precedence < minimum_precedence {
                break;
            }
            self.take();
            self.parse_vector_matching()?;
            let next_minimum = if right_associative {
                precedence
            } else {
                precedence + 1
            };
            self.parse_expression(next_minimum)?;
        }
        Ok(())
    }

    fn binary_precedence(&self) -> Option<(u8, bool)> {
        match self.peek() {
            Some(Token::Ident(operator)) if matches!(operator.as_str(), "or" | "unless") => {
                Some((1, false))
            }
            Some(Token::Ident(operator)) if operator == "and" => Some((2, false)),
            Some(Token::Operator(operator))
                if matches!(operator.as_str(), "==" | "!=" | ">" | "<" | ">=" | "<=") =>
            {
                Some((3, false))
            }
            Some(Token::Operator(operator)) if matches!(operator.as_str(), "+" | "-") => {
                Some((4, false))
            }
            Some(Token::Operator(operator)) if matches!(operator.as_str(), "*" | "/" | "%") => {
                Some((5, false))
            }
            Some(Token::Operator(operator)) if operator == "^" => Some((6, true)),
            _ => None,
        }
    }

    fn parse_primary(&mut self) -> Result<(), String> {
        match self.take() {
            Some(Token::Number) => Ok(()),
            Some(Token::LeftParen) => {
                self.parse_expression(0)?;
                self.expect(&Token::RightParen)
            }
            Some(Token::Ident(name)) if is_aggregation(&name) => self.parse_aggregation(),
            Some(Token::Ident(name)) if self.consume(&Token::LeftParen) => {
                if !is_function(&name) {
                    return Err(format!("unsupported PromQL function: {name}"));
                }
                self.parse_arguments()
            }
            Some(Token::Ident(metric)) => self.parse_selector(metric),
            token => Err(format!("expected PromQL operand, found {token:?}")),
        }
    }

    fn parse_aggregation(&mut self) -> Result<(), String> {
        let prefix_grouping = self.parse_optional_grouping()?;
        self.expect(&Token::LeftParen)?;
        self.parse_arguments_after_open()?;
        if !prefix_grouping {
            self.parse_optional_grouping()?;
        }
        Ok(())
    }

    fn parse_arguments(&mut self) -> Result<(), String> {
        self.parse_arguments_after_open()
    }

    fn parse_arguments_after_open(&mut self) -> Result<(), String> {
        if self.consume(&Token::RightParen) {
            return Err("PromQL calls require an argument".to_owned());
        }
        loop {
            self.parse_expression(0)?;
            if !self.consume(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RightParen)
    }

    fn parse_optional_grouping(&mut self) -> Result<bool, String> {
        if matches!(self.peek(), Some(Token::Ident(keyword)) if keyword == "by" || keyword == "without")
        {
            self.take();
            self.parse_label_list(false)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn parse_vector_matching(&mut self) -> Result<(), String> {
        if matches!(self.peek(), Some(Token::Ident(keyword)) if keyword == "bool") {
            self.take();
        }
        if matches!(self.peek(), Some(Token::Ident(keyword)) if keyword == "on" || keyword == "ignoring")
        {
            self.take();
            self.parse_label_list(true)?;
        }
        if matches!(self.peek(), Some(Token::Ident(keyword)) if keyword == "group_left" || keyword == "group_right")
        {
            self.take();
            if self.peek() == Some(&Token::LeftParen) {
                self.parse_label_list(true)?;
            }
        }
        Ok(())
    }

    fn parse_label_list(&mut self, allow_empty: bool) -> Result<(), String> {
        self.expect(&Token::LeftParen)?;
        if self.consume(&Token::RightParen) {
            return if allow_empty {
                Ok(())
            } else {
                Err("aggregation label list cannot be empty".to_owned())
            };
        }
        loop {
            let Some(Token::Ident(label)) = self.take() else {
                return Err("expected PromQL label name".to_owned());
            };
            self.references.labels.insert(label);
            if !self.consume(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RightParen)
    }

    fn parse_selector(&mut self, metric: String) -> Result<(), String> {
        self.references.metrics.insert(metric);
        if self.consume(&Token::LeftBrace) && !self.consume(&Token::RightBrace) {
            loop {
                let Some(Token::Ident(label)) = self.take() else {
                    return Err("expected selector label".to_owned());
                };
                self.references.labels.insert(label);
                match self.take() {
                    Some(Token::Operator(operator))
                        if matches!(operator.as_str(), "=" | "!=" | "=~" | "!~") => {}
                    operator => return Err(format!("invalid label matcher: {operator:?}")),
                }
                self.expect(&Token::String)?;
                if !self.consume(&Token::Comma) {
                    break;
                }
            }
            self.expect(&Token::RightBrace)?;
        }
        if self.consume(&Token::LeftBracket) {
            self.expect(&Token::Number)?;
            let Some(Token::Ident(unit)) = self.take() else {
                return Err("range duration requires a unit".to_owned());
            };
            if !matches!(unit.as_str(), "ms" | "s" | "m" | "h" | "d" | "w" | "y") {
                return Err(format!("invalid range duration unit: {unit}"));
            }
            self.expect(&Token::RightBracket)?;
        }
        Ok(())
    }
}

fn is_aggregation(name: &str) -> bool {
    matches!(
        name,
        "sum"
            | "avg"
            | "count"
            | "min"
            | "max"
            | "group"
            | "stddev"
            | "stdvar"
            | "topk"
            | "bottomk"
            | "count_values"
            | "quantile"
    )
}

fn is_function(name: &str) -> bool {
    matches!(
        name,
        "rate" | "increase" | "clamp_min" | "histogram_quantile"
    )
}

fn metric_and_label_references(expression: &str) -> Result<References, String> {
    PromqlParser::new(expression)?.parse()
}

fn emitted_prometheus_metrics() -> BTreeSet<String> {
    let mut emitted = BTreeSet::new();
    for metric in MetricName::ALL {
        let base = metric.as_str().replace('.', "_");
        match metric {
            MetricName::A2aRequestDuration | MetricName::TaskSettlementDuration => {
                let histogram = format!("{base}_milliseconds");
                for suffix in ["bucket", "sum", "count"] {
                    emitted.insert(format!("{histogram}_{suffix}"));
                }
            }
            MetricName::AuditProjectionLag => {
                emitted.insert(format!("{base}_seconds"));
            }
            MetricName::OutboxRows | MetricName::TelemetryQueue => {
                emitted.insert(base);
            }
            _ => {
                emitted.insert(format!("{base}_total"));
            }
        }
    }
    emitted
}

fn emitted_prometheus_labels() -> BTreeSet<String> {
    let mut labels: BTreeSet<_> = AttributeKey::ALL
        .iter()
        .map(|key| key.as_str().replace('.', "_"))
        .collect();
    // Prometheus creates this label for classic histogram buckets.
    labels.insert("le".to_owned());
    labels
}

fn validate_expression(expression: &str) -> Result<(), String> {
    let references = metric_and_label_references(expression)?;
    if references.metrics.is_empty() {
        return Err(format!("PromQL has no emitted metric: {expression}"));
    }
    let emitted_metrics = emitted_prometheus_metrics();
    for metric in references.metrics {
        if !emitted_metrics.contains(&metric) {
            return Err(format!("unknown metric {metric} in {expression}"));
        }
    }
    let emitted_labels = emitted_prometheus_labels();
    for label in references.labels {
        if !emitted_labels.contains(&label) {
            return Err(format!("unknown label {label} in {expression}"));
        }
    }
    Ok(())
}

#[test]
fn promql_references_include_aggregation_and_vector_matching_labels() {
    let references = metric_and_label_references(
        "sum by (smesh_outcome, le) (smesh_a2a_request_total) / on(smesh_slo) \
         group_left(smesh_result) smesh_a2a_sli_event_total",
    )
    .unwrap();
    assert_eq!(
        references.labels,
        BTreeSet::from([
            "le".to_owned(),
            "smesh_outcome".to_owned(),
            "smesh_result".to_owned(),
            "smesh_slo".to_owned(),
        ])
    );
    validate_expression(
        "sum by (smesh_outcome, le) (smesh_a2a_request_total) / on(smesh_slo) \
         group_left(smesh_result) smesh_a2a_sli_event_total",
    )
    .unwrap();
}

#[test]
fn promql_validation_rejects_misspelled_aggregation_labels() {
    let expression = "sum by (smesh_outcomm) (smesh_a2a_request_total)";
    let error = validate_expression(expression).unwrap_err();
    assert!(error.contains("unknown label smesh_outcomm"), "{error}");
}

#[test]
fn promql_references_include_every_grouping_and_matching_form() {
    let references = metric_and_label_references(
        "sum without (instance) (smesh_a2a_request_total) / ignoring(job) \
         group_right(smesh_result) max by (smesh_slo) (smesh_a2a_sli_event_total)",
    )
    .unwrap();
    assert_eq!(
        references.labels,
        BTreeSet::from([
            "instance".to_owned(),
            "job".to_owned(),
            "smesh_result".to_owned(),
            "smesh_slo".to_owned(),
        ])
    );
}

#[test]
fn promql_validation_allows_only_generated_histogram_series_and_labels() {
    validate_expression(
        "smesh_a2a_request_duration_milliseconds_sum \
         / smesh_a2a_request_duration_milliseconds_count",
    )
    .unwrap();
    validate_expression(
        "histogram_quantile(0.99, sum by (le) \
         (rate(smesh_a2a_request_duration_milliseconds_bucket[5m])))",
    )
    .unwrap();
    assert!(validate_expression("smesh_a2a_request_duration_milliseconds").is_err());
    assert!(
        validate_expression(
            "smesh_a2a_request_total / on(smesh_outcomm) smesh_a2a_sli_event_total"
        )
        .is_err()
    );
}

#[test]
fn promql_parser_rejects_malformed_or_unparsed_expressions() {
    for expression in [
        "sum(rate(smesh_a2a_request_total[5m])",
        "sum rate(smesh_a2a_request_total[5m])",
        "smesh_a2a_request_total{smesh_outcome}",
        "rate(smesh_a2a_request_total[5fortnights])",
    ] {
        assert!(
            metric_and_label_references(expression).is_err(),
            "malformed expression parsed: {expression}"
        );
    }
}

#[test]
fn objectives_rules_dashboard_and_runbook_are_checked_in_and_schema_consistent() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let objectives: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("observability/objectives.json")).unwrap())
            .unwrap();
    assert_eq!(objectives["classification"], "bootstrap-not-universal");
    assert_eq!(objectives["objectives"][0]["target"], 0.999);
    assert!(objectives["reviewAfterDays"].as_u64().unwrap() <= 30);

    let rules = std::fs::read_to_string(root.join("observability/prometheus-rules.yml")).unwrap();
    let rule_expressions = expressions_from_rules(&rules).unwrap();
    assert_eq!(rule_expressions.len(), 3);
    assert!(rules.contains("[5m]") && rules.contains("[1h]"));
    assert!(rules.contains("increase(") && rules.contains(">= 100"));
    assert_eq!(rules.matches("summary:").count(), rule_expressions.len());
    assert_eq!(rules.matches("runbook:").count(), rule_expressions.len());

    let dashboard: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("observability/grafana/smesh-a2a-overview.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(dashboard["schemaVersion"].as_u64().unwrap(), 39);
    let variables = dashboard["templating"]["list"].as_array().unwrap();
    assert!(variables.iter().any(|variable| {
        variable["name"] == "DS_PROMETHEUS" && variable["type"] == "datasource"
    }));

    let mut expressions = rule_expressions;
    let mut titles = BTreeSet::new();
    for panel in dashboard["panels"].as_array().unwrap() {
        titles.insert(panel["title"].as_str().unwrap());
        for target in panel["targets"].as_array().unwrap() {
            assert_eq!(target["datasource"]["type"], "prometheus");
            assert_eq!(target["datasource"]["uid"], "${DS_PROMETHEUS}");
            expressions.push(target["expr"].as_str().unwrap().to_owned());
        }
    }
    assert_eq!(
        titles,
        BTreeSet::from(["Edge availability", "Edge requests", "Audit projection"])
    );
    for expression in &expressions {
        validate_expression(expression).unwrap_or_else(|error| panic!("{error}"));
    }
    assert_eq!(expressions.len(), 8);

    let runbook = std::fs::read_to_string(root.join("docs/OBSERVABILITY_RUNBOOK.md")).unwrap();
    assert!(runbook.contains("missing telemetry is not evidence of zero errors"));
    assert!(runbook.contains("#18"));
}
