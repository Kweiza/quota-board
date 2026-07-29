use crate::model::UsageWindow;
use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParseError {
    /// The response is not recognizable as a usage payload. See docs/design.md §5.5.
    /// A completely alien shape with no trace of five_hour/seven_day/limits.
    #[error("unrecognized response shape")]
    UnknownShape,
    /// The fields were present (not null) but not a single value could be read.
    /// This must stay distinct from "no windows to report" (a legitimate empty
    /// success) — disguising it as an empty success would let the screen freeze
    /// silently blank when the endpoint changes shape, with nobody noticing.
    #[error("usage fields were present but could not be parsed")]
    UnreadableSource,
}

/// One ISO-8601 string to UTC. None on failure — the caller drops that window.
fn parse_reset(v: &Value) -> Option<DateTime<Utc>> {
    v.as_str()?.parse::<DateTime<Utc>>().ok()
}

/// A 0-100 percentage. Accepts both `utilization` (window objects) and
/// `percent` (limits entries).
fn parse_percent(v: &Value) -> Option<f64> {
    v.as_f64().filter(|p| p.is_finite() && *p >= 0.0)
}

/// Whether the key exists with a non-null value. Absent or null means "not
/// reported", which is normal; present-but-unparseable must be treated
/// differently (see I1) — this distinction is what that relies on.
fn is_present_non_null(root: &Value, key: &str) -> bool {
    root.get(key).is_some_and(|v| !v.is_null())
}

fn flat_window(root: &Value, key: &str, window_id: &str, label: &str) -> Option<UsageWindow> {
    let obj = root.get(key)?;
    if obj.is_null() {
        return None;
    }
    Some(UsageWindow {
        window_id: window_id.to_string(),
        label: label.to_string(),
        percent: parse_percent(obj.get("utilization")?)?,
        resets_at: parse_reset(obj.get("resets_at")?)?,
        scope: None,
    })
}

/// Whether one `limits[]` element is a weekly limit — `kind: "weekly_scoped"`
/// or `group: "weekly"`.
fn is_weekly_entry(e: &Value) -> bool {
    e.get("kind").and_then(Value::as_str) == Some("weekly_scoped")
        || e.get("group").and_then(Value::as_str) == Some("weekly")
}

/// One weekly element of `limits[]` as a window. If any field fails to read,
/// only this element is dropped — it never drags down other elements or the
/// 5h window.
fn parse_weekly_entry(e: &Value) -> Option<UsageWindow> {
    let model = e
        .get("scope")
        .and_then(|s| s.get("model"))
        .and_then(|m| m.get("display_name"))
        .and_then(Value::as_str);
    Some(UsageWindow {
        window_id: match model {
            Some(m) => format!("weekly:{m}"),
            None => "seven_day".to_string(),
        },
        label: match model {
            Some(m) => format!("weekly ({m})"),
            None => "7d".to_string(),
        },
        percent: parse_percent(e.get("percent")?)?,
        resets_at: parse_reset(e.get("resets_at")?)?,
        scope: model.map(str::to_string),
    })
}

/// The weekly windows extracted from `limits[]`, plus whether any weekly
/// element was present at all (regardless of whether it parsed). That flag is
/// what decides "may we fall back to the flat seven_day" — docs/design.md §5.3, C1.
struct WeeklyLimits {
    windows: Vec<UsageWindow>,
    /// If this is true but `windows` is empty, weekly entries were present but
    /// none could be read; in that case we do not fall back to the flat
    /// seven_day and treat the result as unreadable instead.
    matched_any: bool,
}

/// Extract the weekly windows from limits[]. The first-priority path of
/// docs/design.md §5.3.
fn scoped_weekly_windows(root: &Value) -> WeeklyLimits {
    let Some(limits) = root.get("limits").and_then(Value::as_array) else {
        return WeeklyLimits {
            windows: Vec::new(),
            matched_any: false,
        };
    };
    let matching: Vec<&Value> = limits.iter().filter(|e| is_weekly_entry(e)).collect();
    let matched_any = !matching.is_empty();
    let mut windows: Vec<UsageWindow> =
        matching.into_iter().filter_map(parse_weekly_entry).collect();

    // I3: the endpoint does not guarantee the array order of limits[] — sort by
    // window_id so the output is a function of content alone, not of the
    // response's array positions.
    windows.sort_by(|a, b| a.window_id.cmp(&b.window_id));
    // I2: window_id is documented as a stable identifier — collapse duplicate
    // elements pointing at the same model. The sort is stable, so among equal
    // window_ids the element that came first in the original array survives.
    windows.dedup_by(|a, b| a.window_id == b.window_id);

    WeeklyLimits {
        windows,
        matched_any,
    }
}

/// One response body to a normalized list of windows.
///
/// The normative order from docs/design.md §5.3:
///   1. Read weekly_scoped/weekly from limits[] first
///   2. Fall back to the flat `seven_day` only when limits[] contains no weekly
///      element at all (elements that were present but unreadable are not a
///      fallback trigger — C1)
///   3. If neither exists, produce no weekly window (the caller displays
///      "weekly not reported")
pub fn parse_usage(raw: &Value) -> Result<Vec<UsageWindow>, ParseError> {
    let five_hour = flat_window(raw, "five_hour", "five_hour", "5h");
    // The five_hour key was present and non-null but failed to parse — that is
    // not "not reported".
    let five_hour_unreadable = five_hour.is_none() && is_present_non_null(raw, "five_hour");

    let weekly_limits = scoped_weekly_windows(raw);
    let mut weekly_unreadable = false;
    let weekly = if weekly_limits.matched_any {
        // C1: if limits[] had weekly elements, do not fall back to the flat
        // seven_day — not even when none of them could be read. Mark the result
        // unreadable instead.
        if weekly_limits.windows.is_empty() {
            weekly_unreadable = true;
        }
        weekly_limits.windows
    } else if let Some(w) = flat_window(raw, "seven_day", "seven_day", "7d") {
        vec![w]
    } else {
        if is_present_non_null(raw, "seven_day") {
            weekly_unreadable = true;
        }
        Vec::new()
    };

    let mut out = Vec::with_capacity(1 + weekly.len());
    out.extend(five_hour);
    out.extend(weekly);

    if out.is_empty() {
        // I1: when fields were present but nothing could be read, do not
        // disguise it as an empty success — it must stay distinct from
        // "no windows to report".
        if five_hour_unreadable || weekly_unreadable {
            return Err(ParseError::UnreadableSource);
        }
        // Without the five_hour key at all, this response is not a usage payload.
        if raw.get("five_hour").is_none() {
            return Err(ParseError::UnknownShape);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> serde_json::Value {
        let path = format!("{}/tests/fixtures/{}.json", env!("CARGO_MANIFEST_DIR"), name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"));
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn flat_seven_day_produces_two_windows() {
        let w = parse_usage(&fixture("both_windows")).unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].window_id, "five_hour");
        assert_eq!(w[0].percent, 28.0);
        assert_eq!(w[1].window_id, "seven_day");
        assert_eq!(w[1].percent, 41.0);
        assert_eq!(w[1].scope, None);
    }

    /// docs/design.md §5.3: read limits[] first. Weekly information must not be
    /// lost just because the flat seven_day is null.
    #[test]
    fn weekly_scoped_produces_one_window_per_model() {
        let w = parse_usage(&fixture("weekly_scoped")).unwrap();
        assert_eq!(w.len(), 3, "one 5h window plus two per-model weekly windows");
        assert_eq!(w[0].window_id, "five_hour");
        assert_eq!(w[1].window_id, "weekly:Opus");
        assert_eq!(w[1].label, "weekly (Opus)");
        assert_eq!(w[1].percent, 31.0);
        assert_eq!(w[1].scope.as_deref(), Some("Opus"));
        assert_eq!(w[2].window_id, "weekly:Sonnet");
        assert_eq!(w[2].percent, 12.0);
    }

    /// limits[] beats the flat seven_day — when both exist, only limits[] is used.
    #[test]
    fn limits_take_precedence_over_flat_seven_day() {
        let mut v = fixture("both_windows");
        v["limits"] = serde_json::json!([
            { "kind": "weekly_scoped", "group": "weekly", "percent": 55,
              "resets_at": "2026-08-02T00:00:00Z",
              "scope": { "model": { "display_name": "Opus" } } }
        ]);
        let w = parse_usage(&v).unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!(w[1].window_id, "weekly:Opus");
        assert_eq!(w[1].percent, 55.0, "must be 55 from limits[], not the flat 41");
    }

    /// With no weekly data, return only the 5h window. Never invent a 0% weekly window.
    #[test]
    fn missing_weekly_yields_only_the_five_hour_window() {
        let w = parse_usage(&fixture("no_weekly")).unwrap();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].window_id, "five_hour");
    }

    /// docs/design.md §5.5: unknown fields are ignored. Parsing must not break.
    #[test]
    fn unknown_fields_are_ignored() {
        let w = parse_usage(&fixture("unknown_fields")).unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].percent, 28.0);
        assert_eq!(w[1].window_id, "weekly:Opus");
    }

    /// docs/design.md §5.5: an unrecognizable shape is UnknownShape, not 0%.
    #[test]
    fn alien_shape_is_an_error_not_zero() {
        match parse_usage(&fixture("alien_shape")) {
            Err(ParseError::UnknownShape) => {}
            other => panic!("expected UnknownShape, got {other:?}"),
        }
    }

    /// Never fabricate a 0 percent from any input.
    #[test]
    fn never_fabricates_a_zero_percent_window() {
        for name in ["both_windows", "weekly_scoped", "no_weekly", "unknown_fields"] {
            for w in parse_usage(&fixture(name)).unwrap() {
                assert!(w.percent > 0.0, "window {} in {name} was fabricated as 0%", w.window_id);
            }
        }
    }

    #[test]
    fn malformed_reset_timestamp_drops_that_window_only() {
        let mut v = fixture("both_windows");
        v["seven_day"]["resets_at"] = serde_json::json!("nonsense");
        let w = parse_usage(&v).unwrap();
        assert_eq!(w.len(), 1, "5h survives and only 7d is dropped");
        assert_eq!(w[0].window_id, "five_hour");
    }

    /// C1: limits[] had a weekly element but it was unreadable (percent is a
    /// string). Falling back to the flat seven_day (41%) would display a
    /// confidently wrong number.
    #[test]
    fn unreadable_weekly_limit_does_not_fall_back_to_flat_seven_day() {
        let v = serde_json::json!({
            "five_hour": { "utilization": 28, "resets_at": "2026-07-29T15:00:00Z" },
            "seven_day": { "utilization": 41, "resets_at": "2026-08-02T00:00:00Z" },
            "limits": [
                { "kind": "weekly_scoped", "group": "weekly", "percent": "31",
                  "resets_at": "2026-08-02T00:00:00Z",
                  "scope": { "model": { "display_name": "Opus" } } }
            ]
        });
        let w = parse_usage(&v).unwrap();
        assert_eq!(
            w.len(),
            1,
            "a failed weekly element in limits[] must not fall back to the flat seven_day 41%"
        );
        assert_eq!(w[0].window_id, "five_hour");
    }

    /// I1: five_hour and the only weekly element in limits[] are both present
    /// but both unparseable — this must not be disguised as an empty success
    /// (Ok(vec![])).
    #[test]
    fn unreadable_sources_yield_an_error_not_an_empty_success() {
        let v = serde_json::json!({
            "five_hour": { "utilization": "not-a-number", "resets_at": "2026-07-29T15:00:00Z" },
            "seven_day": null,
            "limits": [
                { "kind": "weekly_scoped", "group": "weekly", "percent": "31",
                  "resets_at": "2026-08-02T00:00:00Z",
                  "scope": { "model": { "display_name": "Opus" } } }
            ]
        });
        match parse_usage(&v) {
            Err(ParseError::UnreadableSource) => {}
            other => panic!("expected UnreadableSource, got {other:?} — an empty success is wrong"),
        }
    }

    /// I2: duplicate limits[] elements pointing at the same model must collapse
    /// into one window_id — window_id is the stable identifier used for UI keys
    /// and per-window state.
    #[test]
    fn duplicate_weekly_model_entries_are_deduped_by_window_id() {
        let mut v = fixture("weekly_scoped");
        v["limits"].as_array_mut().unwrap().push(serde_json::json!(
            { "kind": "weekly_scoped", "group": "weekly", "percent": 99,
              "resets_at": "2026-08-02T00:00:00Z",
              "scope": { "model": { "display_name": "Opus" } } }
        ));
        let w = parse_usage(&v).unwrap();
        let opus_windows: Vec<_> = w.iter().filter(|win| win.window_id == "weekly:Opus").collect();
        assert_eq!(opus_windows.len(), 1, "identical window_ids must collapse into one");
        assert_eq!(
            opus_windows[0].percent,
            31.0,
            "on duplicates, deterministically keep the element that came first in the array"
        );
    }

    /// I3: the endpoint does not guarantee the array order of limits[] — output
    /// order must be a function of content (window_id), not array position.
    #[test]
    fn weekly_window_order_does_not_depend_on_limits_array_order() {
        let v = fixture("weekly_scoped");
        let mut reversed = v.clone();
        let mut limits = reversed["limits"].as_array().unwrap().clone();
        limits.reverse();
        reversed["limits"] = serde_json::json!(limits);

        let original = parse_usage(&v).unwrap();
        let flipped = parse_usage(&reversed).unwrap();
        assert_eq!(original, flipped, "reordering limits[] must not change the output");
        assert_eq!(flipped[1].window_id, "weekly:Opus");
        assert_eq!(flipped[2].window_id, "weekly:Sonnet");
    }

    /// I4: the real response shape measured in docs/research/usage-endpoint.md.
    /// The session limit is not weekly and is therefore excluded, and both the
    /// offset-bearing timestamp and the actually observed model name "Fable"
    /// must parse correctly.
    #[test]
    fn spike_observed_response_parses_five_hour_and_fable_weekly_only() {
        let w = parse_usage(&fixture("spike_observed")).unwrap();
        assert_eq!(
            w.len(),
            2,
            "the session limit is not weekly, so only 5h + the Fable weekly window remain"
        );
        assert_eq!(w[0].window_id, "five_hour");
        assert_eq!(w[0].percent, 7.0);
        assert_eq!(w[1].window_id, "weekly:Fable");
        assert_eq!(w[1].percent, 39.0);
        assert_eq!(w[1].scope.as_deref(), Some("Fable"));
    }
}
