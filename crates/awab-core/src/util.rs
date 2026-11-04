//! Small shared helpers: duration parsing and calendar math (std-only).

use std::time::{SystemTime, UNIX_EPOCH};

/// Parse a duration string like `30s`, `5m`, `2h`, `1d` into seconds.
pub fn parse_duration_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let split = s.find(|c: char| c.is_alphabetic())?;
    let (num, unit) = s.split_at(split);
    let n: i64 = num.trim().parse().ok()?;
    Some(match unit {
        "s" | "sec" | "secs" => n,
        "m" | "min" | "mins" => n * 60,
        "h" | "hr" | "hrs" => n * 3600,
        "d" | "day" | "days" => n * 86400,
        _ => return None,
    })
}

/// Days since the Unix epoch for a civil (proleptic Gregorian) date.
/// From Howard Hinnant's `days_from_civil`.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`]: returns `(year, month, day)`.
pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Unix epoch seconds for a UTC date-time.
pub fn epoch_secs(y: i64, mon: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    days_from_civil(y, mon, d) * 86400 + h * 3600 + mi * 60 + s
}

/// The current UTC year (used to fill in year-less syslog timestamps).
pub fn current_year() -> i64 {
    civil_from_days(now_epoch().div_euclid(86400)).0
}

/// Current time as Unix epoch seconds (UTC).
pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Format Unix epoch seconds as `YYYY-MM-DD HH:MM:SS UTC`.
pub fn format_utc(secs: i64) -> String {
    let (y, mon, d) = civil_from_days(secs.div_euclid(86400));
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{mon:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

/// Map a 3-letter English month abbreviation to its number (1-12).
pub fn month_num(abbr: &str) -> Option<i64> {
    Some(match abbr {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration_secs("60s"), Some(60));
        assert_eq!(parse_duration_secs("5m"), Some(300));
        assert_eq!(parse_duration_secs("2h"), Some(7200));
        assert_eq!(parse_duration_secs("1d"), Some(86400));
        assert_eq!(parse_duration_secs("x"), None);
    }

    #[test]
    fn civil_roundtrip() {
        // 2026-11-04 is a known date; round-trip through day count.
        let days = days_from_civil(2026, 11, 4);
        assert_eq!(civil_from_days(days), (2026, 11, 4));
        // Unix epoch day 0 is 1970-01-01.
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }
}
