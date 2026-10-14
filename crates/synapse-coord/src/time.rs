//! UTC timestamps exactly as `crumb.c` writes and reads them (`now_iso`, `parse_iso`).

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `now_iso`: `%Y-%m-%dT%H:%M:%SZ` (UTC) for a Unix time in seconds.
pub fn iso(t: i64) -> String {
    let (y, m, d) = civil_from_days(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        s / 3600,
        (s / 60) % 60,
        s % 60
    )
}

/// One `%d` conversion of `sscanf`: skip whitespace, optional sign, at least one digit.
fn scan_int(s: &[u8], i: &mut usize) -> Option<i64> {
    while *i < s.len() && matches!(s[*i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        *i += 1;
    }
    let mut neg = false;
    if *i < s.len() && (s[*i] == b'-' || s[*i] == b'+') {
        neg = s[*i] == b'-';
        *i += 1;
    }
    let start = *i;
    let mut v: i64 = 0;
    while *i < s.len() && s[*i].is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add(i64::from(s[*i] - b'0'));
        *i += 1;
    }
    if *i == start {
        return None;
    }
    Some(if neg { -v } else { v })
}

/// `parse_iso`: `sscanf("%d-%d-%dT%d:%d:%d")` then `timegm` (which normalizes out-of-range
/// fields). Returns -1 on failure, as the C tool does; callers treat any negative as expired.
pub fn parse_iso(s: Option<&[u8]>) -> i64 {
    let Some(s) = s else { return -1 };
    let mut i = 0;
    let mut f = [0i64; 6];
    let seps = b"--T::";
    for k in 0..6 {
        match scan_int(s, &mut i) {
            Some(v) => f[k] = v,
            None => return -1,
        }
        if k < 5 {
            if s.get(i) != Some(&seps[k]) {
                return -1;
            }
            i += 1;
        }
    }
    let [y, mo, d, h, mi, se] = f;
    let m0 = mo - 1;
    let y = y + m0.div_euclid(12);
    let m = m0.rem_euclid(12) + 1;
    let days = days_from_civil(y, m, 1) + d - 1;
    days * 86_400 + h * 3600 + mi * 60 + se
}

/// Seconds since the Unix epoch from the system clock (C `time(NULL)`).
pub fn system_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_round_trip() {
        for t in [0i64, 951_782_400, 1_760_400_000, 4_102_444_799] {
            assert_eq!(parse_iso(Some(iso(t).as_bytes())), t);
        }
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            parse_iso(Some(b"2026-13-01T00:00:00Z")),
            parse_iso(Some(b"2027-01-01T00:00:00Z"))
        );
        assert_eq!(parse_iso(Some(b"garbage")), -1);
        assert_eq!(parse_iso(None), -1);
    }
}
