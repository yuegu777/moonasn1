///|
/// X.509 time primitives.
///
/// `UTCTime` carries a two-digit year and is interpreted per Y2K rules: years
/// `00..=49` are 2000-2049, years `50..=99` are 1950-1999. `GeneralizedTime`
/// carries an explicit four-digit year and is unambiguous.
pub enum X509Time {
  Utc(year~ : Int, month~ : Int, day~ : Int, hour~ : Int, minute~ : Int, second~ : Int)
  Generalized(year~ : Int, month~ : Int, day~ : Int, hour~ : Int, minute~ : Int, second~ : Int)
} derive(Debug, Eq)

///|
/// Parse a UTCTime body. RFC 5280 §4.1.2.5.3 requires the GMT form, so we
/// accept exactly `YYMMDDhhmmZ` (11 bytes) or `YYMMDDhhmmssZ` (13 bytes)
/// and reject offset variants. Returns `None` on malformed input.
pub fn parse_utctime(body : Bytes) -> X509Time? {
  let n = body.length()
  if n != 11 && n != 13 {
    return None
  }
  if body[n - 1].to_int() != 0x5A {
    // 'Z'
    return None
  }
  let year2 = read_int(body, 0, 2)
  let month = read_int(body, 2, 2)
  let day = read_int(body, 4, 2)
  let hour = read_int(body, 6, 2)
  let minute = read_int(body, 8, 2)
  let second = if n == 13 { read_int(body, 10, 2) } else { 0 }
  if !valid_date_fields(year2, month, day, hour, minute, second) {
    return None
  }
  // Y2K: per RFC 5280 §4.1.2.5.1
  let year = if year2 < 50 { 2000 + year2 } else { 1900 + year2 }
  Some(Utc(year~, month~, day~, hour~, minute~, second~))
}

///|
/// Parse a GeneralizedTime body. Accepts `YYYYMMDDhhmmZ` (13 bytes),
/// `YYYYMMDDhhmmssZ` (15 bytes), and the fractional form
/// `YYYYMMDDhhmmss[.f+]Z`; fractions are truncated to whole seconds.
pub fn parse_generalized_time(body : Bytes) -> X509Time? {
  let n = body.length()
  if n < 13 {
    return None
  }
  if body[n - 1].to_int() != 0x5A {
    // 'Z'
    return None
  }
  let has_seconds = n >= 15 && is_digit(body[12])
  let year = read_int(body, 0, 4)
  let month = read_int(body, 4, 2)
  let day = read_int(body, 6, 2)
  let hour = read_int(body, 8, 2)
  let minute = read_int(body, 10, 2)
  let second = if has_seconds { read_int(body, 12, 2) } else { 0 }
  if !valid_date_fields(year, month, day, hour, minute, second) {
    return None
  }
  // Everything between the seconds and the trailing 'Z' must be either
  // nothing or '.' followed by fraction digits.
  if has_seconds {
    let mut i = 14
    if i < n - 1 {
      if body[i].to_int() != 0x2E {
        // '.'
        return None
      }
      i = i + 1
      while i < n - 1 {
        if !is_digit(body[i]) {
          return None
        }
        i = i + 1
      }
    }
  } else if n != 13 {
    return None
  }
  Some(Generalized(year~, month~, day~, hour~, minute~, second~))
}

fn is_digit(b : Byte) -> Bool {
  let v = b.to_int()
  v >= 0x30 && v <= 0x39
}

///| Range-check the decoded date fields. `year` may be two- or four-digit;
/// `read_int` returns -1 for non-digits, which fails every check below.
fn valid_date_fields(
  year : Int,
  month : Int,
  day : Int,
  hour : Int,
  minute : Int,
  second : Int) -> Bool {
  year >= 0 &&
  month >= 1 &&
  month <= 12 &&
  day >= 1 &&
  day <= 31 &&
  hour <= 23 &&
  minute <= 59 &&
  second <= 59
}

///|
/// Format an `X509Time` as RFC 3339 (UTC), the format every JSON / HTTP
/// stack expects.
pub fn X509Time::to_rfc3339(self : X509Time) -> String {
  let pad2 = fn(n : Int) -> String {
    if n < 10 {
      "0" + n.to_string()
    } else {
      n.to_string()
    }
  }
  match self {
    Utc(year~, month~, day~, hour~, minute~, second~) =>
      year.to_string() +
      "-" +
      pad2(month) +
      "-" +
      pad2(day) +
      "T" +
      pad2(hour) +
      ":" +
      pad2(minute) +
      ":" +
      pad2(second) +
      "Z"
    Generalized(year~, month~, day~, hour~, minute~, second~) =>
      year.to_string() +
      "-" +
      pad2(month) +
      "-" +
      pad2(day) +
      "T" +
      pad2(hour) +
      ":" +
      pad2(minute) +
      ":" +
      pad2(second) +
      "Z"
  }
}

///|
fn read_int(b : Bytes, off : Int, n : Int) -> Int {
  let mut v = 0
  for i in 0..<n {
    let d = b[off + i].to_int()
    if d < 0x30 || d > 0x39 {
      return -1
    }
    v = v * 10 + (d - 0x30)
  }
  v
}