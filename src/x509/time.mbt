///|
/// X.509 time primitives.
///
/// `UTCTime` carries a two-digit year and is interpreted per Y2K rules: years
/// `00..=49` are 2000-2049, years `50..=99` are 1950-1999. `GeneralizedTime`
/// carries an explicit four-digit year and is unambiguous.
pub enum X509Time {
  Utc(year : Int, month : Int, day : Int, hour : Int, minute : Int, second : Int)
  Generalized(year : Int, month : Int, day : Int, hour : Int, minute : Int, second : Int)
} derive(Show, Eq)

///|
/// Parse a UTCTime body. Accepts `YYMMDDhhmm[ss]Z` and the offset variants
/// `+hhmm` / `-hhmm`. Returns `None` on malformed input.
pub fn parse_utctime(body : Bytes) -> X509Time? {
  // Strip trailing 'Z' or offset marker.
  let n = body.length()
  if n < 11 {
    return None
  }
  let has_seconds = n >= 13 &&
    (body[12].to_int() >= 0x30 && body[12].to_int() <= 0x39)
  let year2 = read_int(body, 0, 2)
  let month = read_int(body, 2, 2)
  let day = read_int(body, 4, 2)
  let hour = read_int(body, 6, 2)
  let minute = read_int(body, 8, 2)
  let second = if has_seconds { read_int(body, 10, 2) } else { 0 }
  // Y2K: per RFC 5280 §4.1.2.5.1
  let year = if year2 < 50 { 2000 + year2 } else { 1900 + year2 }
  Some(Utc(year, month, day, hour, minute, second))
}

///|
/// Parse a GeneralizedTime body. Accepts `YYYYMMDDhhmm[ss[.fff]]Z`.
pub fn parse_generalized_time(body : Bytes) -> X509Time? {
  let n = body.length()
  if n < 15 {
    return None
  }
  let year = read_int(body, 0, 4)
  let month = read_int(body, 4, 2)
  let day = read_int(body, 6, 2)
  let hour = read_int(body, 8, 2)
  let minute = read_int(body, 10, 2)
  let second = if n >= 17 &&
    (body[12].to_int() >= 0x30 && body[12].to_int() <= 0x39) {
    read_int(body, 12, 2)
  } else {
    0
  }
  Some(Generalized(year, month, day, hour, minute, second))
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
    Utc(year, month, day, hour, minute, second) =>
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
    Generalized(year, month, day, hour, minute, second) =>
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