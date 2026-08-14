///|
test "parse_utctime YY>=50 is 19xx" {
  // 23 06 15 12 30 45 Z
  let buf = Bytes::from_array([
    b'\x32', b'\x33', b'\x06', b'\x15', b'\x12', b'\x30', b'\x45', b'\x5A',
  ])
  match @x509_time.parse_utctime(buf) {
    Some(@x509_time.Utc(year, 6, 15, 12, 30, 45)) => assert_eq(year, 1923)
    other => fail("expected UTC 1923, got " + other.to_string())
  }
}

///|
test "parse_utctime YY<50 is 20xx" {
  // 25 01 02 03 04 05 Z
  let buf = Bytes::from_array([
    b'\x32', b'\x35', b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x5A',
  ])
  match @x509_time.parse_utctime(buf) {
    Some(@x509_time.Utc(year, 1, 2, 3, 4, 5)) => assert_eq(year, 2025)
    other => fail("expected UTC 2025, got " + other.to_string())
  }
}

///|
test "parse_utctime without seconds" {
  // YY MM DD hh mm Z (11 bytes)
  let buf = Bytes::from_array([
    b'\x32', b'\x35', b'\x01', b'\x02', b'\x03', b'\x04', b'\x5A',
  ])
  match @x509_time.parse_utctime(buf) {
    Some(@x509_time.Utc(_, 1, 2, 3, 4, 0)) => ()
    other => fail("expected UTC, got " + other.to_string())
  }
}

///|
test "parse_generalized_time with explicit year" {
  // YYYY MM DD hh mm ss Z
  let buf = Bytes::from_array([
    b'\x32', b'\x30', b'\x32', b'\x36', b'\x01', b'\x02', b'\x03', b'\x04',
    b'\x05', b'\x06', b'\x5A',
  ])
  match @x509_time.parse_generalized_time(buf) {
    Some(@x509_time.Generalized(2026, 1, 2, 3, 4, 6)) => ()
    other => fail("expected Generalized, got " + other.to_string())
  }
}

///|
test "X509Time::to_rfc3339 UTC" {
  let t = @x509_time.Utc(2026, 1, 2, 3, 4, 6)
  assert_eq(t.to_rfc3339(), "2026-01-02T03:04:06Z")
}

///|
test "X509Time::to_rfc3339 Generalized" {
  let t = @x509_time.Generalized(2030, 12, 31, 23, 59, 59)
  assert_eq(t.to_rfc3339(), "2030-12-31T23:59:59Z")
}