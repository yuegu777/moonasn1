///|
test "parse_utctime YY>=50 is 19xx" {
  // "990615123045Z" -> 1999-06-15 12:30:45 UTC
  let buf = Bytes::from_array([
    b'9', b'9', b'0', b'6', b'1', b'5', b'1', b'2', b'3', b'0', b'4', b'5', b'Z',
  ])
  match parse_utctime(buf) {
    Some(Utc(year~, month~, day~, hour~, minute~, second~)) => {
      assert_eq(year, 1999)
      assert_eq(month, 6)
      assert_eq(day, 15)
      assert_eq(hour, 12)
      assert_eq(minute, 30)
      assert_eq(second, 45)
    }
    _ => fail("expected Utc")
  }
}

///|
test "parse_utctime YY<50 is 20xx" {
  // "250102030405Z" -> 2025-01-02 03:04:05 UTC
  let buf = Bytes::from_array([
    b'2', b'5', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'0', b'5', b'Z',
  ])
  match parse_utctime(buf) {
    Some(Utc(year~, month~, ..)) => {
      assert_eq(year, 2025)
      assert_eq(month, 1)
    }
    _ => fail("expected Utc")
  }
}

///|
test "parse_utctime without seconds" {
  // "2501020304Z" -> 2025-01-02 03:04:00 UTC
  let buf = Bytes::from_array([
    b'2', b'5', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'Z',
  ])
  match parse_utctime(buf) {
    Some(Utc(second~, ..)) => assert_eq(second, 0)
    _ => fail("expected Utc")
  }
}

///|
test "parse_utctime rejects offset form" {
  // RFC 5280 requires the Z form; "+0900" must be rejected.
  let buf = Bytes::from_array([
    b'2', b'5', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'0', b'5', b'+', b'0', b'9', b'0', b'0',
  ])
  assert_eq(parse_utctime(buf), None)
}

///|
test "parse_utctime rejects out-of-range second" {
  // "61" seconds is not a valid time.
  let buf = Bytes::from_array([
    b'2', b'5', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'6', b'1', b'Z',
  ])
  assert_eq(parse_utctime(buf), None)
}

///|
test "parse_generalized_time with explicit year" {
  // "20260102030406Z" -> 2026-01-02 03:04:06 UTC
  let buf = Bytes::from_array([
    b'2', b'0', b'2', b'6', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'0', b'6', b'Z',
  ])
  match parse_generalized_time(buf) {
    Some(Generalized(year~, month~, day~, second~, ..)) => {
      assert_eq(year, 2026)
      assert_eq(month, 1)
      assert_eq(day, 2)
      assert_eq(second, 6)
    }
    _ => fail("expected Generalized")
  }
}

///|
test "parse_generalized_time truncates fraction" {
  // "20260102030406.5Z" -> second stays 6, fraction truncated.
  let buf = Bytes::from_array([
    b'2', b'0', b'2', b'6', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'0', b'6', b'.', b'5', b'Z',
  ])
  match parse_generalized_time(buf) {
    Some(Generalized(year~, second~, ..)) => {
      assert_eq(year, 2026)
      assert_eq(second, 6)
    }
    _ => fail("expected Generalized")
  }
}

///|
test "parse_generalized_time without seconds" {
  // "202601020304Z" -> second defaults to 0.
  let buf = Bytes::from_array([
    b'2', b'0', b'2', b'6', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'Z',
  ])
  match parse_generalized_time(buf) {
    Some(Generalized(second~, ..)) => assert_eq(second, 0)
    _ => fail("expected Generalized")
  }
}

///|
test "X509Time::to_rfc3339 UTC" {
  let t = Utc(year=2026, month=1, day=2, hour=3, minute=4, second=6)
  assert_eq(t.to_rfc3339(), "2026-01-02T03:04:06Z")
}

///|
test "X509Time::to_rfc3339 Generalized" {
  let t = Generalized(year=2030, month=12, day=31, hour=23, minute=59, second=59)
  assert_eq(t.to_rfc3339(), "2030-12-31T23:59:59Z")
}
