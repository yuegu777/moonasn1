///|
test "Reader::new has zero cursor" {
  let buf = Bytes::from_array([b'\x01', b'\x02', b'\x03'])
  let r = @asn1_reader.Reader::new(buf)
  assert_eq(r.pos, 0)
  assert_eq(r.remaining(), 3)
  assert_eq(r.eof(), false)
}

///|
test "Reader::read_byte advances the cursor" {
  let buf = Bytes::from_array([b'\x01', b'\x02', b'\x03'])
  let r = @asn1_reader.Reader::new(buf)
  assert_eq(r.read_byte(), Ok(b'\x01'))
  assert_eq(r.read_byte(), Ok(b'\x02'))
  assert_eq(r.read_byte(), Ok(b'\x03'))
  assert_eq(r.read_byte(), Err(@asn1_reader.Truncated))
  assert_eq(r.eof(), true)
}

///|
test "Reader::read_bytes respects bounds" {
  let buf = Bytes::from_array([b'\x01', b'\x02', b'\x03'])
  let r = @asn1_reader.Reader::new(buf)
  match r.read_bytes(2) {
    Ok(b) => assert_eq(b, Bytes::from_array([b'\x01', b'\x02']))
    Err(_) => fail("expected Ok")
  }
  match r.read_bytes(5) {
    Err(@asn1_reader.Truncated) => ()
    _ => fail("expected Truncated")
  }
}

///|
test "Reader::enter rejects excessive depth" {
  let buf = Bytes::from_array([])
  let r = @asn1_reader.Reader::new(buf, max_depth=2)
  assert_eq(r.enter(), Ok(()))
  assert_eq(r.enter(), Ok(()))
  assert_eq(r.enter(), Err(@asn1_reader.LimitExceeded("depth=3")))
  ignore(r.leave())
}

///|
test "Reader::peek_byte does not advance" {
  let buf = Bytes::from_array([b'\xAA'])
  let r = @asn1_reader.Reader::new(buf)
  assert_eq(r.peek_byte(), Ok(b'\xAA'))
  assert_eq(r.pos, 0)
  assert_eq(r.read_byte(), Ok(b'\xAA'))
}