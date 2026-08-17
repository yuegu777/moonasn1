///|
test "decode_element parses a BOOLEAN TRUE" {
  // DER: 01 01 FF
  let buf = Bytes::from_array([b'\x01', b'\x01', b'\xff'])
  match decode_element(buf) {
    Ok(Boolean(true)) => ()
    _ => fail("expected Boolean(true)")
  }
}

///|
test "decode_element parses an INTEGER 42" {
  // DER: 02 01 2A
  let buf = Bytes::from_array([b'\x02', b'\x01', b'\x2A'])
  match decode_element(buf) {
    Ok(Integer(b)) => assert_eq(b, Bytes::from_array([b'\x2A']))
    _ => fail("expected Integer")
  }
}

///|
test "decode_element parses a NULL" {
  // DER: 05 00
  let buf = Bytes::from_array([b'\x05', b'\x00'])
  match decode_element(buf) {
    Ok(Null) => ()
    _ => fail("expected Null")
  }
}

///|
test "decode_element rejects indefinite length" {
  // 30 80 (indefinite SEQUENCE) is invalid DER.
  let buf = Bytes::from_array([b'\x30', b'\x80'])
  match decode_element(buf) {
    Err(MalformedLength) => ()
    _ => fail("expected MalformedLength")
  }
}

///|
test "decode_element rejects truncated input" {
  let buf = Bytes::from_array([b'\x02', b'\x05', b'\x01'])
  match decode_element(buf) {
    Err(Truncated) => ()
    _ => fail("expected Truncated")
  }
}

///|
test "decode_element parses an OID" {
  // OID 1.2.840.113549 = 2A 86 48 86 F7 0D
  let buf = Bytes::from_array([b'\x06', b'\x06', b'\x2A', b'\x86', b'\x48', b'\x86', b'\xF7', b'\x0D'])
  match decode_element(buf) {
    Ok(ObjectIdentifier(arcs)) => {
      let as_int : Array[Int] = []
      for a in arcs {
        as_int.push(a.reinterpret_as_int())
      }
      assert_eq(as_int, [1, 2, 840, 113549])
    }
    _ => fail("expected ObjectIdentifier")
  }
}

///|
test "decode_element parses an empty SEQUENCE" {
  // DER: 30 00
  let buf = Bytes::from_array([b'\x30', b'\x00'])
  match decode_element(buf) {
    Ok(Sequence(items)) => assert_eq(items.length(), 0)
    _ => fail("expected Sequence")
  }
}
