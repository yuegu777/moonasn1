///|
test "decode_element parses a BOOLEAN TRUE" {
  // DER: 01 01 FF
  let buf = Bytes::from_array([b'\x01', b'\x01', b'\xff'])
  match @asn1_decode.decode_element(buf) {
    Ok(@asn1.Boolean(true)) => ()
    other => fail("expected Boolean(true), got " + other.to_string())
  }
}

///|
test "decode_element parses an INTEGER 42" {
  // DER: 02 01 2A
  let buf = Bytes::from_array([b'\x02', b'\x01', b'\x2A'])
  match @asn1_decode.decode_element(buf) {
    Ok(@asn1.Integer(b)) => assert_eq(b, Bytes::from_array([b'\x2A']))
    other => fail("expected Integer, got " + other.to_string())
  }
}

///|
test "decode_element parses a NULL" {
  // DER: 05 00
  let buf = Bytes::from_array([b'\x05', b'\x00'])
  match @asn1_decode.decode_element(buf) {
    Ok(@asn1.Null) => ()
    other => fail("expected Null, got " + other.to_string())
  }
}

///|
test "decode_element rejects indefinite length" {
  // 30 80 (indefinite SEQUENCE) is invalid DER.
  let buf = Bytes::from_array([b'\x30', b'\x80'])
  match @asn1_decode.decode_element(buf) {
    Err(@asn1_reader.MalformedLength) => ()
    _ => fail("expected MalformedLength")
  }
}

///|
test "decode_element rejects truncated input" {
  let buf = Bytes::from_array([b'\x02', b'\x05', b'\x01'])
  match @asn1_decode.decode_element(buf) {
    Err(@asn1_reader.Truncated) => ()
    _ => fail("expected Truncated")
  }
}

///|
test "decode_element parses an OID" {
  // OID 1.2.840.113549 = 2A 86 48 86 F7 0D
  let buf = Bytes::from_array([b'\x06', b'\x06', b'\x2A', b'\x86', b'\x48', b'\x86', b'\xF7', b'\x0D'])
  match @asn1_decode.decode_element(buf) {
    Ok(@asn1.ObjectIdentifier(arcs)) => {
      let as_int : Array[Int] = []
      for a in arcs {
        as_int.push(a.to_int())
      }
      assert_eq(as_int, [1, 2, 840, 113549])
    }
    other => fail("expected ObjectIdentifier, got " + other.to_string())
  }
}

///|
test "decode_element parses an empty SEQUENCE" {
  // DER: 30 00
  let buf = Bytes::from_array([b'\x30', b'\x00'])
  match @asn1_decode.decode_element(buf) {
    Ok(@asn1.Sequence(items)) => assert_eq(items.length(), 0)
    other => fail("expected Sequence, got " + other.to_string())
  }
}