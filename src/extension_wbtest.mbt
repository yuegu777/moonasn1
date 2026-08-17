///|
test "parse_extensions decodes a keyUsage extension" {
  // Extensions ::= SEQUENCE { Extension ::= SEQUENCE {
  //   OID 2.5.29.15, critical TRUE, OCTET STRING { BIT STRING 02 84 } } }
  // BIT STRING 0x84 = digitalSignature (bit 0) + keyCertSign (bit 5).
  let container = Bytes::from_array([
    b'\x30', b'\x10', b'\x30', b'\x0E', b'\x06', b'\x03', b'\x55', b'\x1D', b'\x0F', b'\x01',
    b'\x01', b'\xFF', b'\x04', b'\x04', b'\x03', b'\x02', b'\x02', b'\x84',
  ])
  let exts = parse_extensions(container)
  assert_eq(exts.length(), 1)
  assert_eq(exts[0].oid, "2.5.29.15")
  assert_eq(exts[0].name, "keyUsage")
  assert_eq(exts[0].critical, true)
  let ku = match parse_key_usage(exts[0].value) {
    Some(ku) => ku
    None => fail("expected KeyUsage")
  }
  assert_eq(ku.digital_signature, true)
  assert_eq(ku.key_cert_sign, true)
  assert_eq(ku.key_encipherment, false)
  assert_eq(ku.decipher_only, false)
}

///|
test "find_extension locates by dotted OID" {
  // A non-critical basicConstraints: CA:TRUE, no pathlen.
  let container = Bytes::from_array([
    b'\x30', b'\x0E', b'\x30', b'\x0C', b'\x06', b'\x03', b'\x55', b'\x1D', b'\x13', b'\x04',
    b'\x05', b'\x30', b'\x03', b'\x01', b'\x01', b'\xFF',
  ])
  let exts = parse_extensions(container)
  let bc_ext = match find_extension(exts, "2.5.29.19") {
    Some(e) => e
    None => fail("expected basicConstraints extension")
  }
  assert_eq(bc_ext.critical, false)
  assert_eq(find_extension(exts, "2.5.29.17"), None)
  let bc = match parse_basic_constraints(bc_ext.value) {
    Some(bc) => bc
    None => fail("expected BasicConstraints")
  }
  assert_eq(bc.is_ca, true)
  assert_eq(bc.path_len, None)
  assert_eq(bc.to_display(), "CA:TRUE")
}

///|
test "parse_basic_constraints variants" {
  // Empty SEQUENCE: CA:FALSE, no pathlen.
  let empty = Bytes::from_array([b'\x30', b'\x00'])
  let bc = match parse_basic_constraints(empty) {
    Some(bc) => bc
    None => fail("expected BasicConstraints")
  }
  assert_eq(bc.is_ca, false)
  assert_eq(bc.path_len, None)
  assert_eq(bc.to_display(), "CA:FALSE")
  // CA:TRUE, pathlen 2.
  let ca = Bytes::from_array([
    b'\x30', b'\x06', b'\x01', b'\x01', b'\xFF', b'\x02', b'\x01', b'\x02',
  ])
  let bc2 = match parse_basic_constraints(ca) {
    Some(bc) => bc
    None => fail("expected BasicConstraints")
  }
  assert_eq(bc2.is_ca, true)
  assert_eq(bc2.path_len, Some(2))
  assert_eq(bc2.to_display(), "CA:TRUE, pathlen:2")
  // Not a SEQUENCE at all.
  let bad = Bytes::from_array([b'\x05', b'\x00'])
  assert_eq(parse_basic_constraints(bad), None)
}

///|
test "parse_general_names covers the common tags" {
  // SEQUENCE { [2] "a.io", [1] "x@y.z", [7] 1.2.3.4, [8] ..., [4] {} }
  let inner = Bytes::from_array([
    b'\x30', b'\x1A', b'\x82', b'\x04', b'\x61', b'\x2E', b'\x69', b'\x6F', b'\x81', b'\x05',
    b'\x78', b'\x40', b'\x79', b'\x2E', b'\x7A', b'\x87', b'\x04', b'\x01', b'\x02', b'\x03',
    b'\x04', b'\x88', b'\x01', b'\xFF', b'\xA4', b'\x02', b'\x30', b'\x00',
  ])
  let names = match parse_general_names(inner) {
    Some(n) => n
    None => fail("expected GeneralNames")
  }
  assert_eq(names.length(), 5)
  assert_eq(names[0], DnsName("a.io"))
  assert_eq(names[1], Rfc822Name("x@y.z"))
  assert_eq(
    names[2],
    IpAddress(Bytes::from_array([b'\x01', b'\x02', b'\x03', b'\x04'])),
  )
  guard names[3] is Unsupported(tag=8, ..) else {
    fail("expected Unsupported tag 8")
  }
  guard names[4] is DirectoryName(n) else { fail("expected DirectoryName") }
  assert_eq(n.rdns.length(), 0)
}

///|
test "GeneralName::to_display formats IPv4 and IPv6" {
  let v4 = IpAddress(Bytes::from_array([b'\x7F', b'\x00', b'\x00', b'\x01']))
  assert_eq(v4.to_display(), "IP:127.0.0.1")
  let v6 = IpAddress(
    Bytes::from_array([
      b'\x20', b'\x01', b'\x0D', b'\xB8', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
      b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x01',
    ]),
  )
  assert_eq(v6.to_display(), "IP:2001:0db8:0000:0000:0000:0000:0000:0001")
  assert_eq(DnsName("example.com").to_display(), "DNS:example.com")
  assert_eq(Rfc822Name("a@b.c").to_display(), "email:a@b.c")
  assert_eq(Uri("https://x.y").to_display(), "URI:https://x.y")
}

///|
test "parse_key_usage reads single-bit and multi-bit values" {
  // BIT STRING, unused=7, data=0x80 -> only digitalSignature.
  let single = Bytes::from_array([b'\x03', b'\x02', b'\x07', b'\x80'])
  let ku = match parse_key_usage(single) {
    Some(ku) => ku
    None => fail("expected KeyUsage")
  }
  assert_eq(ku.digital_signature, true)
  assert_eq(ku.non_repudiation, false)
  assert_eq(ku.to_display(), "digitalSignature")
  // Not a BIT STRING.
  let bad = Bytes::from_array([b'\x05', b'\x00'])
  assert_eq(parse_key_usage(bad), None)
}

///|
test "parse_extensions tolerates empty and non-container input" {
  assert_eq(parse_extensions(Bytes::new(0)).length(), 0)
  // A bare BOOLEAN is not a SEQUENCE OF Extension.
  let bad = Bytes::from_array([b'\x01', b'\x01', b'\xFF'])
  assert_eq(parse_extensions(bad).length(), 0)
}

///|
test "parse_ext_key_usage decodes known and unknown purposes" {
  // SEQUENCE { OID 1.3.6.1.5.5.7.3.1 (serverAuth),
  //            OID 1.3.6.1.5.5.7.3.2 (clientAuth) }
  let inner = Bytes::from_array([
    b'\x30', b'\x14', b'\x06', b'\x08', b'\x2B', b'\x06', b'\x01', b'\x05', b'\x05', b'\x07',
    b'\x03', b'\x01', b'\x06', b'\x08', b'\x2B', b'\x06', b'\x01', b'\x05', b'\x05', b'\x07',
    b'\x03', b'\x02',
  ])
  let eku = match parse_ext_key_usage(inner) {
    Some(e) => e
    None => fail("expected ExtKeyUsage")
  }
  assert_eq(eku.purposes.length(), 2)
  assert_eq(eku.purposes[0], ServerAuth)
  assert_eq(eku.purposes[1], ClientAuth)
  assert_eq(eku.to_display(), "serverAuth, clientAuth")
  // Unknown OID 1.2.3.4.5 -> Other
  let other = Bytes::from_array([
    b'\x30', b'\x06', b'\x06', b'\x04', b'\x2A', b'\x03', b'\x04', b'\x05',
  ])
  let eku2 = match parse_ext_key_usage(other) {
    Some(e) => e
    None => fail("expected ExtKeyUsage")
  }
  assert_eq(eku2.purposes[0], Other(oid="1.2.3.4.5"))
  assert_eq(eku2.to_display(), "1.2.3.4.5")
  // Not a SEQUENCE.
  let bad = Bytes::from_array([b'\x05', b'\x00'])
  assert_eq(parse_ext_key_usage(bad), None)
}

///|
test "parse_subject_key_identifier extracts the key id" {
  // OCTET STRING { OCTET STRING { 20-byte key id } }
  let inner = Bytes::from_array([
    b'\x04', b'\x14', b'\xE4', b'\xF9', b'\xA5', b'\x42', b'\x6C', b'\x7F', b'\x68', b'\x2F',
    b'\xFF', b'\x79', b'\x56', b'\x52', b'\x28', b'\xBD', b'\xD3', b'\x15', b'\xCC', b'\xD1',
    b'\x30', b'\xE5',
  ])
  let kid = match parse_subject_key_identifier(inner) {
    Some(k) => k
    None => fail("expected key id")
  }
  assert_eq(kid.length(), 20)
  assert_eq(kid[0].to_int(), 0xE4)
  assert_eq(kid[19].to_int(), 0xE5)
  // Not an OCTET STRING.
  let bad = Bytes::from_array([b'\x05', b'\x00'])
  assert_eq(parse_subject_key_identifier(bad), None)
}

///|
test "parse_authority_key_identifier decodes all three fields" {
  // SEQUENCE {
  //   [0] keyIdentifier (20 bytes),
  //   [1] authorityCertIssuer { [2] dNSName "ca.example.com" },
  //   [2] authorityCertSerialNumber 0x01
  // }
  let inner = Bytes::from_array([
    b'\x30', b'\x2B', b'\x80', b'\x14', b'\xE4', b'\xF9', b'\xA5', b'\x42', b'\x6C', b'\x7F',
    b'\x68', b'\x2F', b'\xFF', b'\x79', b'\x56', b'\x52', b'\x28', b'\xBD', b'\xD3', b'\x15',
    b'\xCC', b'\xD1', b'\x30', b'\xE5', b'\xA1', b'\x10', b'\x82', b'\x0E', b'\x63', b'\x61',
    b'\x2E', b'\x65', b'\x78', b'\x61', b'\x6D', b'\x70', b'\x6C', b'\x65', b'\x2E', b'\x63',
    b'\x6F', b'\x6D', b'\x82', b'\x01', b'\x01',
  ])
  let aki = match parse_authority_key_identifier(inner) {
    Some(a) => a
    None => fail("expected AuthorityKeyIdentifier")
  }
  assert_eq(aki.key_identifier.unwrap().length(), 20)
  let issuer = match aki.cert_issuer {
    Some(names) => names
    None => fail("expected cert_issuer")
  }
  assert_eq(issuer.length(), 1)
  assert_eq(issuer[0], DnsName("ca.example.com"))
  assert_eq(aki.cert_serial_number, Some(Bytes::from_array([b'\x01'])))
  assert_eq(
    aki.to_display(),
    "keyid:e4f9a5426c7f682fff79565228bdd315ccd130e5, issuer:DNS:ca.example.com, serial:01",
  )
}

///|
test "parse_authority_key_identifier with only keyIdentifier" {
  // SEQUENCE { [0] keyIdentifier (4 bytes) }
  let inner = Bytes::from_array([
    b'\x30', b'\x06', b'\x80', b'\x04', b'\xDE', b'\xAD', b'\xBE', b'\xEF',
  ])
  let aki = match parse_authority_key_identifier(inner) {
    Some(a) => a
    None => fail("expected AuthorityKeyIdentifier")
  }
  assert_eq(aki.key_identifier, Some(Bytes::from_array([b'\xDE', b'\xAD', b'\xBE', b'\xEF'])))
  assert_eq(aki.cert_issuer, None)
  assert_eq(aki.cert_serial_number, None)
  assert_eq(aki.to_display(), "keyid:deadbeef")
  // Not a SEQUENCE.
  let bad = Bytes::from_array([b'\x05', b'\x00'])
  assert_eq(parse_authority_key_identifier(bad), None)
}
