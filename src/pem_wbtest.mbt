///|
test "decode_pem decodes a CERTIFICATE block" {
  // DER: 30 03 02 01 00  ->  SEQUENCE { INTEGER 0 }
  // Base64: MAMCAQA=
  let pem = "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----"
  let block = match decode_pem(pem) {
    Some(b) => b
    None => fail("expected a PEM block")
  }
  assert_eq(block.label, "CERTIFICATE")
  assert_eq(block.data.length(), 5)
  assert_eq(block.data[0].to_int(), 0x30)
  assert_eq(block.data[1].to_int(), 0x03)
  assert_eq(block.data[2].to_int(), 0x02)
  assert_eq(block.data[3].to_int(), 0x01)
  assert_eq(block.data[4].to_int(), 0x00)
}

///|
test "decode_pem returns None for non-PEM text" {
  assert_eq(decode_pem("hello world"), None)
  assert_eq(decode_pem(""), None)
  // Incomplete envelope: BEGIN but no END
  let incomplete = "-----BEGIN CERTIFICATE-----\nMAMCAQA="
  assert_eq(decode_pem(incomplete), None)
}

///|
test "decode_pem handles multiline base64" {
  // Same 5 bytes split across two lines
  let pem = "-----BEGIN CERTIFICATE-----\nMAMC\nAQA=\n-----END CERTIFICATE-----"
  let block = match decode_pem(pem) {
    Some(b) => b
    None => fail("expected a PEM block")
  }
  assert_eq(block.data.length(), 5)
  assert_eq(block.data[0].to_int(), 0x30)
}

///|
test "decode_pem with PRIVATE KEY label" {
  let pem = "-----BEGIN PRIVATE KEY-----\nMAMCAQA=\n-----END PRIVATE KEY-----"
  let block = match decode_pem(pem) {
    Some(b) => b
    None => fail("expected a PEM block")
  }
  assert_eq(block.label, "PRIVATE KEY")
  assert_eq(block.data.length(), 5)
}

///|
test "decode_pem ignores surrounding text" {
  let pem = "Here is a cert:\n-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\nThat's all."
  let block = match decode_pem(pem) {
    Some(b) => b
    None => fail("expected a PEM block")
  }
  assert_eq(block.label, "CERTIFICATE")
  assert_eq(block.data.length(), 5)
}

///|
test "decode_pem_all decodes multiple blocks" {
  let pem = "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMAMCAQE=\n-----END PRIVATE KEY-----"
  let blocks = decode_pem_all(pem)
  assert_eq(blocks.length(), 2)
  assert_eq(blocks[0].label, "CERTIFICATE")
  assert_eq(blocks[0].data.length(), 5)
  assert_eq(blocks[0].data[4].to_int(), 0x00)
  assert_eq(blocks[1].label, "PRIVATE KEY")
  assert_eq(blocks[1].data.length(), 5)
  assert_eq(blocks[1].data[4].to_int(), 0x01)
}

///|
test "decode_pem_all returns empty for no blocks" {
  assert_eq(decode_pem_all("no PEM here").length(), 0)
  assert_eq(decode_pem_all("").length(), 0)
}

///|
test "decode_pem rejects malformed base64" {
  // '!' is not a valid Base64 character, but it's not '=' either,
  // so it's silently skipped. The remaining "MAMCAQA" is 7 chars —
  // not a multiple of 4 — so decode fails.
  let bad = "-----BEGIN CERTIFICATE-----\nMAMCAQA!\n-----END CERTIFICATE-----"
  assert_eq(decode_pem(bad), None)
}

///|
test "decode_pem decodes a realistic-sized certificate" {
  // A minimal but structurally complete DER SEQUENCE (20 bytes).
  // Base64 of 20 zero bytes: AAAAAAAAAAAAAAAAAAAAAAAAAAA=
  let pem = "-----BEGIN CERTIFICATE-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END CERTIFICATE-----"
  let block = match decode_pem(pem) {
    Some(b) => b
    None => fail("expected a PEM block")
  }
  assert_eq(block.data.length(), 20)
  assert_eq(block.data[0].to_int(), 0x00)
  assert_eq(block.data[19].to_int(), 0x00)
}

///|
test "PemBlock::to_display shows label and size" {
  let pem = "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----"
  let block = match decode_pem(pem) {
    Some(b) => b
    None => fail("expected a PEM block")
  }
  assert_eq(block.to_display(), "-----BEGIN CERTIFICATE----- (5 bytes)")
}
