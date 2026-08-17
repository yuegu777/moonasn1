///|
/// End-to-end regression tests against real certificates generated with
/// `openssl req -x509`. Field values below were cross-checked with
/// `openssl x509 -noout -subject -issuer -dates`.

///|
let rsa_cert_der : Bytes = Bytes::from_array([
  b'\x30', b'\x82', b'\x03', b'\x1D', b'\x30', b'\x82', b'\x02', b'\x05',
  b'\xA0', b'\x03', b'\x02', b'\x01', b'\x02', b'\x02', b'\x14', b'\x6D',
  b'\x02', b'\x99', b'\xF3', b'\x61', b'\x8D', b'\x60', b'\x09', b'\x5C',
  b'\xBD', b'\x52', b'\x2A', b'\xA1', b'\xE6', b'\x1C', b'\x02', b'\x07',
  b'\x5D', b'\xAA', b'\x34', b'\x30', b'\x0D', b'\x06', b'\x09', b'\x2A',
  b'\x86', b'\x48', b'\x86', b'\xF7', b'\x0D', b'\x01', b'\x01', b'\x0B',
  b'\x05', b'\x00', b'\x30', b'\x37', b'\x31', b'\x14', b'\x30', b'\x12',
  b'\x06', b'\x03', b'\x55', b'\x04', b'\x03', b'\x0C', b'\x0B', b'\x65',
  b'\x78', b'\x61', b'\x6D', b'\x70', b'\x6C', b'\x65', b'\x2E', b'\x63',
  b'\x6F', b'\x6D', b'\x31', b'\x12', b'\x30', b'\x10', b'\x06', b'\x03',
  b'\x55', b'\x04', b'\x0A', b'\x0C', b'\x09', b'\x41', b'\x63', b'\x6D',
  b'\x65', b'\x20', b'\x54', b'\x65', b'\x73', b'\x74', b'\x31', b'\x0B',
  b'\x30', b'\x09', b'\x06', b'\x03', b'\x55', b'\x04', b'\x06', b'\x13',
  b'\x02', b'\x55', b'\x53', b'\x30', b'\x1E', b'\x17', b'\x0D', b'\x32',
  b'\x36', b'\x30', b'\x38', b'\x31', b'\x37', b'\x30', b'\x30', b'\x32',
  b'\x35', b'\x30', b'\x37', b'\x5A', b'\x17', b'\x0D', b'\x32', b'\x37',
  b'\x30', b'\x38', b'\x31', b'\x37', b'\x30', b'\x30', b'\x32', b'\x35',
  b'\x30', b'\x37', b'\x5A', b'\x30', b'\x37', b'\x31', b'\x14', b'\x30',
  b'\x12', b'\x06', b'\x03', b'\x55', b'\x04', b'\x03', b'\x0C', b'\x0B',
  b'\x65', b'\x78', b'\x61', b'\x6D', b'\x70', b'\x6C', b'\x65', b'\x2E',
  b'\x63', b'\x6F', b'\x6D', b'\x31', b'\x12', b'\x30', b'\x10', b'\x06',
  b'\x03', b'\x55', b'\x04', b'\x0A', b'\x0C', b'\x09', b'\x41', b'\x63',
  b'\x6D', b'\x65', b'\x20', b'\x54', b'\x65', b'\x73', b'\x74', b'\x31',
  b'\x0B', b'\x30', b'\x09', b'\x06', b'\x03', b'\x55', b'\x04', b'\x06',
  b'\x13', b'\x02', b'\x55', b'\x53', b'\x30', b'\x82', b'\x01', b'\x22',
  b'\x30', b'\x0D', b'\x06', b'\x09', b'\x2A', b'\x86', b'\x48', b'\x86',
  b'\xF7', b'\x0D', b'\x01', b'\x01', b'\x01', b'\x05', b'\x00', b'\x03',
  b'\x82', b'\x01', b'\x0F', b'\x00', b'\x30', b'\x82', b'\x01', b'\x0A',
  b'\x02', b'\x82', b'\x01', b'\x01', b'\x00', b'\xB6', b'\x7A', b'\xE7',
  b'\xBD', b'\xEB', b'\xFB', b'\x38', b'\xC7', b'\xFE', b'\xD1', b'\xB7',
  b'\x38', b'\xA4', b'\xB8', b'\x15', b'\xAE', b'\xC5', b'\x66', b'\x3C',
  b'\xA9', b'\xE5', b'\xCC', b'\x1F', b'\xF2', b'\xFC', b'\x21', b'\xD1',
  b'\xFD', b'\xB2', b'\x11', b'\xAB', b'\xD9', b'\x4E', b'\x62', b'\x38',
  b'\x61', b'\xDD', b'\x10', b'\x17', b'\xAE', b'\xF9', b'\x07', b'\x19',
  b'\xFD', b'\xCE', b'\x4A', b'\xB6', b'\x0D', b'\x31', b'\x9E', b'\x8A',
  b'\x0C', b'\xC5', b'\x2C', b'\x84', b'\xFF', b'\x75', b'\x39', b'\xD6',
  b'\x51', b'\x02', b'\x86', b'\xD6', b'\xD6', b'\xFD', b'\xE9', b'\xD4',
  b'\x92', b'\x2E', b'\x5F', b'\x0D', b'\x50', b'\xA4', b'\xFA', b'\xD0',
  b'\x07', b'\x0F', b'\x57', b'\x3E', b'\x0C', b'\x5E', b'\x33', b'\x6F',
  b'\xA6', b'\xB1', b'\xD8', b'\x49', b'\x86', b'\xAA', b'\xCE', b'\x51',
  b'\xBA', b'\xE9', b'\xCB', b'\x06', b'\x6C', b'\x3E', b'\x43', b'\x53',
  b'\xE6', b'\x04', b'\xB2', b'\x9E', b'\xF2', b'\x34', b'\xE2', b'\x59',
  b'\xA1', b'\xF6', b'\x8E', b'\x53', b'\x99', b'\x49', b'\x85', b'\x3F',
  b'\xBE', b'\xDD', b'\x7B', b'\xBE', b'\xA3', b'\x7B', b'\xD6', b'\x6D',
  b'\xDB', b'\x0F', b'\x71', b'\x53', b'\x6B', b'\x48', b'\x2B', b'\x2F',
  b'\xFD', b'\xBF', b'\x90', b'\x8D', b'\xBB', b'\x61', b'\x62', b'\x28',
  b'\xAD', b'\x78', b'\x5D', b'\x1D', b'\x02', b'\xD4', b'\x97', b'\x89',
  b'\xE5', b'\xFC', b'\x89', b'\x63', b'\xAE', b'\xE5', b'\xF0', b'\xE6',
  b'\xDD', b'\x50', b'\x6F', b'\x1D', b'\x4A', b'\xBF', b'\x3E', b'\xED',
  b'\x0C', b'\xD1', b'\xA0', b'\xF1', b'\x27', b'\x28', b'\x71', b'\xE9',
  b'\x65', b'\x01', b'\xE0', b'\x7F', b'\xCB', b'\x7A', b'\xF6', b'\xF7',
  b'\xBE', b'\xF9', b'\x31', b'\x84', b'\x48', b'\xA2', b'\x88', b'\x02',
  b'\xCD', b'\x0A', b'\xE8', b'\x9B', b'\x3D', b'\x0E', b'\x1F', b'\x17',
  b'\xD4', b'\x0A', b'\x6D', b'\x11', b'\xCA', b'\xE1', b'\x0F', b'\xA4',
  b'\xF0', b'\x6C', b'\xAB', b'\x07', b'\xC9', b'\xF8', b'\x43', b'\x98',
  b'\xCF', b'\x13', b'\xF8', b'\x0D', b'\x5E', b'\x9B', b'\xB6', b'\xED',
  b'\x1F', b'\x3C', b'\x87', b'\xE9', b'\x23', b'\xFC', b'\x63', b'\x57',
  b'\xBA', b'\x9A', b'\x25', b'\xBA', b'\x22', b'\x7C', b'\x32', b'\x93',
  b'\x40', b'\x64', b'\x69', b'\x2D', b'\xE4', b'\xAF', b'\x3D', b'\x30',
  b'\xBB', b'\x0D', b'\xED', b'\x52', b'\x58', b'\x9F', b'\xEE', b'\xEC',
  b'\xE9', b'\x3D', b'\xA4', b'\x2F', b'\x4D', b'\x02', b'\x03', b'\x01',
  b'\x00', b'\x01', b'\xA3', b'\x21', b'\x30', b'\x1F', b'\x30', b'\x1D',
  b'\x06', b'\x03', b'\x55', b'\x1D', b'\x0E', b'\x04', b'\x16', b'\x04',
  b'\x14', b'\xAD', b'\x8D', b'\x23', b'\x78', b'\x09', b'\x19', b'\x68',
  b'\x82', b'\x81', b'\xE4', b'\x54', b'\xDC', b'\x68', b'\xE9', b'\xEE',
  b'\x80', b'\x29', b'\xDF', b'\xE6', b'\x50', b'\x30', b'\x0D', b'\x06',
  b'\x09', b'\x2A', b'\x86', b'\x48', b'\x86', b'\xF7', b'\x0D', b'\x01',
  b'\x01', b'\x0B', b'\x05', b'\x00', b'\x03', b'\x82', b'\x01', b'\x01',
  b'\x00', b'\x13', b'\xEB', b'\x15', b'\x4A', b'\x67', b'\xBE', b'\x1A',
  b'\x75', b'\x2E', b'\xA5', b'\xD7', b'\x1A', b'\xA0', b'\xB7', b'\xD6',
  b'\x70', b'\x49', b'\xBD', b'\x72', b'\xC1', b'\xD5', b'\x4C', b'\xA2',
  b'\xDC', b'\x63', b'\x1C', b'\xE4', b'\x23', b'\x13', b'\x76', b'\x86',
  b'\x75', b'\x3B', b'\x0F', b'\x06', b'\x18', b'\xE6', b'\x9E', b'\x06',
  b'\xBC', b'\x56', b'\xE2', b'\x93', b'\xD3', b'\x4D', b'\xEC', b'\x69',
  b'\x89', b'\x4B', b'\xD5', b'\xD8', b'\x09', b'\x43', b'\xDB', b'\xB2',
  b'\xC3', b'\x0B', b'\x45', b'\x95', b'\xCE', b'\x64', b'\x2C', b'\x8B',
  b'\xFC', b'\xB3', b'\x11', b'\xA9', b'\x08', b'\x3D', b'\x89', b'\x6A',
  b'\x06', b'\xD3', b'\xBF', b'\xD3', b'\xC6', b'\x5E', b'\x0E', b'\x63',
  b'\xDE', b'\x80', b'\x2A', b'\x8C', b'\x93', b'\xB2', b'\xA1', b'\x8A',
  b'\xF2', b'\x4F', b'\xC4', b'\x61', b'\xDA', b'\xD4', b'\x5D', b'\x96',
  b'\x24', b'\xCE', b'\x24', b'\x90', b'\xE5', b'\x06', b'\xBA', b'\x9A',
  b'\x47', b'\x3F', b'\xBA', b'\x48', b'\x1E', b'\xB1', b'\xAD', b'\x88',
  b'\x5D', b'\xF6', b'\xCB', b'\x2A', b'\x7D', b'\x20', b'\xBA', b'\x21',
  b'\x1B', b'\xDC', b'\xE7', b'\xFC', b'\x40', b'\x48', b'\x3A', b'\x65',
  b'\xBD', b'\xC9', b'\xA9', b'\xBC', b'\x58', b'\xC4', b'\xDA', b'\x18',
  b'\x35', b'\x38', b'\x8A', b'\xDF', b'\x11', b'\x02', b'\x69', b'\x4B',
  b'\x90', b'\x55', b'\xB9', b'\xDD', b'\x02', b'\x47', b'\x13', b'\xD6',
  b'\x59', b'\x99', b'\xDD', b'\x12', b'\x73', b'\x6E', b'\x6A', b'\xBC',
  b'\x67', b'\xDD', b'\x9F', b'\x75', b'\x1C', b'\x32', b'\xB3', b'\xCF',
  b'\xDD', b'\x36', b'\x56', b'\x26', b'\x8D', b'\xE2', b'\x06', b'\x02',
  b'\x51', b'\x93', b'\x0C', b'\x45', b'\xAF', b'\x6D', b'\x06', b'\x7A',
  b'\xA1', b'\xAB', b'\x45', b'\x86', b'\x51', b'\x42', b'\xE3', b'\xC6',
  b'\x8C', b'\x2F', b'\x52', b'\xF8', b'\xF5', b'\xF5', b'\x5E', b'\x25',
  b'\x1E', b'\xE7', b'\xF4', b'\xEF', b'\xB7', b'\x70', b'\x81', b'\x6D',
  b'\xB0', b'\x9B', b'\x19', b'\x7E', b'\xD8', b'\xF6', b'\xCD', b'\x44',
  b'\x84', b'\x7E', b'\x07', b'\x99', b'\x3D', b'\xC8', b'\x24', b'\x19',
  b'\x1E', b'\x6F', b'\xF6', b'\x7F', b'\x48', b'\x6C', b'\x16', b'\xB5',
  b'\x0E', b'\x04', b'\x0F', b'\xAB', b'\xA6', b'\x04', b'\xD2', b'\x76',
  b'\xA6', b'\x5E', b'\xB9', b'\xFC', b'\xDE', b'\xFF', b'\xFD', b'\x28',
  b'\x0B', b'\xEB', b'\x26', b'\x5D', b'\x44', b'\x38', b'\x0F', b'\xA7',
  b'\xFC',
])

///|
let ec_cert_der : Bytes = Bytes::from_array([
  b'\x30', b'\x82', b'\x01', b'\x97', b'\x30', b'\x82', b'\x01', b'\x3D',
  b'\xA0', b'\x03', b'\x02', b'\x01', b'\x02', b'\x02', b'\x14', b'\x5D',
  b'\x89', b'\xD6', b'\xCC', b'\x38', b'\x6D', b'\x6C', b'\x3C', b'\xAC',
  b'\x39', b'\x30', b'\x72', b'\x8A', b'\x51', b'\xF4', b'\x22', b'\xBB',
  b'\xFF', b'\x5F', b'\x9D', b'\x30', b'\x0A', b'\x06', b'\x08', b'\x2A',
  b'\x86', b'\x48', b'\xCE', b'\x3D', b'\x04', b'\x03', b'\x02', b'\x30',
  b'\x3A', b'\x31', b'\x17', b'\x30', b'\x15', b'\x06', b'\x03', b'\x55',
  b'\x04', b'\x03', b'\x0C', b'\x0E', b'\x65', b'\x63', b'\x2E', b'\x65',
  b'\x78', b'\x61', b'\x6D', b'\x70', b'\x6C', b'\x65', b'\x2E', b'\x63',
  b'\x6F', b'\x6D', b'\x31', b'\x12', b'\x30', b'\x10', b'\x06', b'\x03',
  b'\x55', b'\x04', b'\x0A', b'\x0C', b'\x09', b'\x45', b'\x63', b'\x6D',
  b'\x65', b'\x20', b'\x54', b'\x65', b'\x73', b'\x74', b'\x31', b'\x0B',
  b'\x30', b'\x09', b'\x06', b'\x03', b'\x55', b'\x04', b'\x06', b'\x13',
  b'\x02', b'\x43', b'\x4E', b'\x30', b'\x1E', b'\x17', b'\x0D', b'\x32',
  b'\x36', b'\x30', b'\x38', b'\x31', b'\x37', b'\x30', b'\x30', b'\x32',
  b'\x39', b'\x33', b'\x38', b'\x5A', b'\x17', b'\x0D', b'\x32', b'\x37',
  b'\x30', b'\x38', b'\x31', b'\x37', b'\x30', b'\x30', b'\x32', b'\x39',
  b'\x33', b'\x38', b'\x5A', b'\x30', b'\x3A', b'\x31', b'\x17', b'\x30',
  b'\x15', b'\x06', b'\x03', b'\x55', b'\x04', b'\x03', b'\x0C', b'\x0E',
  b'\x65', b'\x63', b'\x2E', b'\x65', b'\x78', b'\x61', b'\x6D', b'\x70',
  b'\x6C', b'\x65', b'\x2E', b'\x63', b'\x6F', b'\x6D', b'\x31', b'\x12',
  b'\x30', b'\x10', b'\x06', b'\x03', b'\x55', b'\x04', b'\x0A', b'\x0C',
  b'\x09', b'\x45', b'\x63', b'\x6D', b'\x65', b'\x20', b'\x54', b'\x65',
  b'\x73', b'\x74', b'\x31', b'\x0B', b'\x30', b'\x09', b'\x06', b'\x03',
  b'\x55', b'\x04', b'\x06', b'\x13', b'\x02', b'\x43', b'\x4E', b'\x30',
  b'\x59', b'\x30', b'\x13', b'\x06', b'\x07', b'\x2A', b'\x86', b'\x48',
  b'\xCE', b'\x3D', b'\x02', b'\x01', b'\x06', b'\x08', b'\x2A', b'\x86',
  b'\x48', b'\xCE', b'\x3D', b'\x03', b'\x01', b'\x07', b'\x03', b'\x42',
  b'\x00', b'\x04', b'\x87', b'\x61', b'\xC2', b'\x75', b'\x91', b'\x0B',
  b'\x22', b'\x0C', b'\x86', b'\x2F', b'\x5D', b'\x70', b'\x77', b'\xB2',
  b'\xB9', b'\x7A', b'\xE3', b'\x95', b'\x79', b'\x36', b'\x57', b'\x19',
  b'\x50', b'\xF3', b'\x8D', b'\x55', b'\x62', b'\xA7', b'\x48', b'\xD1',
  b'\x04', b'\x90', b'\xA2', b'\xE5', b'\x4E', b'\x46', b'\xEE', b'\x38',
  b'\xAA', b'\xB5', b'\xB7', b'\x6B', b'\x6D', b'\xD7', b'\xB6', b'\x19',
  b'\xA4', b'\x8B', b'\xEA', b'\x01', b'\xF7', b'\xFD', b'\x74', b'\x18',
  b'\x35', b'\x2A', b'\xE6', b'\xC4', b'\xC7', b'\x7C', b'\x17', b'\xDF',
  b'\x06', b'\x68', b'\xA3', b'\x21', b'\x30', b'\x1F', b'\x30', b'\x1D',
  b'\x06', b'\x03', b'\x55', b'\x1D', b'\x0E', b'\x04', b'\x16', b'\x04',
  b'\x14', b'\x2D', b'\x06', b'\x1D', b'\x3E', b'\x3C', b'\xD4', b'\x7F',
  b'\xC1', b'\x5C', b'\x11', b'\x2E', b'\x70', b'\x70', b'\x9E', b'\x8C',
  b'\x19', b'\x3C', b'\xC5', b'\x38', b'\xDE', b'\x30', b'\x0A', b'\x06',
  b'\x08', b'\x2A', b'\x86', b'\x48', b'\xCE', b'\x3D', b'\x04', b'\x03',
  b'\x02', b'\x03', b'\x48', b'\x00', b'\x30', b'\x45', b'\x02', b'\x21',
  b'\x00', b'\xDB', b'\x66', b'\xD9', b'\x75', b'\xAA', b'\x02', b'\xED',
  b'\xA5', b'\x2C', b'\x2F', b'\x3A', b'\x7C', b'\xE7', b'\xA6', b'\x88',
  b'\x59', b'\x50', b'\x09', b'\x65', b'\x6E', b'\xCA', b'\x11', b'\x93',
  b'\x26', b'\x0F', b'\x21', b'\xC5', b'\xBD', b'\x57', b'\x79', b'\xB5',
  b'\xA5', b'\x02', b'\x20', b'\x69', b'\x7C', b'\x15', b'\xA2', b'\x47',
  b'\x35', b'\x98', b'\x6E', b'\xA0', b'\xCF', b'\x6B', b'\xE4', b'\xB2',
  b'\x47', b'\xF4', b'\x66', b'\xF7', b'\x70', b'\x0A', b'\x21', b'\x37',
  b'\xF2', b'\x0D', b'\x43', b'\x42', b'\x73', b'\xE2', b'\xCE', b'\x0D',
  b'\x58', b'\x83', b'\xAE',
])

///|
test "parse_cert on a real RSA-2048 certificate" {
  let cert = match parse_cert(rsa_cert_der) {
    Ok(c) => c
    Err(e) => fail("parse failed: " + e)
  }
  assert_eq(cert.version, 2) // v3
  assert_eq(cert.signature_algorithm, "sha256WithRSAEncryption")
  assert_eq(
    cert.subject_dn_string(),
    "commonName=example.com, organizationName=Acme Test, countryName=US",
  )
  assert_eq(
    cert.issuer_dn_string(),
    "commonName=example.com, organizationName=Acme Test, countryName=US",
  )
  assert_eq(cert.not_before.to_rfc3339(), "2026-08-17T00:25:07Z")
  assert_eq(cert.not_after.to_rfc3339(), "2027-08-17T00:25:07Z")
  assert_eq(cert.public_key_algorithm, Rsa(modulus_bits=Some(2048)))
  assert_eq(cert.signature_value.length(), 256)
}

///|
test "parse_cert on a real EC P-256 certificate" {
  let cert = match parse_cert(ec_cert_der) {
    Ok(c) => c
    Err(e) => fail("parse failed: " + e)
  }
  assert_eq(cert.version, 2) // v3
  assert_eq(
    cert.subject_dn_string(),
    "commonName=ec.example.com, organizationName=Ecme Test, countryName=CN",
  )
  assert_eq(cert.not_before.to_rfc3339(), "2026-08-17T00:29:38Z")
  assert_eq(cert.not_after.to_rfc3339(), "2027-08-17T00:29:38Z")
  assert_eq(cert.public_key_algorithm, Ec(curve=Some("P-256")))
}

///|
test "parse_cert rejects non-certificate input" {
  // A SEQUENCE { INTEGER 1 } is valid DER but not a certificate.
  let buf = Bytes::from_array([b'\x30', b'\x03', b'\x02', b'\x01', b'\x01'])
  guard parse_cert(buf) is Err(_) else { fail("expected error") }
}
