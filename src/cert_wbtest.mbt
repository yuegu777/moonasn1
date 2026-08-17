///|
/// End-to-end regression tests against real certificates generated with
/// `openssl req -x509` (RSA leaf with SAN/keyUsage/EKU/basicConstraints,
/// EC P-256 CA with basicConstraints CA:TRUE pathlen:0). Field values
/// below were cross-checked with `openssl x509 -noout -text`.

///|
let rsa_cert_der : Bytes = Bytes::from_array([
  b'\x30', b'\x82', b'\x03', b'\xA4', b'\x30', b'\x82', b'\x02', b'\x8C',
  b'\xA0', b'\x03', b'\x02', b'\x01', b'\x02', b'\x02', b'\x14', b'\x6B',
  b'\x42', b'\x13', b'\xF4', b'\x08', b'\xAB', b'\x82', b'\x57', b'\x4B',
  b'\x4C', b'\xE9', b'\x55', b'\xED', b'\x2F', b'\x96', b'\x43', b'\xD3',
  b'\x33', b'\xF4', b'\xE6', b'\x30', b'\x0D', b'\x06', b'\x09', b'\x2A',
  b'\x86', b'\x48', b'\x86', b'\xF7', b'\x0D', b'\x01', b'\x01', b'\x0B',
  b'\x05', b'\x00', b'\x30', b'\x37', b'\x31', b'\x14', b'\x30', b'\x12',
  b'\x06', b'\x03', b'\x55', b'\x04', b'\x03', b'\x0C', b'\x0B', b'\x65',
  b'\x78', b'\x61', b'\x6D', b'\x70', b'\x6C', b'\x65', b'\x2E', b'\x63',
  b'\x6F', b'\x6D', b'\x31', b'\x12', b'\x30', b'\x10', b'\x06', b'\x03',
  b'\x55', b'\x04', b'\x0A', b'\x0C', b'\x09', b'\x41', b'\x63', b'\x6D',
  b'\x65', b'\x20', b'\x54', b'\x65', b'\x73', b'\x74', b'\x31', b'\x0B',
  b'\x30', b'\x09', b'\x06', b'\x03', b'\x55', b'\x04', b'\x06', b'\x13',
  b'\x02', b'\x55', b'\x53', b'\x30', b'\x1E', b'\x17', b'\x0D', b'\x32',
  b'\x36', b'\x30', b'\x38', b'\x31', b'\x37', b'\x30', b'\x30', b'\x34',
  b'\x37', b'\x30', b'\x33', b'\x5A', b'\x17', b'\x0D', b'\x32', b'\x37',
  b'\x30', b'\x38', b'\x31', b'\x37', b'\x30', b'\x30', b'\x34', b'\x37',
  b'\x30', b'\x33', b'\x5A', b'\x30', b'\x37', b'\x31', b'\x14', b'\x30',
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
  b'\x02', b'\x82', b'\x01', b'\x01', b'\x00', b'\xDA', b'\x36', b'\x1F',
  b'\x1F', b'\x4B', b'\x2D', b'\xBC', b'\xE6', b'\xE1', b'\x83', b'\xFC',
  b'\x4F', b'\xBB', b'\x81', b'\x77', b'\xBB', b'\x02', b'\x20', b'\xB1',
  b'\xFE', b'\xC5', b'\x1F', b'\xA7', b'\xD2', b'\xC5', b'\x58', b'\x99',
  b'\x12', b'\x5D', b'\xF4', b'\xBD', b'\xD1', b'\x01', b'\x2E', b'\x69',
  b'\x48', b'\xE5', b'\x11', b'\x6A', b'\xE7', b'\xC2', b'\x22', b'\xEA',
  b'\x84', b'\x0C', b'\x37', b'\x05', b'\x68', b'\x24', b'\x26', b'\x5C',
  b'\x15', b'\xB1', b'\xA7', b'\x94', b'\x74', b'\x67', b'\xE3', b'\x51',
  b'\xA3', b'\x3C', b'\xB3', b'\x6A', b'\x10', b'\x0E', b'\xAF', b'\xC2',
  b'\xC5', b'\x72', b'\x26', b'\x8A', b'\x9F', b'\x76', b'\xE7', b'\xF2',
  b'\x8A', b'\x3E', b'\x97', b'\xEE', b'\x6B', b'\xA9', b'\xD7', b'\x1F',
  b'\xF8', b'\xA8', b'\xAC', b'\xA4', b'\x26', b'\xB1', b'\x2C', b'\x16',
  b'\xC9', b'\x31', b'\xF9', b'\x8B', b'\xE0', b'\x7B', b'\x90', b'\x68',
  b'\xB6', b'\xFF', b'\xEA', b'\xCD', b'\xC0', b'\xDE', b'\x2A', b'\x6A',
  b'\x2B', b'\xD6', b'\x5B', b'\x86', b'\xDE', b'\x9B', b'\x01', b'\x4F',
  b'\x1F', b'\x9C', b'\x16', b'\x85', b'\x1D', b'\x35', b'\x2B', b'\xC0',
  b'\x4D', b'\xA2', b'\x21', b'\x50', b'\xDC', b'\x51', b'\x80', b'\x73',
  b'\x00', b'\xA8', b'\x1F', b'\xB5', b'\x22', b'\xC0', b'\x2F', b'\x6F',
  b'\x70', b'\x1F', b'\xBC', b'\xD6', b'\x21', b'\xC7', b'\x97', b'\x85',
  b'\x7D', b'\x14', b'\x6C', b'\x05', b'\x61', b'\x30', b'\x1E', b'\x25',
  b'\x23', b'\x2C', b'\x1E', b'\x67', b'\x23', b'\x7F', b'\x57', b'\xD8',
  b'\xDF', b'\xA8', b'\xED', b'\x58', b'\x75', b'\xB6', b'\x08', b'\x16',
  b'\x07', b'\xB6', b'\x3C', b'\xE7', b'\x62', b'\x1A', b'\x71', b'\xF3',
  b'\xD0', b'\x30', b'\x83', b'\x77', b'\x9B', b'\x7D', b'\xA8', b'\x75',
  b'\xD6', b'\xC1', b'\xAD', b'\xDA', b'\x46', b'\xA0', b'\xF9', b'\xD6',
  b'\x46', b'\x98', b'\xF3', b'\x0F', b'\xC0', b'\x42', b'\x43', b'\xBA',
  b'\xFC', b'\xD7', b'\x51', b'\xCB', b'\xBE', b'\x45', b'\x9C', b'\xAE',
  b'\x38', b'\xF9', b'\x64', b'\xF6', b'\xE6', b'\x22', b'\x28', b'\x19',
  b'\x2D', b'\x74', b'\xCC', b'\xC6', b'\xC8', b'\xC7', b'\x21', b'\x9D',
  b'\xB6', b'\x78', b'\x01', b'\xA0', b'\x7F', b'\xBF', b'\x68', b'\xB1',
  b'\x0D', b'\xB6', b'\x2D', b'\x03', b'\xFD', b'\xBA', b'\x1A', b'\xA0',
  b'\xBE', b'\xB4', b'\xC7', b'\x15', b'\xCE', b'\x76', b'\xD8', b'\x1E',
  b'\xF0', b'\x74', b'\x86', b'\x45', b'\x3F', b'\x02', b'\x03', b'\x01',
  b'\x00', b'\x01', b'\xA3', b'\x81', b'\xA7', b'\x30', b'\x81', b'\xA4',
  b'\x30', b'\x53', b'\x06', b'\x03', b'\x55', b'\x1D', b'\x11', b'\x04',
  b'\x4C', b'\x30', b'\x4A', b'\x82', b'\x0B', b'\x65', b'\x78', b'\x61',
  b'\x6D', b'\x70', b'\x6C', b'\x65', b'\x2E', b'\x63', b'\x6F', b'\x6D',
  b'\x82', b'\x0D', b'\x2A', b'\x2E', b'\x65', b'\x78', b'\x61', b'\x6D',
  b'\x70', b'\x6C', b'\x65', b'\x2E', b'\x63', b'\x6F', b'\x6D', b'\x87',
  b'\x04', b'\x7F', b'\x00', b'\x00', b'\x01', b'\x81', b'\x11', b'\x61',
  b'\x64', b'\x6D', b'\x69', b'\x6E', b'\x40', b'\x65', b'\x78', b'\x61',
  b'\x6D', b'\x70', b'\x6C', b'\x65', b'\x2E', b'\x63', b'\x6F', b'\x6D',
  b'\x86', b'\x13', b'\x68', b'\x74', b'\x74', b'\x70', b'\x73', b'\x3A',
  b'\x2F', b'\x2F', b'\x65', b'\x78', b'\x61', b'\x6D', b'\x70', b'\x6C',
  b'\x65', b'\x2E', b'\x63', b'\x6F', b'\x6D', b'\x30', b'\x0B', b'\x06',
  b'\x03', b'\x55', b'\x1D', b'\x0F', b'\x04', b'\x04', b'\x03', b'\x02',
  b'\x05', b'\xA0', b'\x30', b'\x13', b'\x06', b'\x03', b'\x55', b'\x1D',
  b'\x25', b'\x04', b'\x0C', b'\x30', b'\x0A', b'\x06', b'\x08', b'\x2B',
  b'\x06', b'\x01', b'\x05', b'\x05', b'\x07', b'\x03', b'\x01', b'\x30',
  b'\x0C', b'\x06', b'\x03', b'\x55', b'\x1D', b'\x13', b'\x01', b'\x01',
  b'\xFF', b'\x04', b'\x02', b'\x30', b'\x00', b'\x30', b'\x1D', b'\x06',
  b'\x03', b'\x55', b'\x1D', b'\x0E', b'\x04', b'\x16', b'\x04', b'\x14',
  b'\xE4', b'\xF9', b'\xA5', b'\x42', b'\x6C', b'\x7F', b'\x68', b'\x2F',
  b'\xFF', b'\x79', b'\x56', b'\x52', b'\x28', b'\xBD', b'\xD3', b'\x15',
  b'\xCC', b'\xD1', b'\x30', b'\xE5', b'\x30', b'\x0D', b'\x06', b'\x09',
  b'\x2A', b'\x86', b'\x48', b'\x86', b'\xF7', b'\x0D', b'\x01', b'\x01',
  b'\x0B', b'\x05', b'\x00', b'\x03', b'\x82', b'\x01', b'\x01', b'\x00',
  b'\xA9', b'\xFC', b'\xFC', b'\x8F', b'\x71', b'\xB3', b'\x08', b'\x4E',
  b'\x6E', b'\x90', b'\xE6', b'\x9F', b'\x38', b'\xA3', b'\x9E', b'\x41',
  b'\xF6', b'\x35', b'\x85', b'\x1B', b'\xF0', b'\xDD', b'\xFF', b'\xCB',
  b'\x33', b'\x5E', b'\x91', b'\xA9', b'\x1B', b'\x56', b'\xDE', b'\x47',
  b'\xAE', b'\x6C', b'\xF4', b'\x7C', b'\xD5', b'\x03', b'\x2B', b'\xBF',
  b'\x10', b'\x58', b'\xB0', b'\xC3', b'\x42', b'\x3B', b'\x68', b'\xFE',
  b'\x70', b'\x64', b'\xDD', b'\xCD', b'\xBF', b'\xD5', b'\x8D', b'\x24',
  b'\xB3', b'\x57', b'\x20', b'\x8F', b'\x83', b'\x37', b'\x4D', b'\x19',
  b'\x54', b'\x9A', b'\xC5', b'\x51', b'\x5C', b'\x42', b'\xCB', b'\x69',
  b'\x81', b'\xCC', b'\x17', b'\x6E', b'\x76', b'\x46', b'\xF0', b'\x3B',
  b'\x18', b'\x60', b'\xEB', b'\xBC', b'\x9D', b'\x46', b'\x1A', b'\x67',
  b'\x30', b'\xD3', b'\x62', b'\x24', b'\xE9', b'\x01', b'\x98', b'\xBC',
  b'\x07', b'\x37', b'\x3C', b'\xAB', b'\xD2', b'\x5D', b'\x0D', b'\x47',
  b'\x64', b'\xCF', b'\x8E', b'\x9B', b'\x69', b'\x14', b'\x39', b'\x9B',
  b'\x7E', b'\x74', b'\x32', b'\x07', b'\xDE', b'\xE0', b'\x17', b'\xBE',
  b'\x4C', b'\x12', b'\x71', b'\x53', b'\xD9', b'\xFB', b'\xB2', b'\x53',
  b'\xCE', b'\xA3', b'\x8E', b'\x7E', b'\x85', b'\x54', b'\x4B', b'\x99',
  b'\x24', b'\x6C', b'\xE2', b'\xF4', b'\x4D', b'\x82', b'\x89', b'\x60',
  b'\xAD', b'\x5A', b'\xB5', b'\x7D', b'\x43', b'\x1E', b'\xDB', b'\x63',
  b'\x51', b'\x79', b'\xB0', b'\x50', b'\xA5', b'\xD0', b'\xA4', b'\xA9',
  b'\x05', b'\x54', b'\xF2', b'\x49', b'\x1A', b'\xC0', b'\x3C', b'\x48',
  b'\xEE', b'\x54', b'\xE0', b'\x9A', b'\xA3', b'\x28', b'\x2A', b'\xD3',
  b'\xE4', b'\xC8', b'\xF9', b'\x4A', b'\xEE', b'\x07', b'\x13', b'\xF5',
  b'\x9D', b'\x7B', b'\xD5', b'\xFF', b'\x41', b'\xB3', b'\x12', b'\x44',
  b'\x28', b'\xB8', b'\xE2', b'\xD4', b'\xC3', b'\x63', b'\x90', b'\x4F',
  b'\xCE', b'\xCE', b'\xB1', b'\xFF', b'\x7A', b'\x08', b'\x75', b'\xE2',
  b'\xA1', b'\xFB', b'\x39', b'\x4E', b'\x6D', b'\x17', b'\x2B', b'\x95',
  b'\x45', b'\xCC', b'\x05', b'\xE9', b'\xD1', b'\x7B', b'\x5C', b'\x49',
  b'\x84', b'\x83', b'\xB5', b'\x52', b'\x67', b'\xAF', b'\xDB', b'\xBA',
  b'\x30', b'\xFE', b'\xAF', b'\x45', b'\x70', b'\xC2', b'\x2A', b'\x97',
  b'\xDA', b'\x91', b'\x9F', b'\xBA', b'\x55', b'\xB2', b'\x25', b'\xEA',
  b'\xF3', b'\x66', b'\x8A', b'\x69', b'\x36', b'\x20', b'\x80', b'\x17',
])

///|
let ec_cert_der : Bytes = Bytes::from_array([
  b'\x30', b'\x82', b'\x01', b'\xBA', b'\x30', b'\x82', b'\x01', b'\x61',
  b'\xA0', b'\x03', b'\x02', b'\x01', b'\x02', b'\x02', b'\x14', b'\x76',
  b'\x13', b'\x41', b'\xBC', b'\x14', b'\x36', b'\x90', b'\xF4', b'\x91',
  b'\x25', b'\x4C', b'\x92', b'\xB2', b'\x89', b'\x38', b'\x9F', b'\xC0',
  b'\x32', b'\x24', b'\xF6', b'\x30', b'\x0A', b'\x06', b'\x08', b'\x2A',
  b'\x86', b'\x48', b'\xCE', b'\x3D', b'\x04', b'\x03', b'\x02', b'\x30',
  b'\x3A', b'\x31', b'\x17', b'\x30', b'\x15', b'\x06', b'\x03', b'\x55',
  b'\x04', b'\x03', b'\x0C', b'\x0E', b'\x63', b'\x61', b'\x2E', b'\x65',
  b'\x78', b'\x61', b'\x6D', b'\x70', b'\x6C', b'\x65', b'\x2E', b'\x63',
  b'\x6F', b'\x6D', b'\x31', b'\x12', b'\x30', b'\x10', b'\x06', b'\x03',
  b'\x55', b'\x04', b'\x0A', b'\x0C', b'\x09', b'\x45', b'\x63', b'\x6D',
  b'\x65', b'\x20', b'\x54', b'\x65', b'\x73', b'\x74', b'\x31', b'\x0B',
  b'\x30', b'\x09', b'\x06', b'\x03', b'\x55', b'\x04', b'\x06', b'\x13',
  b'\x02', b'\x43', b'\x4E', b'\x30', b'\x1E', b'\x17', b'\x0D', b'\x32',
  b'\x36', b'\x30', b'\x38', b'\x31', b'\x37', b'\x30', b'\x30', b'\x34',
  b'\x37', b'\x30', b'\x38', b'\x5A', b'\x17', b'\x0D', b'\x32', b'\x37',
  b'\x30', b'\x38', b'\x31', b'\x37', b'\x30', b'\x30', b'\x34', b'\x37',
  b'\x30', b'\x38', b'\x5A', b'\x30', b'\x3A', b'\x31', b'\x17', b'\x30',
  b'\x15', b'\x06', b'\x03', b'\x55', b'\x04', b'\x03', b'\x0C', b'\x0E',
  b'\x63', b'\x61', b'\x2E', b'\x65', b'\x78', b'\x61', b'\x6D', b'\x70',
  b'\x6C', b'\x65', b'\x2E', b'\x63', b'\x6F', b'\x6D', b'\x31', b'\x12',
  b'\x30', b'\x10', b'\x06', b'\x03', b'\x55', b'\x04', b'\x0A', b'\x0C',
  b'\x09', b'\x45', b'\x63', b'\x6D', b'\x65', b'\x20', b'\x54', b'\x65',
  b'\x73', b'\x74', b'\x31', b'\x0B', b'\x30', b'\x09', b'\x06', b'\x03',
  b'\x55', b'\x04', b'\x06', b'\x13', b'\x02', b'\x43', b'\x4E', b'\x30',
  b'\x59', b'\x30', b'\x13', b'\x06', b'\x07', b'\x2A', b'\x86', b'\x48',
  b'\xCE', b'\x3D', b'\x02', b'\x01', b'\x06', b'\x08', b'\x2A', b'\x86',
  b'\x48', b'\xCE', b'\x3D', b'\x03', b'\x01', b'\x07', b'\x03', b'\x42',
  b'\x00', b'\x04', b'\xD1', b'\x44', b'\xD6', b'\x86', b'\x5B', b'\xDB',
  b'\xFB', b'\x1A', b'\xBB', b'\x13', b'\xB5', b'\x75', b'\x35', b'\x34',
  b'\x29', b'\xBE', b'\x42', b'\xFF', b'\x13', b'\x9B', b'\x1D', b'\xED',
  b'\x32', b'\x04', b'\xB8', b'\x22', b'\x68', b'\x10', b'\x4C', b'\x3F',
  b'\x97', b'\x51', b'\xD8', b'\x7C', b'\x6E', b'\x6C', b'\xC6', b'\x66',
  b'\x53', b'\xEF', b'\x76', b'\x37', b'\xAB', b'\xC3', b'\x83', b'\xD1',
  b'\xE2', b'\xC8', b'\x22', b'\x1A', b'\xFE', b'\x1E', b'\xDB', b'\x1D',
  b'\x0B', b'\xA6', b'\xE9', b'\x57', b'\xBF', b'\x8E', b'\x9F', b'\x82',
  b'\x27', b'\x46', b'\xA3', b'\x45', b'\x30', b'\x43', b'\x30', b'\x12',
  b'\x06', b'\x03', b'\x55', b'\x1D', b'\x13', b'\x01', b'\x01', b'\xFF',
  b'\x04', b'\x08', b'\x30', b'\x06', b'\x01', b'\x01', b'\xFF', b'\x02',
  b'\x01', b'\x00', b'\x30', b'\x0E', b'\x06', b'\x03', b'\x55', b'\x1D',
  b'\x0F', b'\x01', b'\x01', b'\xFF', b'\x04', b'\x04', b'\x03', b'\x02',
  b'\x01', b'\x06', b'\x30', b'\x1D', b'\x06', b'\x03', b'\x55', b'\x1D',
  b'\x0E', b'\x04', b'\x16', b'\x04', b'\x14', b'\x9E', b'\xEF', b'\x26',
  b'\x6E', b'\x67', b'\x36', b'\xEA', b'\xB5', b'\xF6', b'\x29', b'\xAE',
  b'\x43', b'\xB8', b'\x44', b'\xC6', b'\x42', b'\x2B', b'\x1C', b'\x69',
  b'\x95', b'\x30', b'\x0A', b'\x06', b'\x08', b'\x2A', b'\x86', b'\x48',
  b'\xCE', b'\x3D', b'\x04', b'\x03', b'\x02', b'\x03', b'\x47', b'\x00',
  b'\x30', b'\x44', b'\x02', b'\x20', b'\x0B', b'\xF4', b'\xEF', b'\x85',
  b'\x4D', b'\x63', b'\x4B', b'\xFC', b'\x58', b'\x38', b'\x43', b'\xB6',
  b'\xDF', b'\xFB', b'\x86', b'\x3E', b'\xA8', b'\x16', b'\x6B', b'\x27',
  b'\xBA', b'\xDC', b'\x6F', b'\xA4', b'\xE5', b'\xC8', b'\x7A', b'\x66',
  b'\x9A', b'\x3B', b'\x3F', b'\x99', b'\x02', b'\x20', b'\x3F', b'\xB4',
  b'\x38', b'\xDB', b'\x4E', b'\xC7', b'\x30', b'\x7D', b'\x3E', b'\x41',
  b'\x90', b'\x99', b'\x1E', b'\x71', b'\xA7', b'\xD8', b'\x6C', b'\x9E',
  b'\xB9', b'\x33', b'\xDC', b'\x3E', b'\x85', b'\xD8', b'\xA3', b'\x93',
  b'\xCB', b'\x29', b'\x91', b'\x2D', b'\x89', b'\x26',
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
  assert_eq(cert.not_before.to_rfc3339(), "2026-08-17T00:47:03Z")
  assert_eq(cert.not_after.to_rfc3339(), "2027-08-17T00:47:03Z")
  assert_eq(cert.public_key_algorithm, Rsa(modulus_bits=Some(2048)))
  assert_eq(cert.signature_value.length(), 256)
}

///|
test "parse_cert decodes extensions on the RSA certificate" {
  let cert = match parse_cert(rsa_cert_der) {
    Ok(c) => c
    Err(e) => fail("parse failed: " + e)
  }
  // SAN, keyUsage, extendedKeyUsage, basicConstraints, subjectKeyIdentifier
  assert_eq(cert.extensions.length(), 5)
  let bc = match cert.basic_constraints {
    Some(bc) => bc
    None => fail("expected basicConstraints")
  }
  assert_eq(bc.is_ca, false)
  assert_eq(bc.path_len, None)
  let ku = match cert.key_usage {
    Some(ku) => ku
    None => fail("expected keyUsage")
  }
  assert_eq(ku.digital_signature, true)
  assert_eq(ku.key_encipherment, true)
  assert_eq(ku.key_cert_sign, false)
  assert_eq(ku.crl_sign, false)
  assert_eq(
    cert.subject_alt_names,
    [
      DnsName("example.com"),
      DnsName("*.example.com"),
      IpAddress(Bytes::from_array([b'\x7F', b'\x00', b'\x00', b'\x01'])),
      Rfc822Name("admin@example.com"),
      Uri("https://example.com"),
    ],
  )
  // extKeyUsage: serverAuth
  let eku = match cert.ext_key_usage {
    Some(e) => e
    None => fail("expected extKeyUsage")
  }
  assert_eq(eku.purposes.length(), 1)
  assert_eq(eku.purposes[0], ServerAuth)
  assert_eq(eku.to_display(), "serverAuth")
  // subjectKeyIdentifier: 20-byte SHA-1 thumbprint
  let kid = match cert.subject_key_id {
    Some(k) => k
    None => fail("expected subjectKeyIdentifier")
  }
  assert_eq(kid.length(), 20)
  assert_eq(kid[0].to_int(), 0xE4)
  assert_eq(kid[19].to_int(), 0xE5)
  // authorityKeyIdentifier absent on self-signed cert
  assert_eq(cert.authority_key_id, None)
  // nameConstraints and certificatePolicies absent
  assert_eq(cert.name_constraints, None)
  assert_eq(cert.certificate_policies.length(), 0)
}

///|
test "parse_cert on a real EC P-256 CA certificate" {
  let cert = match parse_cert(ec_cert_der) {
    Ok(c) => c
    Err(e) => fail("parse failed: " + e)
  }
  assert_eq(cert.version, 2) // v3
  assert_eq(cert.signature_algorithm, "ecdsa-with-SHA256")
  assert_eq(
    cert.subject_dn_string(),
    "commonName=ca.example.com, organizationName=Ecme Test, countryName=CN",
  )
  assert_eq(cert.not_before.to_rfc3339(), "2026-08-17T00:47:08Z")
  assert_eq(cert.not_after.to_rfc3339(), "2027-08-17T00:47:08Z")
  assert_eq(cert.public_key_algorithm, Ec(curve=Some("P-256")))
  // basicConstraints, keyUsage, subjectKeyIdentifier
  assert_eq(cert.extensions.length(), 3)
  let bc = match cert.basic_constraints {
    Some(bc) => bc
    None => fail("expected basicConstraints")
  }
  assert_eq(bc.is_ca, true)
  assert_eq(bc.path_len, Some(0))
  let ku = match cert.key_usage {
    Some(ku) => ku
    None => fail("expected keyUsage")
  }
  assert_eq(ku.key_cert_sign, true)
  assert_eq(ku.crl_sign, true)
  assert_eq(ku.digital_signature, false)
  assert_eq(cert.subject_alt_names.length(), 0)
  assert_eq(cert.ext_key_usage, None)
  let kid = match cert.subject_key_id {
    Some(k) => k
    None => fail("expected subjectKeyIdentifier")
  }
  assert_eq(kid.length(), 20)
  assert_eq(kid[0].to_int(), 0x9E)
  assert_eq(cert.authority_key_id, None)
  assert_eq(cert.name_constraints, None)
  assert_eq(cert.certificate_policies.length(), 0)
}

///|
let nc_cp_cert_der : Bytes = Bytes::from_array([
  b'\x30', b'\x82', b'\x03', b'\x70', b'\x30', b'\x82', b'\x02', b'\x58', b'\xA0', b'\x03', b'\x02', b'\x01',
  b'\x02', b'\x02', b'\x14', b'\x0A', b'\x9E', b'\xD7', b'\xD9', b'\x30', b'\x51', b'\x24', b'\x29', b'\x64',
  b'\x07', b'\xB9', b'\xE9', b'\xB9', b'\x14', b'\x0D', b'\xD3', b'\x1F', b'\x01', b'\x07', b'\x52', b'\x30',
  b'\x0D', b'\x06', b'\x09', b'\x2A', b'\x86', b'\x48', b'\x86', b'\xF7', b'\x0D', b'\x01', b'\x01', b'\x0B',
  b'\x05', b'\x00', b'\x30', b'\x37', b'\x31', b'\x19', b'\x30', b'\x17', b'\x06', b'\x03', b'\x55', b'\x04',
  b'\x03', b'\x0C', b'\x10', b'\x74', b'\x65', b'\x73', b'\x74', b'\x2E', b'\x65', b'\x78', b'\x61', b'\x6D',
  b'\x70', b'\x6C', b'\x65', b'\x2E', b'\x63', b'\x6F', b'\x6D', b'\x31', b'\x0D', b'\x30', b'\x0B', b'\x06',
  b'\x03', b'\x55', b'\x04', b'\x0A', b'\x0C', b'\x04', b'\x54', b'\x65', b'\x73', b'\x74', b'\x31', b'\x0B',
  b'\x30', b'\x09', b'\x06', b'\x03', b'\x55', b'\x04', b'\x06', b'\x13', b'\x02', b'\x55', b'\x53', b'\x30',
  b'\x1E', b'\x17', b'\x0D', b'\x32', b'\x36', b'\x30', b'\x38', b'\x31', b'\x37', b'\x30', b'\x36', b'\x32',
  b'\x32', b'\x30', b'\x37', b'\x5A', b'\x17', b'\x0D', b'\x32', b'\x37', b'\x30', b'\x38', b'\x31', b'\x37',
  b'\x30', b'\x36', b'\x32', b'\x32', b'\x30', b'\x37', b'\x5A', b'\x30', b'\x37', b'\x31', b'\x19', b'\x30',
  b'\x17', b'\x06', b'\x03', b'\x55', b'\x04', b'\x03', b'\x0C', b'\x10', b'\x74', b'\x65', b'\x73', b'\x74',
  b'\x2E', b'\x65', b'\x78', b'\x61', b'\x6D', b'\x70', b'\x6C', b'\x65', b'\x2E', b'\x63', b'\x6F', b'\x6D',
  b'\x31', b'\x0D', b'\x30', b'\x0B', b'\x06', b'\x03', b'\x55', b'\x04', b'\x0A', b'\x0C', b'\x04', b'\x54',
  b'\x65', b'\x73', b'\x74', b'\x31', b'\x0B', b'\x30', b'\x09', b'\x06', b'\x03', b'\x55', b'\x04', b'\x06',
  b'\x13', b'\x02', b'\x55', b'\x53', b'\x30', b'\x82', b'\x01', b'\x22', b'\x30', b'\x0D', b'\x06', b'\x09',
  b'\x2A', b'\x86', b'\x48', b'\x86', b'\xF7', b'\x0D', b'\x01', b'\x01', b'\x01', b'\x05', b'\x00', b'\x03',
  b'\x82', b'\x01', b'\x0F', b'\x00', b'\x30', b'\x82', b'\x01', b'\x0A', b'\x02', b'\x82', b'\x01', b'\x01',
  b'\x00', b'\xA1', b'\x8C', b'\x58', b'\xEA', b'\x9A', b'\xC7', b'\x9A', b'\xCA', b'\x96', b'\x42', b'\x09',
  b'\x0B', b'\xF5', b'\x84', b'\x64', b'\x19', b'\x19', b'\x85', b'\x07', b'\x64', b'\xD8', b'\x56', b'\x56',
  b'\x57', b'\x8D', b'\x64', b'\x19', b'\xDD', b'\x2E', b'\xB8', b'\x0A', b'\xD0', b'\x36', b'\xF7', b'\x1C',
  b'\x57', b'\x75', b'\x4C', b'\xFC', b'\xFB', b'\x3C', b'\xAD', b'\x32', b'\x45', b'\x96', b'\x5D', b'\xD9',
  b'\x3D', b'\xD1', b'\x9A', b'\x5F', b'\x96', b'\x88', b'\x98', b'\xBF', b'\xC9', b'\x6A', b'\x21', b'\x20',
  b'\xEB', b'\x7A', b'\xBD', b'\x1C', b'\x0F', b'\xC4', b'\x37', b'\xF2', b'\xA1', b'\xC6', b'\x06', b'\x81',
  b'\xDA', b'\x2D', b'\xFF', b'\x39', b'\xD9', b'\xAB', b'\x85', b'\xD9', b'\x0F', b'\xF3', b'\xE0', b'\x1E',
  b'\x67', b'\xDC', b'\x7A', b'\x14', b'\x18', b'\xC4', b'\x5D', b'\xD0', b'\x9F', b'\x55', b'\xBE', b'\xFD',
  b'\x5E', b'\x6F', b'\x71', b'\xEB', b'\x39', b'\xC8', b'\x49', b'\xE6', b'\x81', b'\x53', b'\x08', b'\x17',
  b'\x1F', b'\xAA', b'\x91', b'\x9C', b'\x0C', b'\xCF', b'\x0C', b'\x3E', b'\x53', b'\x31', b'\xC8', b'\x4E',
  b'\x7C', b'\x0E', b'\xE9', b'\x56', b'\xA9', b'\x2B', b'\x88', b'\x43', b'\x00', b'\x1B', b'\x10', b'\x4F',
  b'\x3D', b'\x87', b'\xF8', b'\x42', b'\xFA', b'\x13', b'\x0A', b'\xEE', b'\x88', b'\xDF', b'\x44', b'\x99',
  b'\xF7', b'\xFD', b'\xA6', b'\xC9', b'\xE3', b'\xE1', b'\xF8', b'\x1E', b'\xA8', b'\xA3', b'\x9D', b'\x30',
  b'\x21', b'\x7F', b'\x23', b'\x4E', b'\x09', b'\x5C', b'\xB0', b'\x8B', b'\xB6', b'\x17', b'\x4A', b'\x93',
  b'\xE2', b'\x77', b'\xBD', b'\x7E', b'\x82', b'\x36', b'\x4D', b'\x88', b'\xBB', b'\x2C', b'\x90', b'\xA0',
  b'\x31', b'\xEB', b'\x14', b'\xBC', b'\x28', b'\xC3', b'\x1C', b'\x67', b'\xF4', b'\x1B', b'\xF1', b'\x52',
  b'\xA5', b'\xD9', b'\x4C', b'\x34', b'\xDA', b'\xC2', b'\x55', b'\x8D', b'\x49', b'\x03', b'\x75', b'\x55',
  b'\x05', b'\x07', b'\xFE', b'\x12', b'\x9B', b'\x82', b'\x16', b'\x5A', b'\x91', b'\x70', b'\x40', b'\x2E',
  b'\x5B', b'\x2A', b'\x62', b'\x37', b'\x43', b'\x3C', b'\x01', b'\xD8', b'\xF9', b'\x85', b'\x18', b'\xE5',
  b'\x8B', b'\x0E', b'\xF6', b'\x76', b'\x33', b'\x04', b'\xB5', b'\x09', b'\x3B', b'\x46', b'\xFA', b'\x81',
  b'\xD7', b'\x0D', b'\x4F', b'\x6F', b'\x0C', b'\x00', b'\x06', b'\xA9', b'\x4D', b'\x02', b'\xCD', b'\xF7',
  b'\x4B', b'\x68', b'\xB1', b'\xF2', b'\x67', b'\x02', b'\x03', b'\x01', b'\x00', b'\x01', b'\xA3', b'\x74',
  b'\x30', b'\x72', b'\x30', b'\x2D', b'\x06', b'\x03', b'\x55', b'\x1D', b'\x1E', b'\x01', b'\x01', b'\xFF',
  b'\x04', b'\x23', b'\x30', b'\x21', b'\xA0', b'\x10', b'\x30', b'\x0E', b'\x82', b'\x0C', b'\x2E', b'\x65',
  b'\x78', b'\x61', b'\x6D', b'\x70', b'\x6C', b'\x65', b'\x2E', b'\x63', b'\x6F', b'\x6D', b'\xA1', b'\x0D',
  b'\x30', b'\x0B', b'\x82', b'\x09', b'\x2E', b'\x65', b'\x76', b'\x69', b'\x6C', b'\x2E', b'\x63', b'\x6F',
  b'\x6D', b'\x30', b'\x22', b'\x06', b'\x03', b'\x55', b'\x1D', b'\x20', b'\x04', b'\x1B', b'\x30', b'\x19',
  b'\x30', b'\x08', b'\x06', b'\x06', b'\x67', b'\x81', b'\x0C', b'\x01', b'\x02', b'\x01', b'\x30', b'\x0D',
  b'\x06', b'\x0B', b'\x2B', b'\x06', b'\x01', b'\x04', b'\x01', b'\xB1', b'\x3E', b'\x01', b'\x02', b'\x02',
  b'\x03', b'\x30', b'\x1D', b'\x06', b'\x03', b'\x55', b'\x1D', b'\x0E', b'\x04', b'\x16', b'\x04', b'\x14',
  b'\xF1', b'\x3C', b'\x19', b'\xB0', b'\x2A', b'\x6C', b'\x78', b'\x9C', b'\x23', b'\x8F', b'\x2E', b'\x8E',
  b'\x5F', b'\x98', b'\xF1', b'\x2A', b'\x6B', b'\xB4', b'\xF2', b'\xF1', b'\x30', b'\x0D', b'\x06', b'\x09',
  b'\x2A', b'\x86', b'\x48', b'\x86', b'\xF7', b'\x0D', b'\x01', b'\x01', b'\x0B', b'\x05', b'\x00', b'\x03',
  b'\x82', b'\x01', b'\x01', b'\x00', b'\x48', b'\x3D', b'\xA4', b'\x6F', b'\x79', b'\x22', b'\x64', b'\x1D',
  b'\x93', b'\x85', b'\x26', b'\x14', b'\x47', b'\xB1', b'\xFC', b'\xC6', b'\xBE', b'\x06', b'\xEA', b'\xAC',
  b'\x23', b'\x45', b'\x9F', b'\xF2', b'\x3E', b'\x24', b'\x4F', b'\x44', b'\x06', b'\x32', b'\xA8', b'\x1D',
  b'\x6B', b'\x6D', b'\xF5', b'\x7D', b'\xB0', b'\xA2', b'\x6B', b'\xBF', b'\x7A', b'\x80', b'\x68', b'\xA2',
  b'\x8B', b'\xD8', b'\xA4', b'\x74', b'\xF5', b'\x04', b'\xA1', b'\xB2', b'\xA0', b'\x2D', b'\x6C', b'\xB0',
  b'\x5E', b'\xE8', b'\xCA', b'\x9C', b'\x90', b'\xD7', b'\xCF', b'\xF2', b'\xF3', b'\x6D', b'\xD9', b'\xFA',
  b'\x4D', b'\x5B', b'\xEB', b'\xC6', b'\x4D', b'\x4B', b'\xD7', b'\x12', b'\xF9', b'\xEC', b'\x3D', b'\x90',
  b'\x6D', b'\x07', b'\x82', b'\x0F', b'\x54', b'\x05', b'\xBF', b'\xC2', b'\x9E', b'\x5C', b'\xFF', b'\xD3',
  b'\x71', b'\xBC', b'\xA4', b'\xF5', b'\x7B', b'\x20', b'\xEA', b'\xCC', b'\xB9', b'\x72', b'\x59', b'\x0E',
  b'\x09', b'\x6F', b'\x36', b'\x14', b'\x0F', b'\xB8', b'\x23', b'\xB3', b'\x70', b'\x3D', b'\xAE', b'\xBF',
  b'\xF6', b'\x8C', b'\xC8', b'\xA8', b'\xC9', b'\xED', b'\x85', b'\x52', b'\xD5', b'\xA0', b'\x33', b'\xBA',
  b'\x02', b'\x6D', b'\xEC', b'\xFA', b'\x21', b'\x31', b'\x77', b'\x7D', b'\x80', b'\xF0', b'\x81', b'\x81',
  b'\x14', b'\x0E', b'\xD2', b'\x32', b'\x54', b'\x4A', b'\x49', b'\xA2', b'\x8D', b'\xB5', b'\x4E', b'\x8B',
  b'\xAC', b'\x1A', b'\x11', b'\x31', b'\x32', b'\x17', b'\x35', b'\x1C', b'\xEF', b'\xB2', b'\xED', b'\x56',
  b'\xA9', b'\x58', b'\xD8', b'\x14', b'\x38', b'\x3B', b'\x37', b'\x08', b'\xC8', b'\x5D', b'\xB9', b'\x4A',
  b'\x16', b'\x6A', b'\x31', b'\x0F', b'\xFB', b'\x51', b'\xD3', b'\x8A', b'\x6F', b'\x6F', b'\x46', b'\x3D',
  b'\x90', b'\xD5', b'\x07', b'\x64', b'\x6A', b'\xBA', b'\x83', b'\x7B', b'\x83', b'\x96', b'\x25', b'\x71',
  b'\x35', b'\xA1', b'\x93', b'\x71', b'\x32', b'\x0F', b'\x75', b'\xEB', b'\xC3', b'\x6C', b'\x4F', b'\x64',
  b'\x63', b'\xB6', b'\x28', b'\x6E', b'\x3E', b'\x03', b'\x2F', b'\xA5', b'\xA0', b'\x1B', b'\x66', b'\xFE',
  b'\xAD', b'\x27', b'\x93', b'\x1E', b'\x52', b'\x2F', b'\x2B', b'\x67', b'\xB2', b'\x77', b'\x55', b'\x7D',
  b'\xFD', b'\xB1', b'\x68', b'\x1C', b'\x2F', b'\x3D', b'\x38', b'\x57', b'\x04', b'\x19', b'\x83', b'\x40',
  b'\x46', b'\xD2', b'\xC8', b'\xAD', b'\x7C', b'\x15', b'\x8C', b'\x84',
])

///|
test "parse_cert decodes nameConstraints and certificatePolicies" {
  let cert = match parse_cert(nc_cp_cert_der) {
    Ok(c) => c
    Err(e) => fail("parse failed: " + e)
  }
  assert_eq(cert.version, 2) // v3
  assert_eq(cert.signature_algorithm, "sha256WithRSAEncryption")
  assert_eq(
    cert.subject_dn_string(),
    "commonName=test.example.com, organizationName=Test, countryName=US",
  )
  // nameConstraints, certificatePolicies, subjectKeyIdentifier
  assert_eq(cert.extensions.length(), 3)
  // nameConstraints: critical, permitted DNS:.example.com, excluded DNS:.evil.com
  let nc = match cert.name_constraints {
    Some(n) => n
    None => fail("expected nameConstraints")
  }
  assert_eq(nc.permitted_subtrees.length(), 1)
  assert_eq(nc.permitted_subtrees[0].base, DnsName(".example.com"))
  assert_eq(nc.excluded_subtrees.length(), 1)
  assert_eq(nc.excluded_subtrees[0].base, DnsName(".evil.com"))
  assert_eq(
    nc.to_display(),
    "permitted:DNS:.example.com, excluded:DNS:.evil.com",
  )
  // certificatePolicies: two policies without qualifiers
  assert_eq(cert.certificate_policies.length(), 2)
  assert_eq(cert.certificate_policies[0].oid, "2.23.140.1.2.1")
  assert_eq(cert.certificate_policies[0].qualifiers.length(), 0)
  assert_eq(cert.certificate_policies[1].oid, "1.3.6.1.4.1.6334.1.2.2.3")
  assert_eq(cert.certificate_policies[1].qualifiers.length(), 0)
}

///|
test "parse_cert rejects non-certificate input" {
  // A SEQUENCE { INTEGER 1 } is valid DER but not a certificate.
  let buf = Bytes::from_array([b'\x30', b'\x03', b'\x02', b'\x01', b'\x01'])
  guard parse_cert(buf) is Err(_) else { fail("expected error") }
}
