///|
/// Example: parse a DER-encoded X.509 certificate and print its fields.
///
/// The bytes below are a real self-signed RSA-2048 certificate (generated
/// with `openssl req -x509` and `-addext` for the SAN / keyUsage /
/// basicConstraints extensions), so this example exercises the full parser
/// end to end with no file IO. Swap in your own `Bytes` from a `.der` file
/// to inspect other certificates.
///
/// Usage:
///   moon run examples/parse_cert
///   moon run --target native examples/parse_cert
fn main {
  let cert = match @moonasn1.parse_cert(example_der) {
    Ok(c) => c
    Err(e) => {
      println("parse error: " + e)
      return
    }
  }
  println("X.509 Certificate")
  println("  version : v" + (cert.version + 1).to_string())
  println("  serial  : " + to_hex(cert.serial_number))
  println("  sig alg : " + cert.signature_algorithm)
  println("  subject : " + cert.subject_dn_string())
  println("  issuer  : " + cert.issuer_dn_string())
  println("  valid   : " + cert.not_before.to_rfc3339() + " -> " + cert.not_after.to_rfc3339())
  println("  pubkey  : " + cert.public_key_algorithm.to_display())
  println("  sig     : " + to_hex(cert.signature_value)[:16].to_owned() + "...")
  println("  exts    : " + cert.extensions.length().to_string() + " extension(s)")
  match cert.basic_constraints {
    Some(bc) => println("  basic   : " + bc.to_display())
    None => ()
  }
  match cert.key_usage {
    Some(ku) => println("  keyUsage: " + ku.to_display())
    None => ()
  }
  if cert.subject_alt_names.length() > 0 {
    let buf = StringBuilder::new()
    for i, name in cert.subject_alt_names {
      if i > 0 {
        buf.write_string(", ")
      }
      buf.write_string(name.to_display())
    }
    println("  SAN     : " + buf.to_string())
  }
}

///|
let example_der : Bytes = Bytes::from_array([
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
fn to_hex(bytes : Bytes) -> String {
  let buf = StringBuilder::new()
  for b in bytes {
    let v = b.to_int()
    buf.write_char(hex_digit(v >> 4))
    buf.write_char(hex_digit(v & 0xF))
  }
  buf.to_string()
}

///|
fn hex_digit(n : Int) -> Char {
  if n < 10 {
    ('0'.to_int() + n).unsafe_to_char()
  } else {
    ('a'.to_int() + (n - 10)).unsafe_to_char()
  }
}
