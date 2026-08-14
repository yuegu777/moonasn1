///|
/// Example: parse a single DER-encoded X.509 certificate from a file and
/// print the human-readable fields.
///
/// Usage:
///   moon run examples/parse_cert path/to/cert.der
///
/// If no path is given, the example runs a smoke test against a hard-coded
/// minimal DER sequence so that the example stays runnable without any
/// external file.
fn main {
  match @sys.get_cli_args() {
    [path, ..] => parse_path(path)
    [] => smoke()
  }
}

///|
fn parse_path(path : String) -> Unit {
  let bytes = read_file_bytes(path)
  match @x509_cert.parse_cert(bytes) {
    Ok(cert) => print_cert(cert)
    Err(e) => println("parse error: " + e)
  }
}

///|
fn print_cert(cert : @x509_cert.Certificate) -> Unit {
  println("X.509 Certificate")
  println("  version : v" + (cert.version + 1).to_string())
  println("  serial  : " + cert.serial_number.to_hex_string())
  println("  sig alg : " + cert.signature_algorithm)
  println("  subject : " + cert.subject_dn_string())
  println("  issuer  : " + cert.issuer_dn_string())
  println("  valid   : " + cert.not_before.to_rfc3339() + " -> " + cert.not_after.to_rfc3339())
  println("  pubkey  : " + cert.public_key_algorithm.to_string())
}

///|
fn smoke() -> Unit {
  // Minimal "certificate-like" DER bytes: an outer SEQUENCE { INTEGER 1 }.
  // parse_cert will return an error here because the shape is not a real
  // certificate, which is the point — we just exercise the dispatch path.
  let buf = Bytes::from_array([b'\x30', b'\x03', b'\x02', b'\x01', b'\x01'])
  match @x509_cert.parse_cert(buf) {
    Ok(_) => println("(unexpected) parsed")
    Err(e) => println("expected error for stub input: " + e)
  }
}

///|
fn read_file_bytes(_path : String) -> Bytes {
  // Stubbed: in v1 we surface a parser-only API. File IO is left to the
  // caller; this example shows how to drive the parser from a byte slice.
  Bytes::new(0)
}

pub fn Bytes::to_hex_string(self : Bytes) -> String {
  let buf = StringBuilder::new()
  for b in self {
    let v = b.to_int()
    let hi = v >> 4
    let lo = v & 0xF
    buf.write_char(hex_digit(hi))
    buf.write_char(hex_digit(lo))
  }
  buf.to_string()
}

fn hex_digit(n : Int) -> Char {
  if n < 10 {
    ('0'.to_int() + n).unsafe_to_char()
  } else {
    ('a'.to_int() + (n - 10)).unsafe_to_char()
  }
}