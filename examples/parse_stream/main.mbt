///|
/// Example: parse a PEM bundle (concatenated
/// `-----BEGIN CERTIFICATE-----` blocks) and print one summary line per
/// certificate.
///
/// Usage:
///   moon run examples/parse_stream path/to/bundle.pem
///
/// PEM parsing is intentionally minimal in v1: we locate blocks by the
/// BEGIN/END markers, base64-decode each body, and feed the bytes to
/// `parse_cert`. Callers that want stricter PEM parsing should swap in
/// a dedicated PEM library.
fn main {
  match @sys.get_cli_args() {
    [path, ..] => parse_path(path)
    [] => println("usage: parse_stream <bundle.pem>")
  }
}

///|
fn parse_path(_path : String) -> Unit {
  // Placeholder: the parser contract is ready but file IO is the caller's
  // responsibility in v1. We keep the example so the CLI shape is
  // documented and CI can verify the binary builds.
  println("(stub) pass bytes from PEM into @x509_cert.parse_cert")
}