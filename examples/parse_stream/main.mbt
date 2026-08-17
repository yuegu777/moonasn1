///|
/// Example: parse a PEM bundle (concatenated
/// `-----BEGIN CERTIFICATE-----` blocks) and print one summary line per
/// certificate.
///
/// PEM handling here is intentionally minimal: find BEGIN/END CERTIFICATE
/// markers, base64-decode each body with moonbitlang/core, and hand the
/// bytes to the parser. Swap in your own PEM text to inspect other bundles.
///
/// Usage:
///   moon run examples/parse_stream
///   moon run --target native examples/parse_stream
fn main {
  let mut count = 0
  for der in pem_certificates(example_pem) {
    count = count + 1
    match @moonasn1.parse_cert(der) {
      Ok(cert) =>
        println(
          "#" +
          count.to_string() +
          " subject=" +
          cert.subject_dn_string() +
          " issuer=" +
          cert.issuer_dn_string() +
          " valid=" +
          cert.not_before.to_rfc3339() +
          "->" +
          cert.not_after.to_rfc3339() +
          " pubkey=" +
          cert.public_key_algorithm.to_display(),
        )
      Err(e) => println("#" + count.to_string() + " parse error: " + e)
    }
  }
  if count == 0 {
    println("no PEM certificate blocks found")
  }
}

///|
let example_pem : String =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIDHTCCAgWgAwIBAgIUbQKZ82GNYAlcvVIqoeYcAgddqjQwDQYJKoZIhvcNAQEL\n" +
  "BQAwNzEUMBIGA1UEAwwLZXhhbXBsZS5jb20xEjAQBgNVBAoMCUFjbWUgVGVzdDEL\n" +
  "MAkGA1UEBhMCVVMwHhcNMjYwODE3MDAyNTA3WhcNMjcwODE3MDAyNTA3WjA3MRQw\n" +
  "EgYDVQQDDAtleGFtcGxlLmNvbTESMBAGA1UECgwJQWNtZSBUZXN0MQswCQYDVQQG\n" +
  "EwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALZ6573r+zjH/tG3\n" +
  "OKS4Fa7FZjyp5cwf8vwh0f2yEavZTmI4Yd0QF675Bxn9zkq2DTGeigzFLIT/dTnW\n" +
  "UQKG1tb96dSSLl8NUKT60AcPVz4MXjNvprHYSYaqzlG66csGbD5DU+YEsp7yNOJZ\n" +
  "ofaOU5lJhT++3Xu+o3vWbdsPcVNrSCsv/b+QjbthYiiteF0dAtSXieX8iWOu5fDm\n" +
  "3VBvHUq/Pu0M0aDxJyhx6WUB4H/Levb3vvkxhEiiiALNCuibPQ4fF9QKbRHK4Q+k\n" +
  "8GyrB8n4Q5jPE/gNXpu27R88h+kj/GNXupoluiJ8MpNAZGkt5K89MLsN7VJYn+7s\n" +
  "6T2kL00CAwEAAaMhMB8wHQYDVR0OBBYEFK2NI3gJGWiCgeRU3Gjp7oAp3+ZQMA0G\n" +
  "CSqGSIb3DQEBCwUAA4IBAQAT6xVKZ74adS6l1xqgt9ZwSb1ywdVMotxjHOQjE3aG\n" +
  "dTsPBhjmnga8VuKT003saYlL1dgJQ9uywwtFlc5kLIv8sxGpCD2JagbTv9PGXg5j\n" +
  "3oAqjJOyoYryT8Rh2tRdliTOJJDlBrqaRz+6SB6xrYhd9ssqfSC6IRvc5/xASDpl\n" +
  "vcmpvFjE2hg1OIrfEQJpS5BVud0CRxPWWZndEnNuarxn3Z91HDKzz902ViaN4gYC\n" +
  "UZMMRa9tBnqhq0WGUULjxowvUvj19V4lHuf077dwgW2wmxl+2PbNRIR+B5k9yCQZ\n" +
  "Hm/2f0hsFrUOBA+rpgTSdqZeufze//0oC+smXUQ4D6f8\n" +
  "-----END CERTIFICATE-----\n"

///|
/// Extract the DER bytes of every `BEGIN CERTIFICATE` block in a PEM
/// bundle. Non-certificate blocks (keys, CSRs) are skipped; lines outside
/// blocks are ignored.
fn pem_certificates(pem : String) -> Array[Bytes] {
  let out : Array[Bytes] = []
  let b64 = StringBuilder::new()
  let mut in_block = false
  for line in pem.split("\n") {
    let line = line.trim()
    if in_block {
      if line.contains("-----END CERTIFICATE-----") {
        try {
          out.push(@base64.decode(b64.to_string(), ignore_whitespace=false))
        } catch {
          _ => () // skip blocks that do not decode
        }
        b64.reset()
        in_block = false
      } else if line.length() > 0 {
        b64.write_view(line)
      }
    } else if line.contains("-----BEGIN CERTIFICATE-----") {
      in_block = true
      b64.reset()
    }
  }
  out
}
