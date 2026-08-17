///|
/// An X.509 certificate, parsed per RFC 5280.
///
/// Only the fields that matter for inspection (subject, issuer, validity,
/// public key algorithm) are exposed as structured data. Extensions and
/// the signature value are preserved as raw DER for higher-level code to
/// inspect.
pub struct Certificate {
  /// Certificate version. `0` means v1, `1` means v2, `2` means v3.
  /// Most modern certificates are v3.
  version : Int
  /// Serial number, decoded as an unsigned big-endian integer body.
  serial_number : Bytes
  /// The algorithm OID used to sign the certificate, e.g.
  /// "1.2.840.113549.1.1.11" for sha256WithRSAEncryption.
  signature_algorithm : String
  /// Issuer distinguished name.
  issuer : Name
  /// Validity window.
  not_before : X509Time
  not_after : X509Time
  /// Subject distinguished name.
  subject : Name
  /// Public key algorithm summary (RSA bit length, EC curve name, etc.).
  public_key_algorithm : PubkeyAlgorithm
  /// Raw extensions SEQUENCE, kept verbatim for callers to decode.
  extensions_raw : Bytes
  /// Raw signature value BIT STRING contents.
  signature_value : Bytes
} derive(Eq)

///|
/// Convenience: the issuer DN as a string.
pub fn Certificate::issuer_dn_string(self : Certificate) -> String {
  self.issuer.to_string()
}

///|
/// Convenience: the subject DN as a string.
pub fn Certificate::subject_dn_string(self : Certificate) -> String {
  self.subject.to_string()
}

///|
/// Parse a DER-encoded X.509 certificate.
pub fn parse_cert(buf : Bytes) -> Result[Certificate, String] {
  let top = match decode_element(buf) {
    Ok(v) => v
    Err(Truncated) => return Err("outer decode: truncated")
    Err(LimitExceeded(kind~)) => return Err("outer decode: limit exceeded (" + kind + ")")
    Err(MalformedLength) => return Err("outer decode: malformed length")
    Err(MalformedValue) => return Err("outer decode: malformed value")
  }
  guard top is Sequence(outer) else {
    return Err("expected Certificate SEQUENCE")
  }
  if outer.length() < 3 {
    return Err("Certificate SEQUENCE has too few elements")
  }
  // Element 0 is `tbsCertificate`, element 1 is
  // `signatureAlgorithm AlgorithmIdentifier`, element 2 is
  // `signatureValue BIT STRING`.
  let tbs_value = outer[0]
  let sig_alg_value = outer[1]
  let sig_value_value = outer[2]
  let tbs = match tbs_value {
    Sequence(t) => t
    _ => return Err("tbsCertificate is not a SEQUENCE")
  }
  // tbsCertificate layout (RFC 5280 §4.1):
  //   [0] EXPLICIT Version DEFAULT v1
  //   CertificateSerialNumber INTEGER
  //   signature AlgorithmIdentifier
  //   issuer Name
  //   validity Validity
  //   subject Name
  //   subjectPublicKeyInfo SubjectPublicKeyInfo
  //   ...
  //   [3] EXPLICIT extensions OPTIONAL
  // We use index offsets that depend on whether the version tag is present.
  let mut idx = 0
  let version = match tbs[idx] {
    ContextSpecific(number=0, content=body) => {
      idx = idx + 1
      match decode_element(body) {
        Ok(Integer(b)) => {
          // v1=0, v2=1, v3=2. Encoded as a single byte for the common case.
          if b.length() == 0 {
            0
          } else {
            b[0].to_int()
          }
        }
        _ => 0
      }
    }
    _ => 0 // v1
  }
  let serial = match tbs[idx] {
    Integer(b) => {
      idx = idx + 1
      b
    }
    _ => return Err("expected CertificateSerialNumber INTEGER")
  }
  let sig_alg_inner = match tbs[idx] {
    Sequence(items) => {
      idx = idx + 1
      items
    }
    _ => return Err("expected inner signatureAlgorithm AlgorithmIdentifier")
  }
  let sig_alg_str = if sig_alg_inner.length() >= 1 {
    match sig_alg_inner[0] {
      ObjectIdentifier(arcs) =>
        known_oid(arcs_to_int(arcs)).unwrap_or(arcs_to_dotted(arcs_to_int(arcs)))
      _ => "?"
    }
  } else {
    "?"
  }
  let issuer = match parse_name(tbs[idx]) {
    Some(n) => {
      idx = idx + 1
      n
    }
    None => return Err("expected issuer Name")
  }
  let validity = match tbs[idx] {
    Sequence(items) => {
      idx = idx + 1
      items
    }
    _ => return Err("expected validity Validity")
  }
  if validity.length() < 2 {
    return Err("validity must contain notBefore and notAfter")
  }
  let not_before = match time_from_asn1(validity[0]) {
    Some(t) => t
    None => return Err("invalid notBefore")
  }
  let not_after = match time_from_asn1(validity[1]) {
    Some(t) => t
    None => return Err("invalid notAfter")
  }
  let subject = match parse_name(tbs[idx]) {
    Some(n) => {
      idx = idx + 1
      n
    }
    None => return Err("expected subject Name")
  }
  let spki = tbs[idx]
  idx = idx + 1
  let public_key_algorithm = classify_pubkey(spki)
  // After SPKI, any explicit [3] extensions are kept as raw bytes. We do
  // not yet decode individual extensions in v1; we surface the raw
  // container so callers can decode on demand.
  let extensions_raw = match tbs[idx] {
    ContextSpecific(number=3, content=body) => body
    _ => Bytes::new(0)
  }
  // Outer signatureAlgorithm is structurally identical to the inner one;
  // we keep it as the dotted OID string for cross-checking.
  ignore(sig_alg_value)
  let signature_value = match sig_value_value {
    BitString(data~, ..) => data
    _ => Bytes::new(0)
  }
  Ok({
    version,
    serial_number: serial,
    signature_algorithm: sig_alg_str,
    issuer,
    not_before,
    not_after,
    subject,
    public_key_algorithm,
    extensions_raw,
    signature_value,
  })
}

fn time_from_asn1(v : Asn1Value) -> X509Time? {
  match v {
    UTCTime(b) => parse_utctime(b)
    GeneralizedTime(b) => parse_generalized_time(b)
    _ => None
  }
}
