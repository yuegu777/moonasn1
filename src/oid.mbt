///|
/// A small registry of OIDs that show up in X.509 certificates. The full
/// IANA / ITU-T registry is out of scope for v1; this table is enough for
/// the certificate fields and the most common extensions.
pub fn known_oid(arcs : Array[Int]) -> String? {
  let s = arcs_to_dotted(arcs)
  match s {
    // RDN attribute types (X.520 / RFC 4519)
    "2.5.4.3" => Some("commonName")
    "2.5.4.6" => Some("countryName")
    "2.5.4.7" => Some("localityName")
    "2.5.4.8" => Some("stateOrProvinceName")
    "2.5.4.10" => Some("organizationName")
    "2.5.4.11" => Some("organizationalUnitName")
    "2.5.4.5" => Some("serialNumber")
    "2.5.4.9" => Some("streetAddress")
    "2.5.4.17" => Some("postalCode")
    "0.9.2342.19200300.100.1.25" => Some("domainComponent")
    "0.9.2342.19200300.100.1.1" => Some("userid")
    "1.2.840.113549.1.9.1" => Some("emailAddress")
    // Signature algorithms (RFC 4055 / RFC 5754)
    "1.2.840.113549.1.1.5" => Some("sha1WithRSAEncryption")
    "1.2.840.113549.1.1.11" => Some("sha256WithRSAEncryption")
    "1.2.840.113549.1.1.12" => Some("sha384WithRSAEncryption")
    "1.2.840.113549.1.1.13" => Some("sha512WithRSAEncryption")
    "1.2.840.10045.4.3.2" => Some("ecdsa-with-SHA256")
    "1.2.840.10045.4.3.3" => Some("ecdsa-with-SHA384")
    "1.2.840.10045.4.3.4" => Some("ecdsa-with-SHA512")
    "2.16.840.1.101.3.4.3.17" => Some("ed25519")
    "1.3.101.112" => Some("ed25519")
    // Public key algorithms
    "1.2.840.113549.1.1.1" => Some("rsaEncryption")
    "1.2.840.10045.2.1" => Some("ecPublicKey")
    // EC curves (RFC 5480 / RFC 8422)
    "1.2.840.10045.3.1.7" => Some("P-256")
    "1.3.132.0.34" => Some("P-384")
    "1.3.132.0.35" => Some("P-521")
    "1.3.132.0.10" => Some("secp256k1")
    // Extensions (RFC 5280 §4.2)
    "2.5.29.14" => Some("subjectKeyIdentifier")
    "2.5.29.15" => Some("keyUsage")
    "2.5.29.17" => Some("subjectAltName")
    "2.5.29.18" => Some("issuerAltName")
    "2.5.29.19" => Some("basicConstraints")
    "2.5.29.30" => Some("nameConstraints")
    "2.5.29.31" => Some("cRLDistributionPoints")
    "2.5.29.32" => Some("certificatePolicies")
    "2.5.29.35" => Some("authorityKeyIdentifier")
    "2.5.29.37" => Some("extKeyUsage")
    // Extended Key Usage purposes (RFC 5280 §4.2.1.12)
    "2.5.29.37.0" => Some("anyExtendedKeyUsage")
    "1.3.6.1.5.5.7.3.1" => Some("serverAuth")
    "1.3.6.1.5.5.7.3.2" => Some("clientAuth")
    "1.3.6.1.5.5.7.3.3" => Some("codeSigning")
    "1.3.6.1.5.5.7.3.4" => Some("emailProtection")
    "1.3.6.1.5.5.7.3.8" => Some("timeStamping")
    "1.3.6.1.5.5.7.3.9" => Some("OCSPSigning")
    // Policy qualifiers (RFC 5280 §4.2.1.4)
    "1.3.6.1.5.5.7.2.1" => Some("id-qt-cps")
    "1.3.6.1.5.5.7.2.2" => Some("id-qt-unotice")
    _ => None
  }
}

fn arcs_to_int(arcs : Array[UInt]) -> Array[Int] {
  let out : Array[Int] = []
  for a in arcs {
    out.push(a.reinterpret_as_int())
  }
  out
}

///|
/// Format an OID as a dotted-decimal string.
pub fn arcs_to_dotted(arcs : Array[Int]) -> String {
  let buf = StringBuilder::new()
  for i, arc in arcs {
    if i > 0 {
      buf.write_char('.')
    }
    buf.write_string(arc.to_string())
  }
  buf.to_string()
}