///|
/// One decoded X.509 v3 extension (RFC 5280 §4.1).
pub struct Extension {
  /// The extension OID in dotted-decimal form, e.g. "2.5.29.17".
  oid : String
  /// Friendly name for known OIDs (e.g. "subjectAltName"), or the
  /// dotted-decimal OID itself when unknown.
  name : String
  /// Whether the extension is marked critical.
  critical : Bool
  /// The raw `extnValue` bytes (content of the OCTET STRING). For most
  /// extensions this is itself a DER encoding; the typed parsers below
  /// consume it.
  value : Bytes
} derive(Debug, Eq)

///|
/// Decode the `[3] EXPLICIT Extensions` container body (a DER-encoded
/// `SEQUENCE OF Extension`). An empty body (no extensions, e.g. a v1
/// certificate) yields an empty array. Malformed individual entries are
/// skipped; an unusable container yields an empty array.
pub fn parse_extensions(raw : Bytes) -> Array[Extension] {
  let out : Array[Extension] = []
  match decode_element(raw) {
    Ok(Sequence(items)) =>
      for item in items {
        match parse_one_extension(item) {
          Some(e) => out.push(e)
          None => ()
        }
      }
    _ => ()
  }
  out
}

fn parse_one_extension(v : Asn1Value) -> Extension? {
  guard v is Sequence(parts) else { return None }
  guard parts.length() >= 2 else { return None }
  guard parts[0] is ObjectIdentifier(arcs) else { return None }
  let oid = arcs_to_dotted(arcs_to_int(arcs))
  // critical BOOLEAN DEFAULT FALSE — present only when TRUE in DER, but we
  // also tolerate an explicit FALSE.
  let mut critical = false
  let mut idx = 1
  if idx < parts.length() && parts[idx] is Boolean(b) {
    critical = b
    idx = idx + 1
  }
  guard idx < parts.length() && parts[idx] is OctetString(value) else {
    return None
  }
  let name = known_oid(arcs_to_int(arcs)).unwrap_or(oid)
  Some({ oid, name, critical, value })
}

///|
/// Find the first extension with the given dotted-decimal OID.
pub fn find_extension(exts : Array[Extension], dotted : String) -> Extension? {
  for e in exts {
    if e.oid == dotted {
      return Some(e)
    }
  }
  None
}

///|
/// One `GeneralName` (RFC 5280 §4.2.1.6). The variants cover the name
/// forms that commonly appear in `subjectAltName` / `issuerAltName`.
pub enum GeneralName {
  /// [0] otherName — raw content bytes.
  OtherName(content~ : Bytes)
  /// [1] rfc822Name (email address).
  Rfc822Name(String)
  /// [2] dNSName.
  DnsName(String)
  /// [4] directoryName (an X.500 Name).
  DirectoryName(Name)
  /// [6] uniformResourceIdentifier.
  Uri(String)
  /// [7] iPAddress — 4 bytes (IPv4) or 16 bytes (IPv6).
  IpAddress(Bytes)
  /// Any other tag; preserved verbatim (`tag=-1` when the element was not
  /// context-specific at all).
  Unsupported(tag~ : Int, content~ : Bytes)
} derive(Debug, Eq)

///|
/// Parse a `subjectAltName` / `issuerAltName` extnValue (a DER-encoded
/// `GeneralNames` SEQUENCE) into its entries.
pub fn parse_general_names(inner : Bytes) -> Array[GeneralName]? {
  guard decode_element(inner) is Ok(Sequence(items)) else { return None }
  let out : Array[GeneralName] = []
  for item in items {
    out.push(general_name_from(item))
  }
  Some(out)
}

fn general_name_from(v : Asn1Value) -> GeneralName {
  guard v is ContextSpecific(number=tag, content=body) else {
    return Unsupported(tag=-1, content=Bytes::new(0))
  }
  match tag {
    0 => OtherName(content=body)
    1 => Rfc822Name(decode_utf8(body))
    2 => DnsName(decode_utf8(body))
    4 =>
      // directoryName is [4] EXPLICIT over the RDNSequence, so the body
      // carries the full DER of the Name.
      match decode_element(body) {
        Ok(n) =>
          match parse_name(n) {
            Some(name) => DirectoryName(name)
            None => Unsupported(tag=4, content=body)
          }
        Err(_) => Unsupported(tag=4, content=body)
      }
    6 => Uri(decode_utf8(body))
    7 => IpAddress(body)
    _ => Unsupported(tag=tag, content=body)
  }
}

///|
/// Human-readable form, e.g. `DNS:example.com`.
pub fn GeneralName::to_display(self : GeneralName) -> String {
  match self {
    OtherName(_) => "otherName"
    Rfc822Name(s) => "email:" + s
    DnsName(s) => "DNS:" + s
    DirectoryName(n) => "DirName:" + n.to_string()
    Uri(s) => "URI:" + s
    IpAddress(b) => "IP:" + format_ip(b)
    Unsupported(tag~, ..) => "GeneralName[\{tag}]"
  }
}

fn format_ip(b : Bytes) -> String {
  if b.length() == 4 {
    b[0].to_int().to_string() +
    "." +
    b[1].to_int().to_string() +
    "." +
    b[2].to_int().to_string() +
    "." +
    b[3].to_int().to_string()
  } else if b.length() == 16 {
    let buf = StringBuilder::new()
    for i, byte in b {
      if i > 0 && i % 2 == 0 {
        buf.write_char(':')
      }
      let v = byte.to_int()
      buf.write_char(hex_lc(v >> 4))
      buf.write_char(hex_lc(v & 0xF))
    }
    buf.to_string()
  } else {
    "ip(" + b.length().to_string() + " bytes)"
  }
}

fn hex_lc(n : Int) -> Char {
  if n < 10 {
    ('0'.to_int() + n).unsafe_to_char()
  } else {
    ('a'.to_int() + (n - 10)).unsafe_to_char()
  }
}

///|
/// The nine named bits of the `keyUsage` extension (RFC 5280 §4.2.1.3).
pub struct KeyUsage {
  digital_signature : Bool
  non_repudiation : Bool
  key_encipherment : Bool
  data_encipherment : Bool
  key_agreement : Bool
  key_cert_sign : Bool
  crl_sign : Bool
  encipher_only : Bool
  decipher_only : Bool
} derive(Debug, Eq)

///|
/// Parse a `keyUsage` extnValue (a DER-encoded BIT STRING) into its named
/// bits. Bits beyond the encoded length are `false`.
pub fn parse_key_usage(inner : Bytes) -> KeyUsage? {
  guard decode_element(inner) is Ok(BitString(unused_bits~, data~)) else {
    return None
  }
  Some({
    digital_signature: bit_is_set(data, unused_bits, 0),
    non_repudiation: bit_is_set(data, unused_bits, 1),
    key_encipherment: bit_is_set(data, unused_bits, 2),
    data_encipherment: bit_is_set(data, unused_bits, 3),
    key_agreement: bit_is_set(data, unused_bits, 4),
    key_cert_sign: bit_is_set(data, unused_bits, 5),
    crl_sign: bit_is_set(data, unused_bits, 6),
    encipher_only: bit_is_set(data, unused_bits, 7),
    decipher_only: bit_is_set(data, unused_bits, 8),
  })
}

fn bit_is_set(data : Bytes, unused : UInt, i : Int) -> Bool {
  let total = data.length() * 8 - unused.reinterpret_as_int()
  if i < 0 || i >= total {
    return false
  }
  (data[i / 8].to_int() & (0x80 >> (i % 8))) != 0
}

///|
/// Compact human-readable form, e.g. `digitalSignature, keyCertSign`.
pub fn KeyUsage::to_display(self : KeyUsage) -> String {
  let parts : Array[String] = []
  if self.digital_signature {
    parts.push("digitalSignature")
  }
  if self.non_repudiation {
    parts.push("nonRepudiation")
  }
  if self.key_encipherment {
    parts.push("keyEncipherment")
  }
  if self.data_encipherment {
    parts.push("dataEncipherment")
  }
  if self.key_agreement {
    parts.push("keyAgreement")
  }
  if self.key_cert_sign {
    parts.push("keyCertSign")
  }
  if self.crl_sign {
    parts.push("cRLSign")
  }
  if self.encipher_only {
    parts.push("encipherOnly")
  }
  if self.decipher_only {
    parts.push("decipherOnly")
  }
  join_strings(parts)
}

///|
/// The `basicConstraints` extension (RFC 5280 §4.2.1.9).
pub struct BasicConstraints {
  is_ca : Bool
  /// `pathLenConstraint`; encoded only for CAs in practice.
  path_len : Int?
} derive(Debug, Eq)

///|
/// Parse a `basicConstraints` extnValue (a DER-encoded SEQUENCE). An empty
/// SEQUENCE means `CA:FALSE` with no path length.
pub fn parse_basic_constraints(inner : Bytes) -> BasicConstraints? {
  guard decode_element(inner) is Ok(Sequence(parts)) else { return None }
  let mut is_ca = false
  let mut path_len : Int? = None
  for p in parts {
    if p is Boolean(b) {
      is_ca = b
    } else if p is Integer(n) {
      path_len = integer_to_int(n)
    }
  }
  Some({ is_ca, path_len })
}

///|
pub fn BasicConstraints::to_display(self : BasicConstraints) -> String {
  if self.is_ca {
    match self.path_len {
      Some(n) => "CA:TRUE, pathlen:" + n.to_string()
      None => "CA:TRUE"
    }
  } else {
    "CA:FALSE"
  }
}

///|
/// Interpret a DER INTEGER body as a non-negative Int. Returns None when
/// the value does not fit in 4 bytes; fields we decode this way
/// (`pathLenConstraint`) are small in practice and never negative.
fn integer_to_int(b : Bytes) -> Int? {
  if b.length() > 4 {
    return None
  }
  let mut v = 0
  for byte in b {
    v = (v << 8) | byte.to_int()
  }
  Some(v)
}

fn join_strings(parts : Array[String]) -> String {
  let buf = StringBuilder::new()
  for i, p in parts {
    if i > 0 {
      buf.write_string(", ")
    }
    buf.write_string(p)
  }
  buf.to_string()
}

///|
/// One `KeyPurposeId` from the `extKeyUsage` extension (RFC 5280 §4.2.1.12).
pub enum KeyPurpose {
  ServerAuth
  ClientAuth
  CodeSigning
  EmailProtection
  TimeStamping
  OcspSigning
  AnyExtendedKeyUsage
  Other(oid~ : String)
} derive(Debug, Eq)

///|
pub fn KeyPurpose::to_display(self : KeyPurpose) -> String {
  match self {
    ServerAuth => "serverAuth"
    ClientAuth => "clientAuth"
    CodeSigning => "codeSigning"
    EmailProtection => "emailProtection"
    TimeStamping => "timeStamping"
    OcspSigning => "OCSPSigning"
    AnyExtendedKeyUsage => "anyExtendedKeyUsage"
    Other(oid~) => oid
  }
}

///|
/// The `extKeyUsage` extension (RFC 5280 §4.2.1.12). A SEQUENCE OF
/// KeyPurposeId; the array preserves certificate order.
pub struct ExtKeyUsage {
  purposes : Array[KeyPurpose]
} derive(Debug, Eq)

///|
/// Parse an `extKeyUsage` extnValue (a DER-encoded `SEQUENCE OF
/// KeyPurposeId`). Returns None on any structural error.
pub fn parse_ext_key_usage(inner : Bytes) -> ExtKeyUsage? {
  guard decode_element(inner) is Ok(Sequence(items)) else { return None }
  let out : Array[KeyPurpose] = []
  for item in items {
    guard item is ObjectIdentifier(arcs) else { return None }
    let dotted = arcs_to_dotted(arcs_to_int(arcs))
    out.push(key_purpose_from(dotted))
  }
  Some({ purposes: out })
}

fn key_purpose_from(dotted : String) -> KeyPurpose {
  match dotted {
    "2.5.29.37.0" => AnyExtendedKeyUsage
    "1.3.6.1.5.5.7.3.1" => ServerAuth
    "1.3.6.1.5.5.7.3.2" => ClientAuth
    "1.3.6.1.5.5.7.3.3" => CodeSigning
    "1.3.6.1.5.5.7.3.4" => EmailProtection
    "1.3.6.1.5.5.7.3.8" => TimeStamping
    "1.3.6.1.5.5.7.3.9" => OcspSigning
    _ => Other(oid=dotted)
  }
}

///|
pub fn ExtKeyUsage::to_display(self : ExtKeyUsage) -> String {
  let parts : Array[String] = []
  for p in self.purposes {
    parts.push(p.to_display())
  }
  join_strings(parts)
}

///|
/// Parse a `subjectKeyIdentifier` extnValue (RFC 5280 §4.2.1.2). The
/// extnValue is an OCTET STRING wrapping a KeyIdentifier (another OCTET
/// STRING); we return the inner KeyIdentifier bytes.
pub fn parse_subject_key_identifier(inner : Bytes) -> Bytes? {
  guard decode_element(inner) is Ok(OctetString(key_id)) else { return None }
  Some(key_id)
}

///|
/// The `authorityKeyIdentifier` extension (RFC 5280 §4.2.1.1).
pub struct AuthorityKeyIdentifier {
  /// [0] keyIdentifier — the raw KeyIdentifier bytes.
  key_identifier : Bytes?
  /// [1] authorityCertIssuer — parsed GeneralNames; None when absent.
  cert_issuer : Array[GeneralName]?
  /// [2] authorityCertSerialNumber — raw INTEGER body bytes.
  cert_serial_number : Bytes?
} derive(Debug, Eq)

///|
/// Parse an `authorityKeyIdentifier` extnValue (a DER-encoded SEQUENCE
/// with implicit-tagged [0]/[1]/[2] children). Returns None when the
/// outer container is not a SEQUENCE.
pub fn parse_authority_key_identifier(inner : Bytes) -> AuthorityKeyIdentifier? {
  guard decode_element(inner) is Ok(Sequence(parts)) else { return None }
  let mut key_id : Bytes? = None
  let mut issuer : Array[GeneralName]? = None
  let mut serial : Bytes? = None
  for p in parts {
    guard p is ContextSpecific(number=tag, content=body) else { continue }
    match tag {
      0 => key_id = Some(body)
      1 => issuer = Some(parse_general_names_inline(body))
      2 => serial = Some(body)
      _ => ()
    }
  }
  Some({
    key_identifier: key_id,
    cert_issuer: issuer,
    cert_serial_number: serial,
  })
}

///|
/// Parse GeneralNames from the *content* of a constructed [1] tag — i.e.
/// the children of the original SEQUENCE OF, without the outer wrapper.
/// This is how authorityKeyIssuer carries its GeneralNames (implicit tag).
fn parse_general_names_inline(body : Bytes) -> Array[GeneralName] {
  let out : Array[GeneralName] = []
  let r = Reader::new(body)
  while !r.eof() {
    match decode_one(r) {
      Ok(v) => out.push(general_name_from(v))
      Err(_) => break
    }
  }
  out
}

///|
pub fn AuthorityKeyIdentifier::to_display(self : AuthorityKeyIdentifier) -> String {
  let parts : Array[String] = []
  match self.key_identifier {
    Some(kid) => parts.push("keyid:" + bytes_to_hex(kid))
    None => ()
  }
  match self.cert_issuer {
    Some(names) => {
      let buf = StringBuilder::new()
      buf.write_string("issuer:")
      for i, name in names {
        if i > 0 {
          buf.write_char(',')
        }
        buf.write_string(name.to_display())
      }
      parts.push(buf.to_string())
    }
    None => ()
  }
  match self.cert_serial_number {
    Some(serial) => parts.push("serial:" + bytes_to_hex(serial))
    None => ()
  }
  join_strings(parts)
}

fn bytes_to_hex(b : Bytes) -> String {
  let buf = StringBuilder::new()
  for byte in b {
    let v = byte.to_int()
    buf.write_char(hex_lc(v >> 4))
    buf.write_char(hex_lc(v & 0xF))
  }
  buf.to_string()
}
