///|
/// A single relative distinguished name (one attribute-type / attribute-
/// value pair inside an RDN).
pub struct RelativeDistinguishedName {
  oid_arcs : Array[UInt]
  value : String
} derive(Eq)

///|
/// An X.500 distinguished name — an ordered SEQUENCE of RDNs.
pub struct Name {
  rdns : Array[RelativeDistinguishedName]
} derive(Eq)

///|
/// Render the name as a comma-separated list, e.g. `CN=example.com, O=Acme`.
pub fn Name::to_string(self : Name) -> String {
  let buf = StringBuilder::new()
  for i, rdn in self.rdns {
    if i > 0 {
      buf.write_string(", ")
    }
    buf.write_string(known_oid(arcs_to_int(rdn.oid_arcs)).unwrap_or("?"))
    buf.write_char('=')
    buf.write_string(rdn.value)
  }
  buf.to_string()
}

///|
/// Parse an X.500 Name from its DER encoding (a SEQUENCE of SET OF
/// SEQUENCE { OID, ANY }). We flatten to RDNs in the order they appear.
pub fn parse_name(value : Asn1Value) -> Name? {
  guard value is Sequence(outer) else { return None }
  let mut rdns : Array[RelativeDistinguishedName] = []
  for rdn_set in outer {
    guard rdn_set is Set(items) else { continue }
    for item in items {
      guard item is Sequence(pair) else { continue }
      if pair.length() < 2 {
        continue
      }
      guard pair[0] is ObjectIdentifier(arcs) else { continue }
      let value_str = string_value(pair[1])
      rdns = rdns + [{ oid_arcs: arcs, value: value_str }]
    }
  }
  Some({ rdns, })
}

fn string_value(v : Asn1Value) -> String {
  let bytes = match v {
    UTF8String(b) => b
    IA5String(b) => b
    PrintableString(b) => b
    OctetString(b) => b
    Raw(content~, ..) => content
    _ => Bytes::new(0)
  }
  decode_utf8(bytes)
}

///|
/// Decode UTF-8 bytes as a string, replacing invalid sequences with the
/// Unicode replacement character. We never throw on encoding errors because
/// X.509 values are supposed to be UTF-8String but in practice some CAs ship
/// PrintableString / IA5String bytes that we want to surface verbatim.
fn decode_utf8(b : Bytes) -> String {
  let buf = StringBuilder::new()
  let mut i = 0
  while i < b.length() {
    let byte = b[i].to_int()
    if byte < 0x80 {
      buf.write_char(byte.unsafe_to_char())
      i = i + 1
    } else if byte >= 0xC2 && byte <= 0xDF && i + 1 < b.length() {
      let b2 = b[i + 1].to_int()
      let cp = ((byte & 0x1F) << 6) | (b2 & 0x3F)
      buf.write_char(cp.unsafe_to_char())
      i = i + 2
    } else if byte >= 0xE0 && byte <= 0xEF && i + 2 < b.length() {
      let b2 = b[i + 1].to_int()
      let b3 = b[i + 2].to_int()
      let cp = ((byte & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F)
      buf.write_char(cp.unsafe_to_char())
      i = i + 3
    } else if byte >= 0xF0 && byte <= 0xF4 && i + 3 < b.length() {
      let b2 = b[i + 1].to_int()
      let b3 = b[i + 2].to_int()
      let b4 = b[i + 3].to_int()
      let cp = ((byte & 0x07) << 18) |
        ((b2 & 0x3F) << 12) |
        ((b3 & 0x3F) << 6) |
        (b4 & 0x3F)
      buf.write_char(cp.unsafe_to_char())
      i = i + 4
    } else {
      buf.write_char('\u{FFFD}')
      i = i + 1
    }
  }
  buf.to_string()
}