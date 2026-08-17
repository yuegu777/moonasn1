///|
/// The ASN.1 `ANY` type, realised as a recursive ADT.
///
/// Every parsed DER element is one of these variants. Decoders may also
/// hand back a `Raw` to defer interpretation to a higher layer (for
/// example, X.509 parses the outer `Certificate` SEQUENCE and then
/// decodes its fields on demand).
pub enum Asn1Value {
  /// Boolean. The payload is a single byte; only `0x00` and any non-zero
  /// value are valid, but the spec leaves the choice open.
  Boolean(Bool)
  /// Signed INTEGER, two's complement, big-endian.
  /// Leading `0xFF`/`0x00` padding bytes are preserved exactly so the
  /// encoded form round-trips.
  Integer(Bytes)
  /// BIT STRING with the trailing bit count preserved.
  BitString(unused_bits~ : UInt, data~ : Bytes)
  /// OCTET STRING, byte-aligned.
  OctetString(Bytes)
  /// NULL, carries no payload.
  Null
  /// OBJECT IDENTIFIER as a sequence of non-negative arcs.
  ObjectIdentifier(Array[UInt])
  /// UTF8String, decoded as UTF-8 bytes (interpretation is left to callers).
  UTF8String(Bytes)
  /// IA5String, 7-bit ASCII.
  IA5String(Bytes)
  /// PrintableString, restricted ASCII subset.
  PrintableString(Bytes)
  /// UTCTime (YYMMDDhhmm[ss]Z or +hhmm / -hhmm offset).
  UTCTime(Bytes)
  /// GeneralizedTime (YYYYMMDDhhmm[ss[.fff]]Z or offset).
  GeneralizedTime(Bytes)
  /// SEQUENCE — ordered list of elements.
  Sequence(Array[Asn1Value])
  /// SET — unordered list of elements.
  Set(Array[Asn1Value])
  /// A context-specific tag that we did not interpret. The tag number and
  /// the raw bytes of the element body are preserved for the caller to
  /// decode.
  ContextSpecific(number~ : Int, content~ : Bytes)
  /// Any element we did not decode at all (used by the X.509 layer for
  /// fields out of v1 scope).
  Raw(tag~ : Tag, content~ : Bytes)
} derive(Debug, Eq)

///|
/// Convenience: return the bytes of an OCTET STRING or a Raw element.
/// Returns `None` for any other variant.
pub fn Asn1Value::as_bytes(self : Asn1Value) -> Bytes? {
  match self {
    OctetString(b) => Some(b)
    BitString(data~, ..) => Some(data)
    Raw(content~, ..) => Some(content)
    _ => None
  }
}

///|
/// Convenience: an OID as a dotted-decimal string, e.g. "2.5.4.3".
pub fn Asn1Value::oid_dotted(self : Asn1Value) -> String? {
  match self {
    ObjectIdentifier(arcs) => {
      let ints : Array[Int] = []
      for a in arcs {
        ints.push(a.reinterpret_as_int())
      }
      Some(arcs_to_dotted(ints))
    }
    _ => None
  }
}