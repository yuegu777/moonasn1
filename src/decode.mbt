///|
/// Decode one DER element from the head of `buf`.
///
/// This is the workhorse entry point. The X.509 layer in `src/x509/` builds
/// on top of this: it parses the outer `Certificate` SEQUENCE here and then
/// walks the structured children for the fields it cares about.
pub fn decode_element(buf : Bytes) -> Result[Asn1Value, ReaderError] {
  let r = Reader::new(buf)
  match decode_one(r) {
    Ok(v) =>
      // Strict DER: the element must consume the whole buffer.
      if r.eof() {
        Ok(v)
      } else {
        Err(MalformedLength)
      }
    Err(e) => Err(e)
  }
}

///|
/// Decode one DER element from a bounded `Reader`. Used internally; also
/// available so that X.509 callers can parse sub-structures without
/// re-slicing the buffer.
pub fn decode_one(r : Reader) -> Result[Asn1Value, ReaderError] {
  match r.enter() {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let id_byte = match r.read_byte() {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  let class_bits = (id_byte.to_int() >> 6) & 0x3
  let constructed = ((id_byte.to_int() >> 5) & 0x1) == 1
  let low5 = id_byte.to_int() & 0x1F
  let tag_number = if low5 < 31 {
    // Universal tag numbers only have meaning for the universal class;
    // context-specific/application/private tags keep their raw number.
    if class_bits == 0 {
      int_to_universal(low5)
    } else {
      Unknown(low5)
    }
  } else {
    // Long-form tag: read base-128 arcs until MSB=0.
    let mut acc = 0
    let mut found_end = false
    while !found_end {
      let b = match r.read_byte() {
        Ok(x) => x
        Err(e) => return Err(e)
      }
      let v = b.to_int()
      if (v & 0x80) == 0 {
        acc = (acc << 7) | v
        found_end = true
      } else {
        acc = (acc << 7) | (v & 0x7F)
      }
      if acc > (1 << 31) {
        return Err(LimitExceeded(kind="tag number"))
      }
    }
    Unknown(acc)
  }
  let class_ = match class_bits {
    0 => Universal
    1 => Application
    2 => ContextSpecific
    _ => Private
  }
  let length = match decode_length(r) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  if length == 0 && class_ == Universal {
    let is_null = match tag_number {
      Null => true
      _ => false
    }
    if is_null {
      r.leave()
      return Ok(Null)
    }
  }
  let body = match r.read_bytes(length) {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  r.leave()
  build_value(class_, tag_number, constructed, body)
}

///|
/// Decode a DER length octet stream. DER forbids indefinite length.
fn decode_length(r : Reader) -> Result[Int, ReaderError] {
  let first = match r.read_byte() {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  let v = first.to_int()
  if v < 0x80 {
    Ok(v)
  } else if v == 0x80 {
    Err(MalformedLength) // indefinite length, not allowed in DER
  } else {
    let n = v & 0x7F
    if n == 0 || n > 4 {
      return Err(MalformedLength)
    }
    let mut len = 0
    for _ in 0..<n {
      let b = match r.read_byte() {
        Ok(x) => x
        Err(e) => return Err(e)
      }
      // DER (X.690 §9.1) requires the minimum number of length octets:
      // no leading zero octet, and the long form only for lengths >= 0x80.
      if len == 0 && b.to_int() == 0 {
        return Err(MalformedLength)
      }
      len = (len << 8) | b.to_int()
    }
    if n == 1 && len < 0x80 {
      return Err(MalformedLength)
    }
    if len > (1 << 20) {
      return Err(LimitExceeded(kind="length"))
    }
    Ok(len)
  }
}

///|
fn int_to_universal(n : Int) -> TagNumber {
  match n {
    0 => EndOfContent
    1 => Boolean
    2 => Integer
    3 => BitString
    4 => OctetString
    5 => Null
    6 => ObjectIdentifier
    7 => ObjectDescriptor
    8 => External
    9 => Real
    10 => Enumerated
    11 => Embedded
    12 => UTF8String
    13 => RelativeOID
    14 => Time
    15 => Reserved
    16 => Sequence
    17 => Set
    18 => NumericString
    19 => PrintableString
    20 => T61String
    21 => VideotexString
    22 => IA5String
    23 => UTCTime
    24 => GeneralizedTime
    25 => GraphicString
    26 => VisibleString
    27 => GeneralString
    28 => UniversalString
    29 => CharacterString
    30 => BMPString
    other => Unknown(other)
  }
}

///|
/// Build the appropriate `Asn1Value` variant from a tag and body.
fn build_value(
  class_ : TagClass,
  number : TagNumber,
  constructed : Bool,
  body : Bytes,
) -> Result[Asn1Value, ReaderError] {
  match (class_, number, constructed) {
    (_, Sequence, true) =>
      match decode_children_arr(body) {
        Ok(children) => Ok(Sequence(children))
        Err(e) => Err(e)
      }
    (_, Set, true) =>
      match decode_children_arr(body) {
        Ok(children) => Ok(Set(children))
        Err(e) => Err(e)
      }
    (_, OctetString, _) => Ok(OctetString(body))
    (_, BitString, _) => {
      if body.length() == 0 {
        Ok(BitString(unused_bits=0, data=Bytes::new(0)))
      } else {
        let unused = body[0].to_int()
        let rest : FixedArray[Byte] = FixedArray::make(body.length() - 1, b'\x00')
        for i in 0..<rest.length() {
          rest[i] = body[i + 1]
        }
        Ok(BitString(unused_bits=unused.reinterpret_as_uint(), data=Bytes::from_array(rest)))
      }
    }
    (_, Integer, _) => Ok(Integer(body))
    (_, Boolean, _) =>
      match body.length() {
        1 => Ok(Boolean(body[0].to_int() != 0))
        _ => Err(MalformedValue)
      }
    (_, Null, _) => Ok(Null)
    (_, ObjectIdentifier, _) => Ok(decode_oid(body))
    (_, UTF8String, _) => Ok(UTF8String(body))
    (_, IA5String, _) => Ok(IA5String(body))
    (_, PrintableString, _) => Ok(PrintableString(body))
    (_, UTCTime, _) => Ok(UTCTime(body))
    (_, GeneralizedTime, _) => Ok(GeneralizedTime(body))
    // EXPLICIT tags are constructed; the body then carries the full DER
    // encoding of the wrapped element for the caller to decode on demand.
    (ContextSpecific, _, _) =>
      Ok(ContextSpecific(
        number=match number {
          Unknown(n) => n
          _ => -1
        },
        content=body,
      ))
    _ => Ok(Raw(tag=Tag::{ class_: class_, number, constructed }, content=body))
  }
}

///|
/// Decode the body of a SEQUENCE/SET element into its children. A child
/// that fails to decode fails the whole element: silently returning a
/// partial list would let truncated input masquerade as valid data.
fn decode_children_arr(body : Bytes) -> Result[Array[Asn1Value], ReaderError] {
  let r = Reader::new(body)
  let out : Array[Asn1Value] = []
  while !r.eof() {
    match decode_one(r) {
      Ok(v) => out.push(v)
      Err(e) => return Err(e)
    }
  }
  Ok(out)
}

///|
/// Decode the bytes of an OBJECT IDENTIFIER into a list of arcs.
///
/// The first two arcs are packed into the first byte: `arc1 = a / 40`,
/// `arc2 = a mod 40`. Subsequent bytes use base-128 with the high bit
/// indicating continuation (X.690 §8.19.4).
fn decode_oid(body : Bytes) -> Asn1Value {
  if body.length() == 0 {
    return Raw(tag=Tag::{ class_: Universal, number: ObjectIdentifier, constructed: false }, content=body)
  }
  let first = body[0].to_int()
  let arc1 = first / 40
  let arc2 = first % 40
  let mut arcs : Array[UInt] = [arc1.reinterpret_as_uint(), arc2.reinterpret_as_uint()]
  let mut acc = 0
  let mut started = false
  for i in 1..<body.length() {
    let v = body[i].to_int()
    if (v & 0x80) != 0 {
      acc = (acc << 7) | (v & 0x7F)
      started = true
    } else {
      acc = (acc << 7) | v
      arcs = arcs + [acc.reinterpret_as_uint()]
      acc = 0
      started = false
    }
  }
  // Trailing continuation without a final byte means malformed; we surface
  // it as a Raw so the higher layer can decide.
  if started {
    return Raw(tag=Tag::{ class_: Universal, number: ObjectIdentifier, constructed: false }, content=body)
  }
  ObjectIdentifier(arcs)
}