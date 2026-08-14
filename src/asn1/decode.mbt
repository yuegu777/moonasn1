///|
/// Decode one DER element from the head of `buf`.
///
/// This is the workhorse entry point. The X.509 layer in `src/x509/` builds
/// on top of this: it parses the outer `Certificate` SEQUENCE here and then
/// walks the structured children for the fields it cares about.
pub fn decode_element(buf : Bytes) -> Result[@asn1.Asn1Value, @asn1_reader.ReaderError] {
  let r = @asn1_reader.Reader::new(buf)
  decode_one(r)
}

///|
/// Decode one DER element from a bounded `Reader`. Used internally; also
/// available so that X.509 callers can parse sub-structures without
/// re-slicing the buffer.
pub fn decode_one(r : @asn1_reader.Reader) -> Result[@asn1.Asn1Value, @asn1_reader.ReaderError] {
  let _ = r.enter()
  let id_byte = r.read_byte()?
  let class_bits = (id_byte.to_int() >> 6) & 0x3
  let constructed = ((id_byte.to_int() >> 5) & 0x1) == 1
  let low5 = id_byte.to_int() & 0x1F
  let tag_number = if low5 < 31 {
    int_to_universal(low5)
  } else {
    // Long-form tag: read base-128 arcs until MSB=0.
    let mut acc = 0
    let mut found_end = false
    while not(found_end) {
      let b = r.read_byte()?
      let v = b.to_int()
      if (v & 0x80) == 0 {
        acc = (acc << 7) | v
        found_end = true
      } else {
        acc = (acc << 7) | (v & 0x7F)
      }
      if acc > (1 << 31) {
        return Err(@asn1_reader.LimitExceeded("tag number"))
      }
    }
    @asn1.Unknown(acc)
  }
  let class_ = match class_bits {
    0 => @asn1.Universal
    1 => @asn1.Application
    2 => @asn1.ContextSpecific
    _ => @asn1.Private
  }
  let length = decode_length(r)?
  if length == 0 && class_ == @asn1.Universal && matches(tag_number, @asn1.Null) {
    r.leave()
    return Ok(@asn1.Null)
  }
  let body = r.read_bytes(length)?
  r.leave()
  Ok(build_value(class_, tag_number, constructed, body))
}

///|
/// Decode a DER length octet stream. DER forbids indefinite length.
fn decode_length(r : @asn1_reader.Reader) -> Result[Int, @asn1_reader.ReaderError] {
  let first = r.read_byte()?
  let v = first.to_int()
  if v < 0x80 {
    Ok(v)
  } else if v == 0x80 {
    Err(@asn1_reader.MalformedLength) // indefinite length, not allowed in DER
  } else {
    let n = v & 0x7F
    if n == 0 || n > 4 {
      return Err(@asn1_reader.MalformedLength)
    }
    let mut len = 0
    for _ in 0..<n {
      let b = r.read_byte()?
      len = (len << 8) | b.to_int()
    }
    if len > (1 << 20) {
      return Err(@asn1_reader.LimitExceeded("length"))
    }
    Ok(len)
  }
}

///|
fn int_to_universal(n : Int) -> @asn1.TagNumber {
  match n {
    0 => @asn1.EndOfContent
    1 => @asn1.Boolean
    2 => @asn1.Integer
    3 => @asn1.BitString
    4 => @asn1.OctetString
    5 => @asn1.Null
    6 => @asn1.ObjectIdentifier
    7 => @asn1.ObjectDescriptor
    8 => @asn1.External
    9 => @asn1.Real
    10 => @asn1.Enumerated
    11 => @asn1.Embedded
    12 => @asn1.UTF8String
    13 => @asn1.RelativeOID
    14 => @asn1.Time
    15 => @asn1.Reserved
    16 => @asn1.Sequence
    17 => @asn1.Set
    18 => @asn1.NumericString
    19 => @asn1.PrintableString
    20 => @asn1.T61String
    21 => @asn1.VideotexString
    22 => @asn1.IA5String
    23 => @asn1.UTCTime
    24 => @asn1.GeneralizedTime
    25 => @asn1.GraphicString
    26 => @asn1.VisibleString
    27 => @asn1.GeneralString
    28 => @asn1.UniversalString
    29 => @asn1.CharacterString
    30 => @asn1.BMPString
    other => @asn1.Unknown(other)
  }
}

///|
/// Build the appropriate `Asn1Value` variant from a tag and body.
fn build_value(
  class_ : @asn1.TagClass,
  number : @asn1.TagNumber,
  constructed : Bool,
  body : Bytes,
) -> @asn1.Asn1Value {
  match (class_, number, constructed) {
    // Constructed forms of OCTET STRING and BIT STRING are not legal in
    // DER (X.690 §10), so we always treat them as primitive.
    (_, @asn1.Sequence, true) => decode_children(body)
    (_, @asn1.Set, true) => decode_children(body)
    (_, @asn1.OctetString, _) => @asn1.OctetString(body)
    (_, @asn1.BitString, _) => {
      if body.length() == 0 {
        @asn1.BitString(unused_bits=0, data=Bytes::new(0))
      } else {
        let unused = body[0].to_int()
        let rest = Bytes::make(body.length() - 1, b'\x00')
        for i in 0..<rest.length() {
          rest[i] = body[i + 1]
        }
        @asn1.BitString(unused_bits=unused.to_uint(), data=rest)
      }
    }
    (_, @asn1.Integer, _) => @asn1.Integer(body)
    (_, @asn1.Boolean, _) =>
      match body.length() {
        1 => @asn1.Boolean(body[0].to_int() != 0)
        _ => @asn1.Raw(@asn1.Tag::{ class_, number, constructed }, body)
      }
    (_, @asn1.Null, _) => @asn1.Null
    (_, @asn1.ObjectIdentifier, _) => decode_oid(body)
    (_, @asn1.UTF8String, _) => @asn1.UTF8String(body)
    (_, @asn1.IA5String, _) => @asn1.IA5String(body)
    (_, @asn1.PrintableString, _) => @asn1.PrintableString(body)
    (_, @asn1.UTCTime, _) => @asn1.UTCTime(body)
    (_, @asn1.GeneralizedTime, _) => @asn1.GeneralizedTime(body)
    (_, @asn1.ContextSpecific, false) =>
      @asn1.ContextSpecific(
        number=match number {
          @asn1.Unknown(n) => n
          _ => -1
        },
        content=body,
      )
    _ => @asn1.Raw(@asn1.Tag::{ class_, number, constructed }, body)
  }
}

///|
/// Decode the body of a SEQUENCE/SET element into its children.
fn decode_children(body : Bytes) -> @asn1.Asn1Value {
  let r = @asn1_reader.Reader::new(body)
  let mut out : Array[@asn1.Asn1Value] = []
  let mut ok = true
  while ok && not(r.eof()) {
    match decode_one(r) {
      Ok(v) => out = out + [v]
      Err(_) => ok = false
    }
  }
  // The outer tag is needed by callers that want to know SEQUENCE vs SET.
  // We return SEQUENCE as a placeholder; the X.509 layer inspects the raw
  // identifier byte to distinguish. For v1, treat all constructed
  // universal tags as Sequence.
  ignore(@asn1.Sequence) // suppress unused warning when nothing matched
  @asn1.Sequence(out)
}

///|
/// Decode the bytes of an OBJECT IDENTIFIER into a list of arcs.
///
/// The first two arcs are packed into the first byte: `arc1 = a / 40`,
/// `arc2 = a mod 40`. Subsequent bytes use base-128 with the high bit
/// indicating continuation (X.690 §8.19.4).
fn decode_oid(body : Bytes) -> @asn1.Asn1Value {
  if body.length() == 0 {
    return @asn1.Raw(@asn1.Tag::{ class_: @asn1.Universal, number: @asn1.ObjectIdentifier, constructed: false }, body)
  }
  let first = body[0].to_int()
  let arc1 = first / 40
  let arc2 = first % 40
  let mut arcs : Array[UInt] = [arc1.to_uint(), arc2.to_uint()]
  let mut acc = 0
  let mut started = false
  for i in 1..<body.length() {
    let v = body[i].to_int()
    if (v & 0x80) != 0 {
      acc = (acc << 7) | (v & 0x7F)
      started = true
    } else {
      acc = (acc << 7) | v
      arcs = arcs + [acc.to_uint()]
      acc = 0
      started = false
    }
  }
  // Trailing continuation without a final byte means malformed; we surface
  // it as a Raw so the higher layer can decide.
  if started {
    return @asn1.Raw(@asn1.Tag::{ class_: @asn1.Universal, number: @asn1.ObjectIdentifier, constructed: false }, body)
  }
  // Coerce arcs to Int for known_oid lookup.
  let as_int : Array[Int] = []
  for a in arcs {
    as_int.push(a.to_int())
  }
  ignore(as_int)
  @asn1.ObjectIdentifier(arcs)
}