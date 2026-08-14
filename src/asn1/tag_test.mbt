///|
test "Tag::identifier_byte for SEQUENCE universal constructed" {
  let t = @asn1.Tag::{
    class_: @asn1.Universal,
    number: @asn1.Sequence,
    constructed: true,
  }
  // class=00, constructed=1, tag=16 -> 0x30
  assert_eq(t.identifier_byte(), b'\x30')
}

///|
test "Tag::identifier_byte for INTEGER universal primitive" {
  let t = @asn1.Tag::{
    class_: @asn1.Universal,
    number: @asn1.Integer,
    constructed: false,
  }
  // class=00, constructed=0, tag=2 -> 0x02
  assert_eq(t.identifier_byte(), b'\x02')
}

///|
test "Tag::identifier_byte for context-specific [0] primitive" {
  let t = @asn1.Tag::{
    class_: @asn1.ContextSpecific,
    number: @asn1.Unknown(0),
    constructed: false,
  }
  // class=10, constructed=0, tag=0 -> 0x80
  assert_eq(t.identifier_byte(), b'\x80')
}

///|
test "Tag::identifier_byte for context-specific [3] constructed" {
  let t = @asn1.Tag::{
    class_: @asn1.ContextSpecific,
    number: @asn1.Unknown(3),
    constructed: true,
  }
  // class=10, constructed=1, tag=3 -> 0xA3
  assert_eq(t.identifier_byte(), b'\xA3')
}