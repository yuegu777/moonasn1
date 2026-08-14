///|
/// ASN.1 tag numbers (X.680 §3 and ITU-T X.509 / RFC 5280 Appendix A).
///
/// DER distinguishes universal tags from application, context-specific, and
/// private tags. We model the tag's *number* and *class* explicitly so that
/// later readers can reject undefined constructions.
pub enum TagClass {
  Universal
  Application
  ContextSpecific
  Private
} derive(Show, Eq)

///|
/// Universal tag numbers per X.680 §3.8 and the X.509 module.
///
/// Numbers here are the canonical decimal identifiers, not the bit layout.
/// Universal `0x00` is reserved (BER end-of-content); we still encode it so
/// callers can detect malformed inputs.
pub enum TagNumber {
  EndOfContent       // 0
  Boolean            // 1
  Integer            // 2
  BitString          // 3
  OctetString        // 4
  Null               // 5
  ObjectIdentifier   // 6
  ObjectDescriptor   // 7
  External           // 8
  Real               // 9
  Enumerated         // 10
  Embedded           // 11
  UTF8String         // 12
  RelativeOID        // 13
  Time               // 14
  Reserved           // 15
  Sequence           // 16 (constructed)
  Set                // 17 (constructed)
  NumericString      // 18
  PrintableString     // 19
  T61String          // 20
  VideotexString     // 21
  IA5String          // 22
  UTCTime            // 23
  GeneralizedTime    // 24
  GraphicString      // 25
  VisibleString      // 26
  GeneralString      // 27
  UniversalString    // 28
  CharacterString    // 29
  BMPString          // 30
  // 31+ are unused in current ASN.1 modules.
  Unknown(Int)
} derive(Show, Eq)

///|
/// The full tag header (class + number + constructed bit).
pub struct Tag {
  class_ : TagClass
  number : TagNumber
  // Whether the element is constructed (true) or primitive (false).
  constructed : Bool
} derive(Show, Eq)

///|
/// Build the identifier byte used at the head of every DER element
/// (X.690 §8.1.2.3 / Table 1).
pub fn Tag::identifier_byte(self : Tag) -> UInt8 {
  let mut b = 0
  match self.class_ {
    Universal => b = b
    Application => b = b | 0x40
    ContextSpecific => b = b | 0x80
    Private => b = b | 0xC0
  }
  if self.constructed {
    b = b | 0x20
  }
  let n = match self.number {
    EndOfContent => 0
    Boolean => 1
    Integer => 2
    BitString => 3
    OctetString => 4
    Null => 5
    ObjectIdentifier => 6
    ObjectDescriptor => 7
    External => 8
    Real => 9
    Enumerated => 10
    Embedded => 11
    UTF8String => 12
    RelativeOID => 13
    Time => 14
    Reserved => 15
    Sequence => 16
    Set => 17
    NumericString => 18
    PrintableString => 19
    T61String => 20
    VideotexString => 21
    IA5String => 22
    UTCTime => 23
    GeneralizedTime => 24
    GraphicString => 25
    VisibleString => 26
    GeneralString => 27
    UniversalString => 28
    CharacterString => 29
    BMPString => 30
    Unknown(n) => n
  }
  if n < 31 {
    (b | n).to_uint8()
  } else {
    // long-form tag: low five bits = 0x1F; full number follows as base-128
    // bytes. Callers must use `encode_long_form_tag` for n >= 31.
    abort("Tag::identifier_byte: long-form tag encoding not implemented; use encode_long_form_tag")
  }
}