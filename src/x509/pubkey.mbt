///|
/// The result of inspecting a `SubjectPublicKeyInfo`'s algorithm field.
/// We do not parse the key material itself; the consuming crypto package
/// can do that based on this hint.
pub enum PubkeyAlgorithm {
  /// RSA with the modulus bit length recovered from the integer's leading
  /// byte count.
  Rsa(modulus_bits : Int?)
  /// EC, with the named curve OID if it was a named curve.
  Ec(curve : String?)
  /// Ed25519 (RFC 8422 / 8032).
  Ed25519
  /// Any other algorithm. The OID's dotted-decimal representation is
  /// preserved for callers to dispatch on.
  Other(oid : String)
} derive(Show, Eq)

///|
/// Inspect a `SubjectPublicKeyInfo` ASN.1 value and return the algorithm.
/// `SubjectPublicKeyInfo` is `SEQUENCE { algorithm AlgorithmIdentifier,
/// subjectPublicKey BIT STRING }`. We only look at the algorithm.
pub fn classify_pubkey(spki : @asn1.Asn1Value) -> PubkeyAlgorithm {
  guard spki is @asn1.Sequence(parts) else { return Other(oid="?") }
  if parts.length() < 1 {
    return Other(oid="?")
  }
  guard parts[0] is @asn1.Sequence(alg) else { return Other(oid="?") }
  if alg.length() < 1 {
    return Other(oid="?")
  }
  guard alg[0] is @asn1.ObjectIdentifier(arcs) else { return Other(oid="?") }
  let s = @asn1_oid.arcs_to_dotted(arcs_to_int(arcs))
  match s {
    "1.2.840.113549.1.1.1" =>
      // Look at the embedded RSA key for the modulus bit length.
      match (try_get_sequence(spki), try_get_bitstring(spki)) {
        (Some(parts), Some(bits)) => {
          ignore(parts)
          let n = rsa_modulus_bits(bits)
          Rsa(modulus_bits=n)
        }
        _ => Rsa(modulus_bits=None)
      }
    "1.2.840.10045.2.1" => {
      // EC: the algorithm parameters carry the curve OID.
      let curve = if alg.length() >= 2 {
        match alg[1] {
          @asn1.ObjectIdentifier(arcs) =>
            @asn1_oid.known_oid(arcs_to_int(arcs)).unwrap_or("unknown-curve")
          _ => None
        }
      } else {
        None
      }
      Ec(curve=curve)
    }
    "1.3.101.112" => Ed25519
    _ => Other(oid=s)
  }
}

fn arcs_to_int(arcs : Array[UInt]) -> Array[Int] {
  let out : Array[Int] = []
  for a in arcs {
    out.push(a.to_int())
  }
  out
}

fn try_get_sequence(v : @asn1.Asn1Value) -> Array[@asn1.Asn1Value]? {
  match v {
    @asn1.Sequence(items) => Some(items)
    _ => None
  }
}

fn try_get_bitstring(v : @asn1.Asn1Value) -> Bytes? {
  match v {
    @asn1.Sequence(items) =>
      for it in items {
        guard it is @asn1.BitString(unused_bits=_, data) else { continue }
        return Some(data)
      }
      None
    _ => None
  }
}

///|
/// Recover the bit length of an RSA modulus from the raw key bytes.
///
/// The BIT STRING contains a DER-encoded SEQUENCE { n, e, ... }. The
/// modulus `n` is an INTEGER, and we approximate its bit length by
/// counting leading zeros in the first byte of the integer and adding
/// (byte count * 8).
fn rsa_modulus_bits(key : Bytes) -> Int? {
  // Walk into the SEQUENCE { INTEGER n, INTEGER e }.
  let r = @asn1_reader.Reader::new(key)
  match @asn1_decode.decode_one(r) {
    Ok(@asn1.Sequence(parts)) =>
      if parts.length() >= 1 {
        match parts[0] {
          @asn1.Integer(n) => Some(integer_bit_length(n))
          _ => None
        }
      } else {
        None
      }
    _ => None
  }
}

fn integer_bit_length(b : Bytes) -> Int {
  let mut bits = 0
  for i, byte in b {
    let v = byte.to_int()
    if v == 0 {
      bits = bits
    } else {
      // Bit length of this byte + trailing zero bits.
      bits = i * 8 + 8 - leading_zeros_in_byte(v)
      return bits
    }
  }
  bits
}

fn leading_zeros_in_byte(v : Int) -> Int {
  let mut n = 0
  let mut mask = 0x80
  while mask > 0 {
    if (v & mask) != 0 {
      return n
    }
    n = n + 1
    mask = mask >> 1
  }
  n
}