///|
/// The result of inspecting a `SubjectPublicKeyInfo`'s algorithm field.
/// We do not parse the key material itself; the consuming crypto package
/// can do that based on this hint.
pub enum PubkeyAlgorithm {
  /// RSA with the modulus bit length recovered from the integer's leading
  /// byte count.
  Rsa(modulus_bits~ : Int?)
  /// EC, with the named curve OID if it was a named curve.
  Ec(curve~ : String?)
  /// Ed25519 (RFC 8422 / 8032).
  Ed25519
  /// Any other algorithm. The OID's dotted-decimal representation is
  /// preserved for callers to dispatch on.
  Other(oid~ : String)
} derive(Debug, Eq)

///|
/// Inspect a `SubjectPublicKeyInfo` ASN.1 value and return the algorithm.
/// `SubjectPublicKeyInfo` is `SEQUENCE { algorithm AlgorithmIdentifier,
/// subjectPublicKey BIT STRING }`. We only look at the algorithm.
pub fn classify_pubkey(spki : Asn1Value) -> PubkeyAlgorithm {
  guard spki is Sequence(parts) else { return Other(oid="?") }
  if parts.length() < 1 {
    return Other(oid="?")
  }
  guard parts[0] is Sequence(alg) else { return Other(oid="?") }
  if alg.length() < 1 {
    return Other(oid="?")
  }
  guard alg[0] is ObjectIdentifier(arcs) else { return Other(oid="?") }
  let s = arcs_to_dotted(arcs_to_int(arcs))
  match s {
    "1.2.840.113549.1.1.1" =>
      // Look at the embedded RSA key for the modulus bit length.
      match (try_get_sequence(spki), try_get_bitstring(spki)) {
        (Some(_), Some(bits)) => {
          let n = rsa_modulus_bits(bits)
          Rsa(modulus_bits=n)
        }
        _ => Rsa(modulus_bits=None)
      }
    "1.2.840.10045.2.1" => {
      // EC: the algorithm parameters carry the curve OID.
      let curve : String? = if alg.length() >= 2 {
        match alg[1] {
          ObjectIdentifier(arcs) =>
            Some(known_oid(arcs_to_int(arcs)).unwrap_or("unknown-curve"))
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

///|
/// A human-readable summary, e.g. `RSA-2048`, `EC-P-256`, `Ed25519`.
pub fn PubkeyAlgorithm::to_display(self : PubkeyAlgorithm) -> String {
  match self {
    Rsa(modulus_bits=Some(n)) => "RSA-" + n.to_string()
    Rsa(..) => "RSA"
    Ec(curve=Some(c)) => "EC-" + c
    Ec(..) => "EC"
    Ed25519 => "Ed25519"
    Other(oid=o) => "unknown (" + o + ")"
  }
}

fn try_get_sequence(v : Asn1Value) -> Array[Asn1Value]? {
  match v {
    Sequence(items) => Some(items)
    _ => None
  }
}

fn try_get_bitstring(v : Asn1Value) -> Bytes? {
  match v {
    Sequence(items) => {
      let mut result : Bytes? = None
      for it in items {
        if it is BitString(data~, ..) {
          result = Some(data)
          break
        }
      }
      result
    }
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
  let r = Reader::new(key)
  match decode_one(r) {
    Ok(Sequence(parts)) =>
      if parts.length() >= 1 {
        match parts[0] {
          Integer(n) => Some(integer_bit_length(n))
          _ => None
        }
      } else {
        None
      }
    _ => None
  }
}

fn integer_bit_length(b : Bytes) -> Int {
  let n = b.length()
  let mut i = 0
  while i < n && b[i].to_int() == 0 {
    i = i + 1
  }
  if i == n {
    return 0
  }
  // All-zero prefix skipped: bit length is the remaining byte count * 8
  // minus the leading zeros of the first significant byte.
  (n - i) * 8 - leading_zeros_in_byte(b[i].to_int())
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