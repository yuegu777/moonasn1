# moonasn1

> A pure MoonBit ASN.1 DER codec and X.509 certificate parser.

`moonasn1` reads and decodes binary data encoded with the **Distinguished
Encoding Rules (DER)** of ASN.1 (ITU-T X.690), and exposes a high-level
parser for **X.509 certificates** (RFC 5280). It does not perform
cryptography: it parses bytes and surfaces a typed tree that another
package can verify or sign.

## Why this exists

ASN.1 / DER is the wire format of every TLS certificate, every OCSP
response, and every X.509 attribute. In the MoonBit ecosystem, there is
no general-purpose ASN.1 codec yet, so anything that wants to read a
`.pem` or `.der` certificate has to vendor one. `moonasn1` fills that
gap with a small, strict, easy-to-audit library:

- **DER only.** DER is a strict subset of BER. Bounded inputs only; no
  indefinite lengths, no constructed-vs-primitive ambiguity.
- **X.509 v3.** Covers `Certificate` and `TBSCertificate` plus the most
  common extensions (SAN, Key Usage, Basic Constraints, SKI/AKI).
- **Bounded decoder.** Maximum depth and byte size are enforced before
  a byte is read, so a hostile input cannot blow the stack.
- **Pure MoonBit.** No FFI, no platform-specific code, works on Native,
  Wasm-GC, and JavaScript backends.

## Quick start

```moonbit
///|
fn main {
  let der_bytes : Bytes = read_file("cert.der")
  let cert = @x509.parse_cert(der_bytes) catch {
    e => {
      println("parse error: \{e}")
      return
    }
  }
  println("subject: \{cert.subject_dn_string()}")
  println("issuer : \{cert.issuer_dn_string()}")
  println("valid  : \{cert.not_before} -> \{cert.not_after}")
  match cert.public_key_algorithm {
    Rsa(modulus_bits=Some(n)) => println("RSA key: \{n} bits")
    Ec(curve=Some(curve)) => println("EC key: \{curve}")
    _ => ()
  }
}
```

## Project layout

```
moonasn1/
├── README.md          # this file
├── REFERENCES.md      # upstream specs and reference projects (audit trail)
├── THIRD_PARTY_NOTICES.md
├── LICENSE            # Apache-2.0
├── moon.pkg.json      # main package manifest
├── moon.work          # multi-target workspace
├── src/
│ ├── asn1/            # generic DER codec
│ │ ├── tag.mbt        # ASN.1 tag constants and TagNumber enum
│ │ ├── value.mbt      # Asn1Value ADT and Show/derive helpers
│ │ ├── reader.mbt     # bounded Bytes reader
│ │ ├── decode.mbt     # top-level DER decoder
│ │ └── oid.mbt        # ObjectIdentifier type and lookup table
│ └── x509/            # RFC 5280 layer
│ ├── time.mbt         # ASN.1 UTCTime / GeneralizedTime parsers
│ ├── name.mbt         # RDN / DN parser
│ ├── tbs.mbt          # TBSCertificate decoding
│ ├── cert.mbt         # Certificate decoding (entry point)
│ └── pubkey.mbt       # SubjectPublicKeyInfo + algorithm OIDs
├── examples/
│ ├── parse_cert/      # parse a single .der certificate
│ └── parse_stream/    # parse a PEM bundle
├── tests/             # moon test
└── .github/workflows/ci.yml
```

## Running locally

```bash
moon check
moon test
moon run examples/parse_cert
moon run examples/parse_stream
```

## Non-goals (explicit)

`moonasn1` does **not**:

- Verify signatures, certificate chains, or trust.
- Generate certificates or keys.
- Implement BER/CER/PER (X.690 other encoding rules).
- Implement CRL, OCSP, CSR (PKCS#10), CMS, or PKCS#12.
- Replace a crypto library. Pair it with one of your choice for
  cryptographic operations.

See `REFERENCES.md` for the normative documents and reference projects
this library is built on.

## License

Apache-2.0. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.
