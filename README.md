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

`moonasn1` is a single package. Import it by path and call `parse_cert`,
which returns a `Result`:

```moonbit
// moon.pkg:
//   import { "yuegu777/moonasn1/src" @moonasn1, }
fn main {
  // der_bytes comes from a .der file or from base64-decoding a PEM block.
  match @moonasn1.parse_cert(der_bytes) {
    Ok(cert) => {
      println("subject: " + cert.subject_dn_string())
      println("issuer : " + cert.issuer_dn_string())
      println("valid  : " + cert.not_before.to_rfc3339() + " -> " + cert.not_after.to_rfc3339())
      println("pubkey : " + cert.public_key_algorithm.to_display()) // e.g. RSA-2048
    }
    Err(e) => println("parse error: " + e)
  }
}
```

The examples embed real self-signed certificates (RSA-2048 and EC P-256,
generated with `openssl req -x509`), so they run anywhere with no file IO:

```
moon run examples/parse_cert     # parse one DER certificate
moon run examples/parse_stream   # parse an embedded PEM bundle
```

## Project layout

```
moonasn1/
├── README.md          # this file
├── REFERENCES.md      # upstream specs and reference projects (audit trail)
├── THIRD_PARTY_NOTICES.md
├── LICENSE            # Apache-2.0
├── moon.mod           # module manifest
├── moon.work          # workspace root
├── src/               # the library (single package: DER codec + X.509 layer)
│ ├── tag.mbt          # ASN.1 tag classes and universal tag numbers
│ ├── value.mbt        # Asn1Value ADT (the parsed tree)
│ ├── reader.mbt       # bounded Bytes reader with depth/length limits
│ ├── decode.mbt       # top-level DER decoder
│ ├── oid.mbt          # OID dotted-decimal helpers and lookup table
│ ├── time.mbt         # UTCTime / GeneralizedTime parsing, RFC 3339 output
│ ├── name.mbt         # X.500 RDN / DN parsing
│ ├── pubkey.mbt       # SubjectPublicKeyInfo algorithm classification
│ ├── cert.mbt         # Certificate decoding (entry point)
│ └── *_wbtest.mbt     # tests, incl. real-certificate end-to-end regressions
├── examples/
│ ├── parse_cert/      # parse a single DER certificate (embedded sample)
│ └── parse_stream/    # parse a PEM bundle (embedded sample)
├── tests/fixtures/    # reserved for third-party test vectors (see its README)
└── .github/workflows/ci.yml
```

## Running locally

```bash
moon check                      # type-check (default target)
moon check --target all         # native, wasm, wasm-gc, js
moon test                       # run the test suite
moon run examples/parse_cert    # run the examples
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
