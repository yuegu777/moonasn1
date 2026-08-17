# Changelog

All notable changes to `moonasn1` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial public release of the DER codec and X.509 v3 certificate
  parser.
- `src/asn1/`: bounded DER reader, universal-tag codec, OID lookup.
- `src/x509/`: `Certificate` struct, DN parser, time parser,
  public-key-algorithm classifier.
- Examples: `examples/parse_cert`, `examples/parse_stream`.
- CI on Linux and macOS (`moon check`, `moon test`, `moon build`).
- Certificate extension parsing: `subjectAltName` (GeneralName forms),
  `keyUsage`, `basicConstraints`, `extKeyUsage`, `subjectKeyIdentifier`,
  `authorityKeyIdentifier`, plus generic extension enumeration.
- PEM decoding (`decode_pem`, `decode_pem_all`): RFC 7468 text envelope
  parser with an inline Base64 (RFC 4648) decoder. Extracts DER bytes
  from `-----BEGIN ...-----` / `-----END ...-----` blocks.
- Wycheproof-based DER robustness tests: 916 generated assertions from
  the ECDSA/DSA verify vectors (SPKI decoding and classification, valid
  DER signature structure/canonicality, malformed-encoding rejection),
  vendored under `tests/fixtures/wycheproof/` with the generator script.

### Fixed

- DER decoding is now strictly minimal per X.690: long-form lengths that
  fit the short form (e.g. `81 45`), and length octets with leading
  zeros, are rejected.
- `decode_element` rejects trailing bytes after the top-level element.
- A malformed child inside a SEQUENCE/SET no longer silently yields a
  partially decoded container; the whole element now fails.

### Non-goals

- BER (indefinite length) and CER are not supported; only DER.
- Cryptographic verification and chain validation are out of scope.
- CRL, OCSP, CSR, CMS, PKCS#12 are out of scope.

## [0.1.0] — 2026-08-23

Planned release target for the OSC 2026 evaluation.