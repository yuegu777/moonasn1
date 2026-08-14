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

### Non-goals

- BER (indefinite length) and CER are not supported; only DER.
- Cryptographic verification and chain validation are out of scope.
- CRL, OCSP, CSR, CMS, PKCS#12 are out of scope.

## [0.1.0] — 2026-08-23

Planned release target for the OSC 2026 evaluation.