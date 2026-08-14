# moonasn1 — References and Provenance

This file records the upstream specifications, reference implementations, and test
suites that `moonasn1` is built on. It exists so the OSC 2026 reviewers can audit
provenance and license compatibility at a glance.

## Specifications (normative)

| ID | Title | Status |
|---|---|---|
| ITU-T X.680 | Information technology — Abstract Syntax Notation One (ASN.1): Specification of basic notation | Latest |
| ITU-T X.690 | ASN.1 encoding rules: Basic, Canonical, Distinguished, and Octet Encoding Rules (BER/DER/CER) | Latest |
| ITU-T X.509 | Information technology — Open Systems Interconnection — The Directory: Public-key and attribute certificate frameworks | Latest |
| RFC 5280 | Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile | Proposed Standard |

Sources of normative text (public):
- <https://www.itu.int/rec/T-REC-X/en> (ITU-T X-series, free for reading)
- <https://datatracker.ietf.org/doc/html/rfc5280> (RFC 5280, BSD-3-Clause text license)

> The ASN.1 module text in ITU-T X.509 is reproduced in normative form in RFC 5280
> Appendix A. The implementation in `moonasn1` parses that RFC 5280 profile, not
> the full ITU-T catalogue.

## Reference implementations studied (background, NOT vendored)

| Project | URL | License | Used for |
|---|---|---|---|
| `@blamejs/pki` | github.com/blamejs/pki | ISC | DER codec shape, X.509 schema, OID registry structure |
| `rusticata` `pcap-parser` (not vendored; we do not parse PCAP) | github.com/rusticata/pcap-parser | MIT | Inapplicable — only kept as a "struct-of-byte-readers" reference style |
| `cddl-rs` (not vendored) | github.com/anweiss/cddl | Apache-2.0 | Read for "fail-closed DER decoder" design philosophy only |

> No source code is copied from these projects. Only design ideas (DER is a
> strict subset of BER; decoder must be bounded in time and depth; OID table
> drives both parsing and stringification).

## External test fixtures (re-distributed)

The test fixtures under `tests/fixtures/` come from the public RFC repository.
They are short, public-domain ASN.1 excerpts used as positive/negative parse
cases.

| Source | Origin | License | Location in this repo |
|---|---|---|---|
| RFC 5280 Appendix A (X.509 module) | datatracker.ietf.org | BSD-3-Clause | `tests/fixtures/rfc5280/` |
| Wycheproof X.509 test vectors | github.com/google/wycheproof | Apache-2.0 | `tests/fixtures/wycheproof/x509/` |

> Each fixture file is included verbatim; the accompanying `THIRD_PARTY_NOTICES.md`
> in this directory restates the upstream license and the SPDX-License-Identifier.

## Compliance constraints (mirrored from `osc2026-guide`)

`moonasn1` will:

- Be released under **Apache-2.0**.
- Cite every third-party asset in `THIRD_PARTY_NOTICES.md`.
- Pass `moon check`, `moon test`, `moon build` on Linux and macOS in CI.
- Avoid copying code from any non-Apache-2.0 / BSD-3-Clause / MIT / ISC project
  unless explicitly cleared in this file.

## Non-goals (explicit)

- Full ITU-T X.680/X.690 coverage. The first version targets **DER** only,
  which is a strict subset of BER. CER is **not** supported in v1.
- Full X.509 schema. v1 covers `Certificate` and `TBSCertificate`. CRL, OCSP,
  CSR (PKCS#10), CMS, and PKCS#12 are out of scope.
- Cryptography. `moonasn1` parses bytes; it does not verify signatures,
  validate chains, or generate certificates. Pair it with a separate crypto
  package for those.

## Versioning

The package follows semver. The current target is **0.1.0**. Breaking changes
to the public API (the `Asn1Value` and `Certificate` types) will bump the
minor version and appear in `CHANGELOG.md` before publishing to `mooncakes.io`.