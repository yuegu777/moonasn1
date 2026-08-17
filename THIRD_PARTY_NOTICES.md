# Third-Party Notices

`moonasn1` redistributes a small amount of third-party material for the sole
purpose of running the test suite. Each item below states the upstream source,
the SPDX-License-Identifier, and where it lives in this repository.

## Test fixtures

### RFC 5280 Appendix A — X.509 module and certificate examples

- Source: <https://www.rfc-editor.org/rfc/rfc5280>
- License: BSD-3-Clause (RFC text license, see <https://www.rfc-editor.org/>)
- Location: `tests/fixtures/rfc5280/` (reserved; not yet populated)
- Use (planned): Small excerpts of ASN.1 module text and encoded
  certificates used as positive and negative parser test cases.
- Modifications: When vendored, files will be included verbatim with a
  header comment citing the upstream RFC number and section.

### Wycheproof — ECDSA/DSA verify test vectors

- Source: <https://github.com/google/wycheproof>
  (`testvectors_v1/` directory on `main`)
- License: Apache-2.0
- Location: `tests/fixtures/wycheproof/*.json`
- Files: `ecdsa_secp256r1_sha256_test.json`,
  `ecdsa_secp384r1_sha384_test.json`, `dsa_2048_256_sha256_test.json`
- Use: The `publicKeyDer` fields (DER SubjectPublicKeyInfo) and `sig`
  fields (DER `SEQUENCE { r INTEGER, s INTEGER }`, including deliberately
  malformed encodings) drive the generated robustness tests in
  `src/wycheproof_wbtest.mbt`. Wycheproof ships no X.509 certificate
  vectors; these signature/SPKI vectors are what exercise the DER layer.
- Modifications: JSON files are included verbatim. The generated test file
  embeds hex strings extracted from them via
  `tests/fixtures/wycheproof/gen_wycheproof.py`; no MoonBit code is
  derived from Wycheproof sources.

## Reference implementations studied (no code copied)

These projects are listed for reviewer transparency. **No source code was
copied from them.** They were used to study public interface shapes and
fail-closed decoder patterns only.

- `@blamejs/pki` (ISC) — <https://github.com/blamejs/pki>
- `cddl-rs` (Apache-2.0) — <https://github.com/anweiss/cddl>

If, in a future revision, code is copied or translated, this file will be
updated first with a per-file notice.