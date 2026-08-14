# Third-Party Notices

`moonasn1` redistributes a small amount of third-party material for the sole
purpose of running the test suite. Each item below states the upstream source,
the SPDX-License-Identifier, and where it lives in this repository.

## Test fixtures

### RFC 5280 Appendix A — X.509 module and certificate examples

- Source: <https://www.rfc-editor.org/rfc/rfc5280>
- License: BSD-3-Clause (RFC text license, see <https://www.rfc-editor.org/>)
- Location: `tests/fixtures/rfc5280/`
- Use: Small excerpts of ASN.1 module text and encoded certificates used as
  positive and negative parser test cases.
- Modifications: Files are included verbatim. Each file carries a header
  comment with the upstream RFC number and section reference.

### Wycheproof — X.509 test vectors

- Source: <https://github.com/google/wycheproof/tree/master/testvectors>
- License: Apache-2.0
- Location: `tests/fixtures/wycheproof/x509/`
- Use: Public, hand-curated encoded certificate examples used as
  positive parser cases.
- Modifications: Files are included verbatim; no MoonBit code is derived
  from Wycheproof.

## Reference implementations studied (no code copied)

These projects are listed for reviewer transparency. **No source code was
copied from them.** They were used to study public interface shapes and
fail-closed decoder patterns only.

- `@blamejs/pki` (ISC) — <https://github.com/blamejs/pki>
- `cddl-rs` (Apache-2.0) — <https://github.com/anweiss/cddl>

If, in a future revision, code is copied or translated, this file will be
updated first with a per-file notice.