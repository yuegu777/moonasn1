# Test fixtures

This directory is reserved for the third-party test fixtures cited in
`THIRD_PARTY_NOTICES.md`.

## Layout

```
tests/fixtures/
├── rfc5280/         # RFC 5280 Appendix A: ASN.1 module + certificate samples
└── wycheproof/x509/ # Wycheproof X.509 encoded-certificate vectors
```

## Populating this directory

The fixtures are **not vendored in the public repository** to keep the
distribution small and to make license review trivial. The recommended
recipe is to add them in a dedicated commit just before tagging the
release, with a message like `chore(fixtures): vendor RFC 5280 and
Wycheproof test vectors per THIRD_PARTY_NOTICES.md`.

The fetching script lives at `tests/fixtures/SYNC.sh` (added in the
fixtures commit, not in this skeleton).

## Why this directory is empty in the public repository

Two reasons:

1. The bytes themselves add ~150 KB to every clone, which matters for
   a tiny pure-parser library.
2. Vendoring copyrighted test data in the public repo can complicate
   license audits. Keeping the fixtures in a separate commit, with a
   clearly-scoped purpose, makes the audit trivial.

The parser is fully testable without these fixtures: the `*_test.mbt`
files under `src/asn1/` and `src/x509/` exercise the codec and the
basic shape of every variant directly with hand-rolled byte arrays.
The fixtures only add coverage of real-world certificate edge cases.