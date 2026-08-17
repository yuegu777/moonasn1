# Test fixtures

Third-party test data referenced by `THIRD_PARTY_NOTICES.md`. Everything in
this directory exists to feed the test suite; none of it is required at
runtime by the library itself.

## Layout

```
tests/fixtures/wycheproof/
├── ecdsa_secp256r1_sha256_test.json   # Wycheproof verify vectors (Apache-2.0)
├── ecdsa_secp384r1_sha384_test.json
├── dsa_2048_256_sha256_test.json
└── gen_wycheproof.py                  # code generator (see below)

tests/fixtures/rfc5280/                # reserved, not yet populated
```

## Wycheproof vectors

Wycheproof has **no X.509 certificate vectors**. What it does ship that
exercises an ASN.1 DER decoder is the ECDSA / DSA *verify* vector files:

- every test group carries a `publicKeyDer` — a DER SubjectPublicKeyInfo;
- every test case carries a `sig` — a hex DER
  `SEQUENCE { r INTEGER, s INTEGER }`, including deliberately malformed
  encodings (BER long-form lengths, indefinite lengths, truncations,
  wrong child types, trailing garbage).

The three vendored JSON files were taken from the `testvectors_v1`
directory of <https://github.com/google/wycheproof> (Apache-2.0) and are
committed verbatim so that regeneration never depends on network access.

## Regenerating the tests

`src/wycheproof_wbtest.mbt` is **generated**; do not edit it by hand:

```sh
python3 tests/fixtures/wycheproof/gen_wycheproof.py
moon test
```

The generator classifies every vector with a strict reference DER validator
and emits, per vector file:

1. SPKI decode + `classify_pubkey` expectations (all distinct `publicKeyDer`);
2. `result: valid` signatures must decode to `SEQUENCE { INTEGER, INTEGER }`
   with canonical (minimal two's-complement) integer bodies;
3. `result: acceptable` signatures must decode (canonicality not asserted);
4. `result: invalid` signatures whose *encoding* violates DER must be
   rejected with `Err` (crypto-invalid but DER-well-formed vectors are
   skipped — a parser has nothing to assert about them).

Rerunning the generator against a newer Wycheproof drop should be
byte-identical unless upstream changes the vectors.

## rfc5280/

Reserved for RFC 5280 Appendix A ASN.1 module excerpts and encoded
certificate samples. Not yet populated; the end-to-end certificate
regressions currently live in `src/cert_wbtest.mbt` as self-signed
certificates generated with `openssl req -x509`.
