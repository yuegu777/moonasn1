#!/usr/bin/env python3
"""Generate src/wycheproof_wbtest.mbt from Wycheproof test vectors.

Wycheproof has no X.509 certificate vectors; what it does ship that exercises
an ASN.1 DER decoder is the ECDSA / DSA verify vector files:

  * `publicKeyDer` in every test group is a DER SubjectPublicKeyInfo
    -> exercises decode_element + classify_pubkey.
  * `sig` in every test case is a hex DER signature
    `SEQUENCE { r INTEGER, s INTEGER }`, including deliberately malformed
    BER / non-minimal / truncated encodings
    -> exercises decode_element acceptance and rejection.

This script classifies each vector with a strict reference DER validator and
emits four test blocks per vector file:

  1. SPKI decode + classify_pubkey expectations
  2. `result: valid` signatures must decode to SEQUENCE{INTEGER, INTEGER}
     with canonical (minimal two's-complement) integer bodies
  3. `result: acceptable` signatures must decode (structure asserted,
     canonicality NOT asserted)
  4. `result: invalid` signatures whose encoding violates DER must be
     rejected with Err

Usage:
    python3 gen_wycheproof.py
(writes ../../../src/wycheproof_wbtest.mbt relative to this file)

Vectors: Project Wycheproof, https://github.com/google/wycheproof
(Apache-2.0). Downloaded from the `testvectors_v1` directory on `main`.
"""

import json
import os
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "..", "src", "wycheproof_wbtest.mbt")

FILES = [
    # (filename, expected classify_pubkey pattern)
    ("ecdsa_secp256r1_sha256_test.json", 'Ec(curve=Some("P-256"))'),
    ("ecdsa_secp384r1_sha384_test.json", 'Ec(curve=Some("P-384"))'),
    ("dsa_2048_256_sha256_test.json", 'Other(oid="1.2.840.10040.4.1")'),
]

REJECT_CAP = 250  # max malformed cases emitted per file, keeps the .mbt sane


# ---------------------------------------------------------------------------
# Strict reference DER validation for SEQUENCE { INTEGER, INTEGER }
# ---------------------------------------------------------------------------

def read_tlv(buf, i):
    """Parse one TLV at `i` under strict DER rules.

    Returns (tag, body_start, body_len, next_index) or None on violation:
    indefinite/long-form-when-short-works/oversize length octets, high tag
    numbers, or bounds errors.
    """
    n = len(buf)
    if i >= n:
        return None
    tag = buf[i]
    j = i + 1
    if tag & 0x1F == 0x1F:
        # multi-byte tag number (X.690 §8.1.2.4): valid DER, read base-128
        while j < n and buf[j] & 0x80:
            j += 1
        if j >= n:
            return None
        j += 1
    if j >= n:
        return None
    b = buf[j]
    if b < 0x80:
        length, j = b, j + 1
    elif b == 0x80:
        return None  # indefinite length: BER only
    else:
        num = b & 0x7F
        if num > 4 or j + 1 + num > n:
            return None
        ln_bytes = buf[j + 1 : j + 1 + num]
        j = j + 1 + num
        if ln_bytes[0] == 0:
            return None  # non-minimal length octets
        length = int.from_bytes(ln_bytes, "big")
        if length < 0x80:
            return None  # long form used where short form fits
    if j + length > n:
        return None
    return tag, j, length, j + length


def integer_canonical(body):
    """Minimal two's-complement INTEGER body per DER X.690 §10.4 / §8.3.2."""
    if len(body) == 0:
        return False
    if len(body) == 1:
        return True
    if body[0] == 0x00 and (body[1] & 0x80) == 0:
        return False
    if body[0] == 0xFF and (body[1] & 0x80) != 0:
        return False
    return True


def classify_signature(hexstr):
    """Return one of 'canonical', 'der-ok', 'invalid'."""
    try:
        buf = bytes.fromhex(hexstr)
    except ValueError:
        return "invalid"
    top = read_tlv(buf, 0)
    if top is None:
        return "invalid"
    tag, body_start, body_len, end = top
    if end != len(buf):
        return "invalid"  # trailing garbage
    if tag != 0x30:
        return "der-ok"  # valid DER, wrong top-level type
    i, kids = body_start, []
    while i < body_start + body_len:
        tlv = read_tlv(buf, i)
        if tlv is None:
            return "invalid"
        t, s, l, i = tlv
        kids.append((t, buf[s : s + l]))
    if len(kids) != 2 or any(t != 0x02 for t, _ in kids):
        return "der-ok"  # valid DER, wrong child types / count
    if not all(integer_canonical(b) for _, b in kids):
        return "der-ok"  # decodes, but integer bodies are non-minimal
    return "canonical"


# ---------------------------------------------------------------------------
# Code emission
# ---------------------------------------------------------------------------

HEADER = """\
///|
// GENERATED FILE — DO NOT EDIT.
// Regenerate with: python3 tests/fixtures/wycheproof/gen_wycheproof.py
//
// Source: Project Wycheproof test vectors (Apache-2.0),
// https://github.com/google/wycheproof — files below were taken from the
// `testvectors_v1` directory and are mirrored under
// tests/fixtures/wycheproof/ for provenance:
//   %s
//
// Wycheproof ships no X.509 certificate vectors; these ECDSA/DSA verify
// vectors are what exercise the ASN.1 DER layer: `publicKeyDer` entries
// are DER SubjectPublicKeyInfo blobs and `sig` entries are DER
// SEQUENCE { r INTEGER, s INTEGER } signatures, including deliberately
// malformed encodings that a strict DER decoder must reject.

///|
/// Hex string (lower- or upper-case, even length) to `Bytes`.
fn wp_hex_to_bytes(s : String) -> Bytes {
  fn hv(c : Int) -> Int {
    if c >= 48 && c <= 57 {
      c - 48
    } else if c >= 97 && c <= 102 {
      c - 87
    } else if c >= 65 && c <= 70 {
      c - 55
    } else {
      -1
    }
  }
  Bytes::makei(s.length() / 2, i => {
    let hi = hv(s.get(i * 2).unwrap_or(0).to_int())
    let lo = hv(s.get(i * 2 + 1).unwrap_or(0).to_int())
    (hi * 16 + lo).to_byte()
  })
}

///|
/// DER INTEGER body must be a minimal two's-complement encoding.
fn wp_integer_canonical(b : Bytes) -> Bool {
  let n = b.length()
  if n == 0 {
    return false
  }
  if n == 1 {
    return true
  }
  let f = b[0].to_int()
  if f == 0 && (b[1].to_int() & 0x80) == 0 {
    return false
  }
  if f == 0xFF && (b[1].to_int() & 0x80) != 0 {
    return false
  }
  true
}

///|
/// Shared assertions for one Wycheproof `sig` vector.
/// `expect` is "canonical" (decode Ok, SEQUENCE of 2 canonical INTEGERs),
/// "structure" (decode Ok, SEQUENCE of 2 INTEGERs, canonicality unchecked)
/// or "reject" (decode must fail).
fn wp_check_sig(file : String, tcid : Int, hex : String, expect : String) -> Unit raise {
  match decode_element(wp_hex_to_bytes(hex)) {
    Ok(v) => {
      if expect == "reject" {
        fail("wycheproof " + file + " tcId=" + tcid.to_string() + " should have been rejected")
      }
      guard v is Sequence(items) else {
        fail("wycheproof " + file + " tcId=" + tcid.to_string() + ": top level is not a SEQUENCE")
      }
      if items.length() != 2 {
        fail("wycheproof " + file + " tcId=" + tcid.to_string() + ": expected 2 children, got " + items.length().to_string())
      }
      for k, item in items {
        guard item is Integer(body) else {
          fail("wycheproof " + file + " tcId=" + tcid.to_string() + ": child " + k.to_string() + " is not an INTEGER")
        }
        if expect == "canonical" && !wp_integer_canonical(body) {
          fail("wycheproof " + file + " tcId=" + tcid.to_string() + ": non-minimal INTEGER body")
        }
      }
    }
    Err(_) => {
      if expect != "reject" {
        fail("wycheproof " + file + " tcId=" + tcid.to_string() + ": decode failed, expected success")
      }
    }
  }
}
"""


def moon_str(s):
    return '"' + s + '"'


def emit_file_blocks(name, classify_pattern, data):
    short = name[: -len("_test.json")]
    lines = []
    stats = {"spki": 0, "valid": 0, "acceptable": 0, "reject": 0, "skipped": 0}

    # -- 1. SPKI ------------------------------------------------------------
    spki_cases = []
    seen = set()
    for g in data["testGroups"]:
        der = g.get("publicKeyDer", "")
        if not der or der in seen:
            continue
        seen.add(der)
        # reference: SPKI must itself decode under our strict rules
        if classify_signature(der) in ("invalid",):
            stats["skipped"] += 1
            continue
        spki_cases.append(der)
    stats["spki"] = len(spki_cases)

    lines.append("///|")
    lines.append(
        'test "wycheproof %s: SubjectPublicKeyInfo decode + classify" {'
        % short
    )
    lines.append("  let keys : Array[String] = [")
    for der in spki_cases:
        lines.append("    %s," % moon_str(der))
    lines.append("  ]")
    lines.append("  for i, hex in keys {")
    lines.append("    let der = wp_hex_to_bytes(hex)")
    lines.append("    match decode_element(der) {")
    lines.append("      Ok(v) =>")
    lines.append("        match classify_pubkey(v) {")
    lines.append("          %s => ()" % classify_pattern)
    lines.append(
        '          other => fail("wycheproof %s SPKI #" + i.to_string() + ": wrong algorithm " + other.to_display())'
        % short
    )
    lines.append("        }")
    lines.append(
        '      Err(_) => fail("wycheproof %s SPKI #" + i.to_string() + ": decode failed")'
        % short
    )
    lines.append("    }")
    lines.append("  }")
    lines.append("}")
    lines.append("")

    # -- 2/3/4. signature cases --------------------------------------------
    valid, acceptable, rejects = [], [], []
    by_flag = defaultdict(list)
    for g in data["testGroups"]:
        for t in g["tests"]:
            sig = t["sig"]
            verdict = classify_signature(sig)
            if t["result"] == "valid":
                if verdict != "canonical":
                    raise SystemExit(
                        "reference disagrees with 'valid' tcId=%d (%s): %s"
                        % (t["tcId"], verdict, t["comment"])
                    )
                valid.append((t["tcId"], sig))
            elif t["result"] == "acceptable":
                if verdict == "invalid":
                    raise SystemExit(
                        "reference rejects 'acceptable' tcId=%d" % t["tcId"]
                    )
                acceptable.append((t["tcId"], sig))
            else:  # invalid
                if verdict == "invalid":
                    key = ",".join(t["flags"]) or "none"
                    by_flag[key].append((t["tcId"], sig))
                else:
                    stats["skipped"] += 1

    # cap rejects, keeping flag diversity via round-robin over flags
    order = sorted(by_flag, key=lambda k: -len(by_flag[k]))
    rr = 0
    while len(rejects) < REJECT_CAP and any(by_flag[f] for f in order):
        f = order[rr % len(order)]
        if by_flag[f]:
            rejects.append(by_flag[f].pop(0))
        rr += 1
    stats["valid"] = len(valid)
    stats["acceptable"] = len(acceptable)
    stats["reject"] = len(rejects)

    for label, cases, expect in [
        ("valid signatures decode canonically", valid, "canonical"),
        ("acceptable signatures decode", acceptable, "structure"),
        ("malformed DER signatures are rejected", rejects, "reject"),
    ]:
        if not cases:
            continue
        lines.append("///|")
        lines.append('test "wycheproof %s: %s" {' % (short, label))
        lines.append("  // (tcId, sig hex)")
        lines.append("  let cases : Array[(Int, String)] = [")
        for tcid, sig in cases:
            lines.append("    (%d, %s)," % (tcid, moon_str(sig)))
        lines.append("  ]")
        lines.append("  for c in cases {")
        lines.append(
            '    wp_check_sig("%s", c.0, c.1, "%s")' % (short, expect)
        )
        lines.append("  }")
        lines.append("}")
        lines.append("")

    return "\n".join(lines), stats


def main():
    total = defaultdict(int)
    body_parts = []
    names = [n for n, _ in FILES]
    for name, pattern in FILES:
        with open(os.path.join(HERE, name)) as f:
            data = json.load(f)
        block, stats = emit_file_blocks(name, pattern, data)
        body_parts.append(block)
        for k, v in stats.items():
            total[k] += v
        print(
            "%-38s spki=%3d valid=%3d acceptable=%2d reject=%3d skipped=%3d"
            % (name, stats["spki"], stats["valid"], stats["acceptable"],
               stats["reject"], stats["skipped"])
        )
    print(
        "TOTAL spki=%d valid=%d acceptable=%d reject=%d skipped=%d"
        % (total["spki"], total["valid"], total["acceptable"],
           total["reject"], total["skipped"])
    )
    with open(OUT, "w") as f:
        f.write(HEADER % ",\n//   ".join(names))
        f.write("\n")
        for p in body_parts:
            f.write(p)
    print("wrote", os.path.abspath(OUT))


if __name__ == "__main__":
    main()
