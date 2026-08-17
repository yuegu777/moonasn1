///|
test "known_oid returns friendly names" {
  // CN
  let arcs : Array[Int] = [2, 5, 4, 3]
  assert_eq(known_oid(arcs), Some("commonName"))
  // sha256WithRSAEncryption
  let arcs2 : Array[Int] = [1, 2, 840, 113549, 1, 1, 11]
  assert_eq(known_oid(arcs2), Some("sha256WithRSAEncryption"))
  // subjectAltName
  let arcs3 : Array[Int] = [2, 5, 29, 17]
  assert_eq(known_oid(arcs3), Some("subjectAltName"))
}

///|
test "known_oid returns None for unknown arcs" {
  let arcs : Array[Int] = [1, 2, 3]
  assert_eq(known_oid(arcs), None)
}

///|
test "arcs_to_dotted formats correctly" {
  let arcs : Array[Int] = [1, 2, 840, 113549]
  assert_eq(arcs_to_dotted(arcs), "1.2.840.113549")
  let empty : Array[Int] = []
  assert_eq(arcs_to_dotted(empty), "")
}
