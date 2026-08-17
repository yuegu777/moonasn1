///|
/// A decoded PEM block (RFC 7468 §3).
///
/// PEM is the Base64-with-headers format used to carry DER-encoded
/// structures in text channels. A block looks like:
///
/// ```text
/// -----BEGIN CERTIFICATE-----
/// MIIB...
/// -----END CERTIFICATE-----
/// ```
///
/// The `label` is the text between `BEGIN ` and the closing `-----`
/// (e.g. `CERTIFICATE`, `PRIVATE KEY`, `PUBLIC KEY`).
pub struct PemBlock {
  /// The label from the BEGIN/END header, e.g. "CERTIFICATE".
  label : String
  /// The decoded binary data (typically DER-encoded).
  data : Bytes
} derive(Debug, Eq)

///|
/// Decode the first PEM block from `text`. Returns `None` when no valid
/// `-----BEGIN ...----- ... -----END ...-----` envelope is found or the
/// Base64 payload is malformed.
pub fn decode_pem(text : String) -> PemBlock? {
  let begin_pos = match find_str(text, "-----BEGIN ", 0) {
    Some(p) => p
    None => return None
  }
  // Label starts right after "-----BEGIN "
  let label_start = begin_pos + 11
  // The begin line ends with "-----"
  let dash_pos = match find_str(text, "-----", label_start) {
    Some(p) => p
    None => return None
  }
  let label = text_range(text, label_start, dash_pos)
  // Find the matching END marker
  let end_marker = "-----END " + label + "-----"
  let end_pos = match find_str(text, end_marker, dash_pos + 5) {
    Some(p) => p
    None => return None
  }
  // Base64 payload is everything between the begin and end lines
  let b64_text = text_range(text, dash_pos + 5, end_pos)
  let data = match base64_decode(b64_text) {
    Some(d) => d
    None => return None
  }
  Some({ label, data })
}

///|
/// Decode all PEM blocks from `text`. Blocks with a malformed Base64
/// payload are silently skipped. Returns an empty array when no blocks
/// are found.
pub fn decode_pem_all(text : String) -> Array[PemBlock] {
  let blocks : Array[PemBlock] = []
  let mut pos = 0
  while pos < text.length() {
    let begin_pos = match find_str(text, "-----BEGIN ", pos) {
      Some(p) => p
      None => break
    }
    let label_start = begin_pos + 11
    let dash_pos = match find_str(text, "-----", label_start) {
      Some(p) => p
      None => break
    }
    let label = text_range(text, label_start, dash_pos)
    let end_marker = "-----END " + label + "-----"
    let end_pos = match find_str(text, end_marker, dash_pos + 5) {
      Some(p) => p
      None => break
    }
    let b64_text = text_range(text, dash_pos + 5, end_pos)
    match base64_decode(b64_text) {
      Some(data) => blocks.push({ label, data })
      None => ()
    }
    pos = end_pos + end_marker.length()
  }
  blocks
}

///|
pub fn PemBlock::to_display(self : PemBlock) -> String {
  "-----BEGIN " + self.label + "----- (" + self.data.length().to_string() + " bytes)"
}

// ---------------------------------------------------------------------------
// Base64 (RFC 4648) decoder
// ---------------------------------------------------------------------------

///|
/// Decode a Base64 string to bytes. Whitespace and other non-Base64
/// characters (newlines, carriage returns, spaces) are silently
/// skipped. Returns `None` when the input is empty or the Base64
/// content is malformed (bad length, invalid characters after
/// filtering, or padding errors).
fn base64_decode(input : String) -> Bytes? {
  let values : Array[Int] = []
  for i in 0..<input.length() {
    match input.get_char(i) {
      Some(c) => {
        let v = b64_val(c)
        if v >= 0 {
          values.push(v)
        } else if c == '=' {
          values.push(-1) // padding sentinel
        }
        // Ignore all other characters (whitespace, etc.)
      }
      None => ()
    }
  }
  if values.length() == 0 || values.length() % 4 != 0 {
    return None
  }
  // Padding can only appear in the last group, at most 2 '=' chars
  let n = values.length()
  let last_group = values[n - 1] == -1 || values[n - 2] == -1
  if !last_group {
    // Check for '=' in the middle
    for i in 0..<(n - 4) {
      if values[i] == -1 {
        return None
      }
    }
  }
  let out : Array[Byte] = []
  let mut i = 0
  while i < n {
    let c0 = values[i]
    let c1 = values[i + 1]
    if c0 < 0 || c1 < 0 {
      return None
    }
    out.push(((c0 << 2) | (c1 >> 4)).to_byte())
    if i + 2 < n && values[i + 2] >= 0 {
      let c2 = values[i + 2]
      out.push((((c1 & 0xF) << 4) | (c2 >> 2)).to_byte())
      if i + 3 < n && values[i + 3] >= 0 {
        let c3 = values[i + 3]
        out.push((((c2 & 0x3) << 6) | c3).to_byte())
      }
    }
    i = i + 4
  }
  Some(Bytes::from_array(out))
}

///|
/// Map one Base64 character to its 6-bit value, or -1 if not a Base64
/// alphabet character (A-Z, a-z, 0-9, +, /).
fn b64_val(c : Char) -> Int {
  let v = c.to_int()
  if v >= 65 && v <= 90 {
    v - 65 // A-Z -> 0-25
  } else if v >= 97 && v <= 122 {
    v - 71 // a-z -> 26-51
  } else if v >= 48 && v <= 57 {
    v + 4 // 0-9 -> 52-61
  } else if v == 43 {
    62 // +
  } else if v == 47 {
    63 // /
  } else {
    -1
  }
}

// ---------------------------------------------------------------------------
// String helpers (avoid StringView friction for callers)
// ---------------------------------------------------------------------------

///|
/// Find the first occurrence of `pattern` in `text` at or after `from`.
/// Returns the byte offset or `None`.
fn find_str(text : String, pattern : String, from : Int) -> Int? {
  let tl = text.length()
  let pl = pattern.length()
  if pl == 0 || from + pl > tl {
    return None
  }
  for i in from..=(tl - pl) {
    let mut found = true
    for j in 0..<pl {
      if text.get_char(i + j) != pattern.get_char(j) {
        found = false
        break
      }
    }
    if found {
      return Some(i)
    }
  }
  None
}

///|
/// Extract `text[start:end]` as a new String.
fn text_range(text : String, start : Int, end : Int) -> String {
  let buf = StringBuilder::new()
  for i in start..<end {
    match text.get_char(i) {
      Some(c) => buf.write_char(c)
      None => ()
    }
  }
  buf.to_string()
}
