///|
/// A bounded reader over a `Bytes` slice. Every read advances the cursor
/// and checks for end-of-buffer, which keeps the worst-case runtime of the
/// decoder linear in the buffer size.
///
/// Bounds are part of the type-level contract: a `Reader` is constructed
/// with a maximum element count and a maximum nesting depth, and any
/// decoded value that exceeds them causes a `ReaderError::LimitExceeded`.
pub struct Reader {
  buf : Bytes
  mut pos : Int
  max_len : Int
  max_depth : Int
  mut depth : Int
  mut element_count : Int
}

///|
pub enum ReaderError {
  /// The reader reached the end of the buffer while more bytes were expected.
  Truncated
  /// A length or tag exceeded `max_len` or `max_depth`.
  LimitExceeded(kind : String)
  /// A length prefix was inconsistent with the buffer (e.g. indefinite
  /// length, which DER forbids).
  MalformedLength
  /// The encoded data violated a structural rule (e.g. a boolean not
  /// exactly one byte, or an integer that overflows).
  MalformedValue
} derive(Show, Eq)

///|
/// Construct a reader with explicit safety bounds. Defaults are chosen to
/// be safely above any plausible RFC 5280 certificate while still keeping
/// adversarial inputs bounded.
pub fn Reader::new(buf : Bytes, max_len? : Int = 1 << 20, max_depth? : Int = 64) -> Reader {
  {
    buf,
    pos: 0,
    max_len,
    max_depth,
    depth: 0,
    element_count: 0,
  }
}

///|
/// Bytes remaining in the buffer.
pub fn Reader::remaining(self : Reader) -> Int {
  self.buf.length() - self.pos
}

///|
/// Whether the reader is at end of buffer.
pub fn Reader::eof(self : Reader) -> Bool {
  self.pos >= self.buf.length()
}

///|
/// Read one byte and advance. Returns `Truncated` if the buffer is exhausted.
pub fn Reader::read_byte(self : Reader) -> Result[UInt8, ReaderError] {
  if self.pos >= self.buf.length() {
    Err(Truncated)
  } else {
    let b = self.buf[self.pos]
    self.pos = self.pos + 1
    Ok(b)
  }
}

///|
/// Read `n` bytes and advance. Returns `Truncated` if fewer than `n` remain.
pub fn Reader::read_bytes(self : Reader, n : Int) -> Result[Bytes, ReaderError] {
  if n < 0 || n > self.max_len {
    Err(LimitExceeded("read_bytes: n=" + n.to_string()))
  } else if self.pos + n > self.buf.length() {
    Err(Truncated)
  } else {
    let out = Bytes::make(n, b'\x00')
    for i in 0..<n {
      out[i] = self.buf[self.pos + i]
    }
    self.pos = self.pos + n
    Ok(out)
  }
}

///|
/// Peek one byte without advancing.
pub fn Reader::peek_byte(self : Reader) -> Result[UInt8, ReaderError] {
  if self.pos >= self.buf.length() {
    Err(Truncated)
  } else {
    Ok(self.buf[self.pos])
  }
}

///|
/// Enter a nested element. Increments the depth counter and rejects if the
/// limit is exceeded.
pub fn Reader::enter(self : Reader) -> Result[Unit, ReaderError] {
  self.depth = self.depth + 1
  self.element_count = self.element_count + 1
  if self.depth > self.max_depth {
    Err(LimitExceeded("depth=" + self.depth.to_string()))
  } else if self.element_count > self.max_len {
    Err(LimitExceeded("element_count"))
  } else {
    Ok(())
  }
}

///|
/// Leave a nested element.
pub fn Reader::leave(self : Reader) -> Unit {
  if self.depth > 0 {
    self.depth = self.depth - 1
  }
  ignore(self.depth)
}