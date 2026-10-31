//! Stream transports for wire frames.
//!
//! Any reliable, ordered byte stream works (`UnixStream`, `TcpStream`, the shared-memory
//! [`crate::ring::RingStream`], an in-memory pipe).
//! The reader takes the 16-byte header first, checks the declared body length against its
//! cap, and only then allocates and reads exactly that many bytes, so a hostile peer cannot
//! make it allocate more than `max_frame_body` or consume bytes of the next frame.
//! Outgoing frames are queued and written with one `write_all` per [`FrameConn::flush`].

use crate::frame::{
    decode_body, decode_header, encode_frame_within, Frame, WireLimits, WireRefusal,
    FRAME_HEADER_LEN,
};
use std::io::{BufReader, ErrorKind, Read, Write};
use synapse_core::{RefusalCode, SynapseError, SynapseResult};

/// An I/O error, except that a shared-memory ring refusal carried inside one keeps its own
/// code (`WireRingViolation`).
fn io(e: std::io::Error) -> SynapseError {
    if let Some(r) = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<crate::ring::RingRefusal>())
    {
        return r.clone().into_error();
    }
    SynapseError::new(RefusalCode::IoFailure, format!("wire transport: {e}"))
}

/// Read one frame. `Ok(None)` is a clean end of stream at a frame boundary; an end of stream
/// inside a frame is `WireFrameMalformed` (truncated).
pub fn read_frame<R: Read>(r: &mut R, limits: &WireLimits) -> SynapseResult<Option<Frame>> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    let mut got = 0;
    while got < FRAME_HEADER_LEN {
        match r.read(&mut header[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => {
                return Err(WireRefusal::Truncated {
                    at: got,
                    need: FRAME_HEADER_LEN - got,
                }
                .into_error())
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(io(e)),
        }
    }
    let h = decode_header(&header, limits).map_err(WireRefusal::into_error)?;
    // Allocation is bounded by the cap checked in `decode_header`.
    let mut body = vec![0u8; h.body_len as usize];
    let mut got = 0;
    while got < body.len() {
        match r.read(&mut body[got..]) {
            Ok(0) => {
                return Err(WireRefusal::Truncated {
                    at: FRAME_HEADER_LEN + got,
                    need: body.len() - got,
                }
                .into_error())
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(io(e)),
        }
    }
    decode_body(&h, &body, limits)
        .map(Some)
        .map_err(WireRefusal::into_error)
}

/// A framed connection over one bidirectional stream, counting bytes in each direction.
pub struct FrameConn<S: Read + Write> {
    stream: BufReader<S>,
    out: Vec<u8>,
    /// Limits applied to frames this side reads.
    pub read_limits: WireLimits,
    /// Limits the peer announced for frames it reads (applied when encoding).
    pub peer_limits: WireLimits,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
}

impl<S: Read + Write> FrameConn<S> {
    pub fn new(stream: S, read_limits: WireLimits) -> Self {
        Self {
            stream: BufReader::with_capacity(64 * 1024, stream),
            out: Vec::with_capacity(64 * 1024),
            read_limits,
            peer_limits: read_limits,
            bytes_sent: 0,
            bytes_received: 0,
            frames_sent: 0,
            frames_received: 0,
        }
    }

    /// Queue one frame for the next [`Self::flush`]. Refused (and nothing queued) if it
    /// exceeds the peer's announced `max_frame_body`.
    pub fn queue(&mut self, frame: &Frame) -> SynapseResult<()> {
        let bytes = encode_frame_within(frame, &self.peer_limits)?;
        self.out.extend_from_slice(&bytes);
        self.frames_sent += 1;
        Ok(())
    }

    /// Write every queued frame.
    pub fn flush(&mut self) -> SynapseResult<()> {
        if self.out.is_empty() {
            return Ok(());
        }
        let s = self.stream.get_mut();
        s.write_all(&self.out).map_err(io)?;
        s.flush().map_err(io)?;
        self.bytes_sent += self.out.len() as u64;
        self.out.clear();
        Ok(())
    }

    /// Queue and flush one frame.
    pub fn send(&mut self, frame: &Frame) -> SynapseResult<()> {
        self.queue(frame)?;
        self.flush()
    }

    /// Read the next frame (`None` at a clean end of stream).
    pub fn recv(&mut self) -> SynapseResult<Option<Frame>> {
        let mut counted = CountingRead {
            inner: &mut self.stream,
            n: 0,
        };
        let frame = read_frame(&mut counted, &self.read_limits);
        self.bytes_received += counted.n;
        if let Ok(Some(_)) = &frame {
            self.frames_received += 1;
        }
        frame
    }

    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }
}

struct CountingRead<'a, R: Read> {
    inner: &'a mut R,
    n: u64,
}

impl<R: Read> Read for CountingRead<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.n += n as u64;
        Ok(n)
    }
}
