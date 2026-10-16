//! Synapse wire protocol (ADR 0003 section 8 crate `synapse-wire`, step G1).
//!
//! * [`frame`]: length-prefixed binary frames (hello, have, want, chunk, submit, accepted,
//!   refused) with one canonical encoding each, and an untrusted-input decoder that checks
//!   every declared length against a cap before it allocates or reads, and refuses anything
//!   else with a typed [`frame::WireRefusal`].
//! * [`transport`]: framed connections over any reliable byte stream (Unix socket, TCP).
//! * [`ring`]: a shared-memory ring for local agents (step G3, experiment X5): two
//!   single-producer, single-consumer rings in a sealed shared region, safe against a hostile
//!   peer, joined into a byte stream that carries the same frames.
//! * [`session`]: have-want chunk negotiation (only blobs the server lacks cross the wire)
//!   and change submission authorised by a capability chain (step F1), admitted by the
//!   group-commit store and acknowledged once durable.
//! * [`fuzz`]: the in-repository coverage-guided fuzzer for the frame decoder, with
//!   [`probe`] supplying the edge feedback.
//! * [`testkit`]: deterministic fixtures for tests, the fuzz seed corpus, and benchmarks.

pub mod frame;
pub mod fuzz;
pub mod probe;
pub mod ring;
pub mod session;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod shm;
pub mod testkit;
pub mod transport;

pub use frame::{
    decode_frame, encode_frame, Frame, FrameBody, FrameKind, WireLimits, WireRefusal,
    DEFAULT_MAX_FRAME_BODY, FRAME_HEADER_LEN,
};
pub use ring::{RingConfig, RingReceiver, RingRefusal, RingRegion, RingSender, RingStream, Side};
pub use session::{ServerConfig, SubmitReport, WireClient, WireServer};
pub use transport::FrameConn;
