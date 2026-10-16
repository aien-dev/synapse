//! Synapse wire protocol (ADR 0003 section 8 crate `synapse-wire`, step G1).
//!
//! * [`frame`]: length-prefixed binary frames (hello, have, want, chunk, submit, accepted,
//!   refused) with one canonical encoding each, and an untrusted-input decoder that checks
//!   every declared length against a cap before it allocates or reads, and refuses anything
//!   else with a typed [`frame::WireRefusal`].
//! * [`transport`]: framed connections over any reliable byte stream (Unix socket, TCP).
//! * [`session`]: have-want chunk negotiation (only blobs the server lacks cross the wire)
//!   and change submission authorised by a capability chain (step F1), admitted by the
//!   group-commit store and acknowledged once durable.
//! * [`fuzz`]: the in-repository coverage-guided fuzzer for the frame decoder, with
//!   [`probe`] supplying the edge feedback.
//! * [`testkit`]: deterministic fixtures for tests, the fuzz seed corpus, and benchmarks.

pub mod frame;
pub mod fuzz;
pub mod probe;
pub mod session;
pub mod testkit;
pub mod transport;

pub use frame::{
    decode_frame, encode_frame, Frame, FrameBody, FrameKind, WireLimits, WireRefusal,
    DEFAULT_MAX_FRAME_BODY, FRAME_HEADER_LEN,
};
pub use session::{ServerConfig, SubmitReport, WireClient, WireServer};
pub use transport::FrameConn;
