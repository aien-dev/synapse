//! Have-want chunk negotiation and change submission over wire frames.
//!
//! One change crosses the transport in two round trips:
//!
//! ```text
//! client                                   server
//!   Hello ------------------------------->     (once per connection, both ways)
//!   <------------------------------- Hello
//!   Have {repo, digests the change needs} ->
//!   <---------- Want {the offered digests the server lacks}
//!   Chunk * |Want|, Submit {chained request} ->   (one write)
//!   <--------------- Accepted {wal_seq} | Refused {code}
//! ```
//!
//! The server lacks a digest when no committed changeset references it and no chunk of the
//! current negotiation carried it, so a chunk the server already holds is never resent
//! (FindMissingBlobs style, ADR 0003 section 5.9). Until G2 a chunk is a whole blob.
//!
//! Server rules (each break is a typed refusal, and the negotiation is reset):
//! * `Hello` first, once (`WireProtocolViolation`).
//! * One `Have` per negotiation, for the server's repository (`AuthCrossRepoDenied`).
//! * A `Chunk` must be wanted and not yet received (`WireProtocolViolation`), match its
//!   digest (`BlobDigestMismatch`), and fit the pending-bytes cap (`QuotaPayloadTooLarge`).
//! * A `Submit` must come after every wanted chunk (`WireProtocolViolation`); its payload
//!   must be one canonical binary envelope (`WireFrameMalformed`); its capability chain is
//!   checked by `PolicyEnforcer::authorize_chain` (step F1) with `Capability::Propose`; the
//!   envelope must be for this repository and authored by the leaf audience, and the request
//!   scope must list exactly the envelope's paths; then the store admits it with group commit
//!   and the reply is sent only after the change is durable.
//! * A frame the server never accepts from a client (`Want`, `Accepted`, `Refused`) is a
//!   `WireProtocolViolation`. A malformed frame is refused with `WireFrameMalformed` and the
//!   connection is closed, since framing can no longer be trusted.

use crate::frame::{Accepted, Chunk, Frame, FrameBody, Have, Hello, Refused, Want, WireLimits};
use crate::transport::FrameConn;
use ed25519_dalek::SigningKey;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use synapse_auth::{
    BoundaryKind, Capability, CapabilityChain, ChainedRequest, PolicyEnforcer, RequestScope,
};
use synapse_core::{
    BlobDigest, ChangesetEnvelope, MutationOp, RefusalCode, RepoId, SynapseError, SynapseResult,
    WalSeq,
};
use synapse_store::codec::{decode_envelope, encode_envelope};
use synapse_store::{IngestOutcome, SharedStore};

/// Default cap on chunk bytes buffered for one negotiation (64 MiB).
pub const DEFAULT_MAX_PENDING_CHUNK_BYTES: u64 = 64 << 20;
/// Refusals close a connection before one peer can consume the shared audit capacity.
const MAX_SESSION_REFUSALS: u32 = 64;

fn violation(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::WireProtocolViolation, msg)
}

/// Build the chained `Propose` request that carries `envelope` over the wire: payload is the
/// binary envelope, scope paths are exactly the envelope's mutation paths.
pub fn submit_request(
    agent_key: &SigningKey,
    chain: CapabilityChain,
    envelope: &ChangesetEnvelope,
    request_nonce: [u8; 32],
    timestamp_ms: u64,
) -> SynapseResult<ChainedRequest> {
    Ok(ChainedRequest::sign_new(
        agent_key,
        chain,
        envelope.repo_id.clone(),
        Capability::Propose,
        RequestScope {
            paths: envelope.mutations.iter().map(|m| m.path.clone()).collect(),
            reference: None,
            join_change: None,
        },
        request_nonce,
        timestamp_ms,
        encode_envelope(envelope)?,
    ))
}

/// Digests of the blobs an envelope's upserts reference.
fn upsert_digests(envelope: &ChangesetEnvelope) -> impl Iterator<Item = BlobDigest> + '_ {
    envelope.mutations.iter().filter_map(|m| match &m.op {
        MutationOp::Upsert { blob_digest, .. } => Some(*blob_digest),
        MutationOp::Delete => None,
    })
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub repo_id: RepoId,
    /// Limits for frames the server reads (announced in its `Hello`).
    pub read_limits: WireLimits,
    pub max_pending_chunk_bytes: u64,
}

/// A wire server for one repository over a shared group-commit store.
#[derive(Clone)]
pub struct WireServer {
    cfg: ServerConfig,
    store: Arc<SharedStore>,
    auth: Arc<Mutex<PolicyEnforcer>>,
    known: Arc<Mutex<BTreeSet<BlobDigest>>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl WireServer {
    /// Serve `store` with `auth` (holding the repository authority and granted links).
    /// `clock` returns the server time in milliseconds.
    pub fn new(
        cfg: ServerConfig,
        store: Arc<SharedStore>,
        auth: PolicyEnforcer,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> SynapseResult<Self> {
        let mut known = BTreeSet::new();
        for cs in store.read().list_changesets(None, None, None)? {
            known.extend(upsert_digests(&cs.envelope));
        }
        Ok(Self {
            cfg,
            store,
            auth: Arc::new(Mutex::new(auth)),
            known: Arc::new(Mutex::new(known)),
            clock,
        })
    }

    pub fn config(&self) -> &ServerConfig {
        &self.cfg
    }

    pub fn store(&self) -> &Arc<SharedStore> {
        &self.store
    }

    /// Whether a committed changeset references `digest`.
    pub fn knows(&self, digest: &BlobDigest) -> bool {
        lock(&self.known).contains(digest)
    }

    /// A new per-connection session.
    pub fn session(&self) -> Session<'_> {
        Session {
            server: self,
            hello_done: false,
            refusals: 0,
            neg: Negotiation::default(),
        }
    }

    /// Serve one connection until the peer closes it or sends a malformed frame.
    pub fn serve<S: Read + Write>(&self, stream: S) -> SynapseResult<FrameConnStats> {
        let mut conn = FrameConn::new(stream, self.cfg.read_limits);
        let mut session = self.session();
        loop {
            match conn.recv() {
                Ok(None) => break,
                Ok(Some(frame)) => {
                    if let (false, FrameBody::Hello(h)) = (session.hello_done, &frame.body) {
                        conn.peer_limits = WireLimits {
                            max_frame_body: h.max_frame_body,
                        };
                    }
                    let reply = session.handle(frame);
                    for f in &reply.frames {
                        // A reply the peer's own cap refuses cannot be sent: close.
                        if conn.queue(f).is_err() {
                            conn.flush()?;
                            return Ok(conn_stats(&conn));
                        }
                    }
                    conn.flush()?;
                    if reply.close {
                        break;
                    }
                }
                Err(e) if e.code == RefusalCode::WireFrameMalformed => {
                    conn.send(&Frame {
                        request_id: 0,
                        body: FrameBody::Refused(Refused {
                            code: e.code,
                            message: e.message,
                        }),
                    })?;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(conn_stats(&conn))
    }
}

fn conn_stats<S: Read + Write>(conn: &FrameConn<S>) -> FrameConnStats {
    FrameConnStats {
        bytes_sent: conn.bytes_sent,
        bytes_received: conn.bytes_received,
        frames_sent: conn.frames_sent,
        frames_received: conn.frames_received,
    }
}

/// Byte and frame counts of one served connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameConnStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
}

#[derive(Debug, Default)]
struct Negotiation {
    active: bool,
    wanted: BTreeSet<BlobDigest>,
    received: BTreeMap<BlobDigest, Vec<u8>>,
    pending_bytes: u64,
}

/// Frames to send back, and whether to close the connection after them.
#[derive(Debug, Default)]
pub struct Reply {
    pub frames: Vec<Frame>,
    pub close: bool,
}

/// Server state of one connection.
pub struct Session<'a> {
    server: &'a WireServer,
    hello_done: bool,
    refusals: u32,
    neg: Negotiation,
}

impl Session<'_> {
    fn refuse(&mut self, request_id: u32, e: SynapseError) -> Reply {
        self.neg = Negotiation::default();
        self.refusals += 1;
        let close = self.refusals >= MAX_SESSION_REFUSALS
            || e.code == RefusalCode::BackpressureOverCapacity;
        Reply {
            frames: vec![Frame {
                request_id,
                body: FrameBody::Refused(Refused {
                    code: e.code,
                    message: e.message,
                }),
            }],
            close,
        }
    }

    /// Handle one well-formed frame from the client.
    pub fn handle(&mut self, frame: Frame) -> Reply {
        let id = frame.request_id;
        let reply_body = match (self.hello_done, frame.body) {
            (false, FrameBody::Hello(_)) => {
                self.hello_done = true;
                Ok(Some(FrameBody::Hello(Hello {
                    max_frame_body: self.server.cfg.read_limits.max_frame_body,
                    max_pending_chunk_bytes: self.server.cfg.max_pending_chunk_bytes,
                })))
            }
            (false, other) => {
                let mut r = self.refuse(
                    id,
                    violation(format!(
                        "{} before Hello: Hello must be the first frame",
                        other.kind().name()
                    )),
                );
                r.close = true;
                return r;
            }
            (true, FrameBody::Hello(_)) => Err(violation("second Hello on one connection")),
            (true, FrameBody::Have(h)) => self.have(h).map(|w| Some(FrameBody::Want(w))),
            (true, FrameBody::Chunk(c)) => self.chunk(c).map(|()| None),
            (true, FrameBody::Submit(req)) => self.submit(*req).map(|a| {
                self.neg = Negotiation::default();
                Some(FrameBody::Accepted(a))
            }),
            (
                true,
                other @ (FrameBody::Want(_) | FrameBody::Accepted(_) | FrameBody::Refused(_)),
            ) => Err(violation(format!(
                "a server never accepts {} from a client",
                other.kind().name()
            ))),
        };
        match reply_body {
            Ok(Some(body)) => Reply {
                frames: vec![Frame {
                    request_id: id,
                    body,
                }],
                close: false,
            },
            Ok(None) => Reply::default(),
            Err(e) => self.refuse(id, e),
        }
    }

    fn have(&mut self, h: Have) -> SynapseResult<Want> {
        if self.neg.active {
            return Err(violation("Have while a negotiation is open (Submit first)"));
        }
        if h.repo_id != self.server.cfg.repo_id {
            return Err(SynapseError::new(
                RefusalCode::AuthCrossRepoDenied,
                format!(
                    "Have for {} on a server for {}",
                    h.repo_id, self.server.cfg.repo_id
                ),
            ));
        }
        let known = lock(&self.server.known);
        let wanted: Vec<BlobDigest> = h
            .digests
            .iter()
            .filter(|d| !known.contains(d))
            .copied()
            .collect();
        drop(known);
        self.neg = Negotiation {
            active: true,
            wanted: wanted.iter().copied().collect(),
            received: BTreeMap::new(),
            pending_bytes: 0,
        };
        Ok(Want { digests: wanted })
    }

    fn chunk(&mut self, c: Chunk) -> SynapseResult<()> {
        if !self.neg.wanted.contains(&c.digest) {
            return Err(violation(format!(
                "unsolicited chunk {} (not in the last Want)",
                c.digest
            )));
        }
        if self.neg.received.contains_key(&c.digest) {
            return Err(violation(format!("chunk {} sent twice", c.digest)));
        }
        let computed = BlobDigest::compute(&c.bytes);
        if computed != c.digest {
            return Err(SynapseError::new(
                RefusalCode::BlobDigestMismatch,
                format!(
                    "chunk declared {} but its bytes hash to {computed}",
                    c.digest
                ),
            ));
        }
        let pending = self.neg.pending_bytes + c.bytes.len() as u64;
        if pending > self.server.cfg.max_pending_chunk_bytes {
            return Err(SynapseError::new(
                RefusalCode::QuotaPayloadTooLarge,
                format!(
                    "pending chunk bytes {pending} exceed max_pending_chunk_bytes {}",
                    self.server.cfg.max_pending_chunk_bytes
                ),
            ));
        }
        self.neg.pending_bytes = pending;
        self.neg.received.insert(c.digest, c.bytes);
        Ok(())
    }

    fn submit(&mut self, req: ChainedRequest) -> SynapseResult<Accepted> {
        // Before envelope decoding or signature verification, refuse if the shared audit
        // cannot retain the next decision. The enforcer rechecks under its mutex at admission.
        lock(&self.server.auth).audit_log().ensure_capacity()?;
        let srv = self.server;
        if let Some(missing) = self
            .neg
            .wanted
            .iter()
            .find(|d| !self.neg.received.contains_key(d))
        {
            return Err(violation(format!(
                "Submit before wanted chunk {missing} arrived"
            )));
        }
        let envelope = decode_envelope(&req.payload, u64::from(srv.cfg.read_limits.max_frame_body))
            .map_err(|r| {
                r.into_error(RefusalCode::WireFrameMalformed, "Submit payload envelope")
            })?;
        let now_ms = (srv.clock)();
        let request_seq = WalSeq(srv.store.read().committed_seq().0 + 1);
        lock(&srv.auth).authorize_chain(
            BoundaryKind::Api,
            "wire_submit",
            &srv.cfg.repo_id,
            Capability::Propose,
            &req,
            request_seq,
            now_ms,
        )?;
        if envelope.repo_id != srv.cfg.repo_id {
            return Err(SynapseError::new(
                RefusalCode::AuthCrossRepoDenied,
                "envelope repo_id does not match the server's repository",
            ));
        }
        if envelope.author_did != req.agent_did() {
            return Err(SynapseError::new(
                RefusalCode::AuthSignatureInvalid,
                "envelope author_did is not the chain's leaf audience",
            ));
        }
        if req.scope.paths.len() != envelope.mutations.len()
            || req
                .scope
                .paths
                .iter()
                .zip(&envelope.mutations)
                .any(|(p, m)| p != &m.path)
        {
            return Err(SynapseError::new(
                RefusalCode::AuthPathOutOfScope,
                "request scope must list exactly the envelope's mutation paths",
            ));
        }
        let blobs: Vec<(BlobDigest, Vec<u8>)> =
            std::mem::take(&mut self.neg.received).into_iter().collect();
        let digests: Vec<BlobDigest> = upsert_digests(&envelope).collect();
        let outcome = srv.store.submit(envelope, &blobs)?;
        lock(&srv.known).extend(digests);
        Ok(match outcome {
            IngestOutcome::Committed {
                wal_seq,
                changeset_id,
                ..
            } => Accepted {
                wal_seq,
                changeset_id,
                duplicate: false,
            },
            IngestOutcome::IdempotentDuplicate {
                wal_seq,
                changeset_id,
            } => Accepted {
                wal_seq,
                changeset_id,
                duplicate: true,
            },
        })
    }
}

/// What one submission cost on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitReport {
    pub accepted: Accepted,
    /// Digests offered in the `Have` (0 when the change carries no blobs).
    pub offered: usize,
    /// Digests the server wanted, so chunks sent.
    pub wanted: usize,
    pub chunk_bytes_sent: u64,
    /// Frame bytes written and read for this submission.
    pub wire_bytes_sent: u64,
    pub wire_bytes_received: u64,
}

/// Client side of a wire connection.
pub struct WireClient<S: Read + Write> {
    conn: FrameConn<S>,
    next_id: u32,
    pub server_hello: Hello,
}

impl<S: Read + Write> WireClient<S> {
    /// Exchange `Hello` frames. `read_limits` caps frames this client reads.
    pub fn connect(stream: S, read_limits: WireLimits) -> SynapseResult<Self> {
        let mut conn = FrameConn::new(stream, read_limits);
        conn.send(&Frame {
            request_id: 1,
            body: FrameBody::Hello(Hello {
                max_frame_body: read_limits.max_frame_body,
                max_pending_chunk_bytes: 0,
            }),
        })?;
        let server_hello = match Self::expect(&mut conn)? {
            FrameBody::Hello(h) => h,
            other => {
                return Err(violation(format!(
                    "server answered Hello with {}",
                    other.kind().name()
                )))
            }
        };
        conn.peer_limits = WireLimits {
            max_frame_body: server_hello.max_frame_body,
        };
        Ok(Self {
            conn,
            next_id: 2,
            server_hello,
        })
    }

    fn expect(conn: &mut FrameConn<S>) -> SynapseResult<FrameBody> {
        match conn.recv()? {
            None => Err(SynapseError::new(
                RefusalCode::IoFailure,
                "server closed the connection",
            )),
            Some(Frame {
                body: FrameBody::Refused(r),
                ..
            }) => Err(SynapseError::new(r.code, r.message)),
            Some(f) => Ok(f.body),
        }
    }

    fn id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Submit one change: negotiate which of `blobs` the server lacks, send only those, then
    /// the request. Returns after the server's durable acknowledgement.
    pub fn submit(
        &mut self,
        req: &ChainedRequest,
        blobs: &[(BlobDigest, Vec<u8>)],
    ) -> SynapseResult<SubmitReport> {
        let (sent0, recv0) = (self.conn.bytes_sent, self.conn.bytes_received);
        let mut by_digest: BTreeMap<BlobDigest, &[u8]> = BTreeMap::new();
        for (d, b) in blobs {
            by_digest.insert(*d, b);
        }
        let offered = by_digest.len();
        let mut wanted = 0;
        let mut chunk_bytes_sent = 0u64;
        if offered > 0 {
            let id = self.id();
            self.conn.send(&Frame {
                request_id: id,
                body: FrameBody::Have(Have {
                    repo_id: req.target_repo_id.clone(),
                    digests: by_digest.keys().copied().collect(),
                }),
            })?;
            let want = match Self::expect(&mut self.conn)? {
                FrameBody::Want(w) => w,
                other => {
                    return Err(violation(format!(
                        "server answered Have with {}",
                        other.kind().name()
                    )))
                }
            };
            wanted = want.digests.len();
            for d in &want.digests {
                let Some(bytes) = by_digest.get(d) else {
                    return Err(violation(format!(
                        "server wanted {d}, which was not offered"
                    )));
                };
                let id = self.id();
                self.conn.queue(&Frame {
                    request_id: id,
                    body: FrameBody::Chunk(Chunk {
                        digest: *d,
                        bytes: bytes.to_vec(),
                    }),
                })?;
                chunk_bytes_sent += bytes.len() as u64;
            }
        }
        let id = self.id();
        self.conn.queue(&Frame {
            request_id: id,
            body: FrameBody::Submit(Box::new(req.clone())),
        })?;
        self.conn.flush()?;
        let accepted = match Self::expect(&mut self.conn)? {
            FrameBody::Accepted(a) => a,
            other => {
                return Err(violation(format!(
                    "server answered Submit with {}",
                    other.kind().name()
                )))
            }
        };
        Ok(SubmitReport {
            accepted,
            offered,
            wanted,
            chunk_bytes_sent,
            wire_bytes_sent: self.conn.bytes_sent - sent0,
            wire_bytes_received: self.conn.bytes_received - recv0,
        })
    }

    /// Send raw frames and read one reply (tests of server refusals).
    pub fn exchange(&mut self, frames: &[Frame]) -> SynapseResult<Option<Frame>> {
        for f in frames {
            self.conn.queue(f)?;
        }
        self.conn.flush()?;
        self.conn.recv()
    }

    /// Bytes written and read so far, including the hello exchange.
    pub fn bytes(&self) -> (u64, u64) {
        (self.conn.bytes_sent, self.conn.bytes_received)
    }

    pub fn conn_mut(&mut self) -> &mut FrameConn<S> {
        &mut self.conn
    }
}
