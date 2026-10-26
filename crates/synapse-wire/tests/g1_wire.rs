//! G1 acceptance: every frame kind round-trips to identical bytes; the decoder refuses
//! malformed frames with typed refusals and never reads past a frame; have-want
//! negotiation sends only the chunks the server lacks; a change submitted across a Unix
//! socket is authorised by its capability chain and acknowledged only once durable; and
//! the server refuses protocol breaks with typed refusal codes.

use std::collections::BTreeSet;
use std::os::unix::net::UnixStream;
use std::thread::JoinHandle;
use synapse_auth::{Capability, ChainedRequest, RequestScope};
use synapse_core::{RefusalCode, RepoId, SynapseResult};
use synapse_wire::frame::{
    decode_frame, decode_header, encode_frame, Chunk, Frame, FrameBody, FrameKind, Have, Hello,
    Want, WireLimits, WireRefusal, FRAME_HEADER_LEN,
};
use synapse_wire::session::{submit_request, FrameConnStats};
use synapse_wire::testkit::{
    envelope, open_store, repo, sample_frames, server, temp_dir, ChainFixture,
};
use synapse_wire::transport::read_frame;
use synapse_wire::WireClient;

// ---------------------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------------------

#[test]
fn every_frame_kind_round_trips_to_identical_bytes() {
    let frames = sample_frames();
    let kinds: BTreeSet<u8> = frames.iter().map(|f| f.body.kind().byte()).collect();
    assert_eq!(kinds.len(), FrameKind::ALL.len(), "a sample of every kind");
    let limits = WireLimits::default();
    let mut stream = Vec::new();
    for f in &frames {
        let bytes = encode_frame(f).unwrap();
        let (back, used) = decode_frame(&bytes, &limits).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(
            &back,
            f,
            "{} decodes to the same value",
            f.body.kind().name()
        );
        assert_eq!(
            encode_frame(&back).unwrap(),
            bytes,
            "{} re-encodes to identical bytes",
            f.body.kind().name()
        );
        stream.extend_from_slice(&bytes);
    }
    // Back to back in one stream buffer: each decode takes exactly its own frame.
    let mut at = 0;
    for f in &frames {
        let (back, used) = decode_frame(&stream[at..], &limits).unwrap();
        assert_eq!(&back, f);
        at += used;
    }
    assert_eq!(at, stream.len());
    // And through the stream reader.
    let mut r = std::io::Cursor::new(&stream);
    for f in &frames {
        assert_eq!(read_frame(&mut r, &limits).unwrap().as_ref(), Some(f));
    }
    assert!(read_frame(&mut r, &limits).unwrap().is_none());
}

fn hello_bytes() -> Vec<u8> {
    encode_frame(&sample_frames()[0]).unwrap()
}

#[test]
fn malformed_header_is_refused_with_typed_refusal() {
    let limits = WireLimits {
        max_frame_body: 1024,
    };
    let good = hello_bytes();
    let refuse = |b: &[u8]| decode_frame(b, &limits).unwrap_err();
    let with = |i: usize, v: u8| {
        let mut b = good.clone();
        b[i] = v;
        b
    };
    assert!(matches!(
        refuse(&with(0, b'X')),
        WireRefusal::BadMagic { .. }
    ));
    assert!(matches!(
        refuse(&with(4, 2)),
        WireRefusal::VersionUnsupported { found: 2 }
    ));
    assert!(matches!(
        refuse(&with(5, 0)),
        WireRefusal::UnknownKind { found: 0 }
    ));
    assert!(matches!(
        refuse(&with(5, 8)),
        WireRefusal::UnknownKind { found: 8 }
    ));
    assert!(matches!(
        refuse(&with(6, 1)),
        WireRefusal::FlagsNonZero { found: 1 }
    ));
    assert!(matches!(
        refuse(&with(7, 1)),
        WireRefusal::ReservedNonZero { found: 1 }
    ));
    assert!(matches!(
        refuse(&good[..FRAME_HEADER_LEN - 1]),
        WireRefusal::Truncated { .. }
    ));
    assert!(matches!(
        refuse(&good[..good.len() - 1]),
        WireRefusal::Truncated { .. }
    ));
    // A declared length over the cap is refused from the header alone: no body needed.
    let mut over = good[..FRAME_HEADER_LEN].to_vec();
    over[12..16].copy_from_slice(&1025u32.to_le_bytes());
    assert!(matches!(
        refuse(&over),
        WireRefusal::LengthOverCap {
            declared: 1025,
            cap: 1024,
            ..
        }
    ));
    // A trailing byte inside the declared body is refused.
    let mut trailing = good.clone();
    trailing.push(0);
    let n = (trailing.len() - FRAME_HEADER_LEN) as u32;
    trailing[12..16].copy_from_slice(&n.to_le_bytes());
    assert!(matches!(
        refuse(&trailing),
        WireRefusal::TrailingBytes { .. }
    ));
    // Every refusal is the typed service refusal WireFrameMalformed.
    assert_eq!(
        refuse(&with(0, b'X')).into_error().code,
        RefusalCode::WireFrameMalformed
    );
}

#[test]
fn malformed_body_is_refused_with_typed_refusal() {
    let limits = WireLimits::default();
    let enc = |body: FrameBody| {
        encode_frame(&Frame {
            request_id: 9,
            body,
        })
        .unwrap()
    };
    let d = |n: u8| synapse_core::BlobDigest([n; 32]);
    // Unsorted and repeated digests have a second encoding: refused as not canonical.
    let mut unsorted = enc(FrameBody::Want(Want {
        digests: vec![d(1), d(2)],
    }));
    let body = FRAME_HEADER_LEN + 4;
    unsorted[body..body + 32].copy_from_slice(&[2; 32]);
    unsorted[body + 32..body + 64].copy_from_slice(&[1; 32]);
    assert!(matches!(
        decode_frame(&unsorted, &limits).unwrap_err(),
        WireRefusal::NotCanonical { .. }
    ));
    let mut repeated = unsorted.clone();
    repeated[body + 32..body + 64].copy_from_slice(&[2; 32]);
    assert!(matches!(
        decode_frame(&repeated, &limits).unwrap_err(),
        WireRefusal::NotCanonical { .. }
    ));
    // A count that needs more bytes than the body holds is refused before allocating.
    let mut count = enc(FrameBody::Want(Want { digests: vec![] }));
    count[FRAME_HEADER_LEN..FRAME_HEADER_LEN + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        decode_frame(&count, &limits).unwrap_err(),
        WireRefusal::LengthOverCap { .. } | WireRefusal::Truncated { .. }
    ));
    // An invalid repository id in a Have is refused.
    let have = enc(FrameBody::Have(Have {
        repo_id: repo(),
        digests: vec![],
    }));
    let mut bad_repo = have.clone();
    bad_repo[FRAME_HEADER_LEN + 4] = b' ';
    assert!(matches!(
        decode_frame(&bad_repo, &limits).unwrap_err(),
        WireRefusal::InvalidRepoId { .. }
    ));
    let mut bad_utf8 = have;
    bad_utf8[FRAME_HEADER_LEN + 4] = 0xFF;
    assert!(matches!(
        decode_frame(&bad_utf8, &limits).unwrap_err(),
        WireRefusal::InvalidUtf8 { .. }
    ));
}

#[test]
fn decoder_never_reads_past_a_frame() {
    let limits = WireLimits::default();
    for f in sample_frames() {
        let bytes = encode_frame(&f).unwrap();
        // Whatever follows a frame never changes how it decodes.
        for tail in [&[][..], &[0u8; 7][..], &[0xFF; 40][..], &hello_bytes()[..]] {
            let mut buf = bytes.clone();
            buf.extend_from_slice(tail);
            let (back, used) = decode_frame(&buf, &limits).unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(back, f);
        }
        // The header alone never decides more than the header: body checks need the body.
        let h = decode_header(&bytes, &limits).unwrap();
        assert_eq!(h.frame_len(), bytes.len());
    }
}

#[test]
fn stream_reader_refuses_length_over_cap_before_reading_the_body() {
    let limits = WireLimits { max_frame_body: 64 };
    let mut header = hello_bytes()[..FRAME_HEADER_LEN].to_vec();
    header[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    // Only the header is available: the reader must refuse without waiting for 4 GiB.
    let err = read_frame(&mut std::io::Cursor::new(header), &limits).unwrap_err();
    assert_eq!(err.code, RefusalCode::WireFrameMalformed);
    assert!(err.message.contains("LengthOverCap"), "{}", err.message);
    // End of stream inside a frame is a typed truncation.
    let good = hello_bytes();
    let err = read_frame(&mut std::io::Cursor::new(&good[..20]), &limits).unwrap_err();
    assert_eq!(err.code, RefusalCode::WireFrameMalformed);
    assert!(err.message.contains("Truncated"), "{}", err.message);
}

// ---------------------------------------------------------------------------------------
// Negotiation and submission over a Unix socket
// ---------------------------------------------------------------------------------------

type ServerThread = JoinHandle<SynapseResult<FrameConnStats>>;

fn connect(srv: &synapse_wire::WireServer) -> (WireClient<UnixStream>, ServerThread) {
    let (a, b) = UnixStream::pair().unwrap();
    // A missing reply fails the test instead of hanging it.
    a.set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    let s = srv.clone();
    let t = std::thread::spawn(move || s.serve(b));
    let c = WireClient::connect(a, WireLimits::default()).unwrap();
    (c, t)
}

fn blob(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| tag ^ (i as u8).wrapping_mul(31)).collect()
}

#[test]
fn have_want_sends_only_missing_chunks_and_acknowledges_durable_changes() {
    let dir = temp_dir("negotiation");
    let fx = ChainFixture::new(2, None);
    let shared = blob(0xA1, 3000);
    let (b, c) = (blob(0xB2, 3967), blob(0xC3, 3967));
    {
        let store = open_store(&dir);
        let srv = server(&fx, store.clone());
        let (mut client, t) = connect(&srv);

        // Change 1: both blobs are new, so both are wanted.
        let (env1, blobs1) = envelope(
            &fx.agent,
            "one",
            &[("lib/shared.rs", shared.clone()), ("lib/b.rs", b.clone())],
            &[],
            10,
        );
        let req1 = submit_request(&fx.agent, fx.chain.clone(), &env1, [1; 32], 10).unwrap();
        let r1 = client.submit(&req1, &blobs1).unwrap();
        assert_eq!((r1.offered, r1.wanted), (2, 2));
        assert_eq!(r1.chunk_bytes_sent, (shared.len() + b.len()) as u64);
        assert!(!r1.accepted.duplicate);

        // Change 2: the shared blob is already held, so only the new one crosses.
        let (env2, blobs2) = envelope(
            &fx.agent,
            "two",
            &[("lib/c.rs", c.clone()), ("lib/shared2.rs", shared.clone())],
            &["lib/b.rs"],
            11,
        );
        let req2 = submit_request(&fx.agent, fx.chain.clone(), &env2, [2; 32], 11).unwrap();
        let r2 = client.submit(&req2, &blobs2).unwrap();
        assert_eq!((r2.offered, r2.wanted), (2, 1));
        assert_eq!(r2.chunk_bytes_sent, c.len() as u64);
        assert!(r2.accepted.wal_seq > r1.accepted.wal_seq);

        // Change 3: every blob is held, so zero chunks cross.
        let (env3, blobs3) = envelope(&fx.agent, "three", &[("x/b.rs", b.clone())], &[], 12);
        let req3 = submit_request(&fx.agent, fx.chain.clone(), &env3, [3; 32], 12).unwrap();
        let r3 = client.submit(&req3, &blobs3).unwrap();
        assert_eq!((r3.offered, r3.wanted, r3.chunk_bytes_sent), (1, 0, 0));
        assert!(r3.wire_bytes_sent < 2 * 1024, "{}", r3.wire_bytes_sent);

        // Resubmitting a committed change (fresh nonce) is an idempotent duplicate.
        let req1b = submit_request(&fx.agent, fx.chain.clone(), &env1, [4; 32], 13).unwrap();
        let r1b = client.submit(&req1b, &blobs1).unwrap();
        assert!(r1b.accepted.duplicate);
        assert_eq!(r1b.accepted.changeset_id, r1.accepted.changeset_id);
        assert_eq!(r1b.wanted, 0);

        assert_eq!(store.read().committed_seq(), r3.accepted.wal_seq);
        drop(client);
        let stats = t.join().unwrap().unwrap();
        assert!(stats.frames_received >= 9);
    }
    // Durable: a fresh open of the directory sees all three changes.
    let reopened = open_store(&dir);
    let n = reopened
        .read()
        .list_changesets(None, None, None)
        .unwrap()
        .len();
    assert_eq!(n, 3);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------
// Server refusals
// ---------------------------------------------------------------------------------------

fn refused_code(reply: Option<Frame>) -> RefusalCode {
    match reply.map(|f| f.body) {
        Some(FrameBody::Refused(r)) => r.code,
        other => panic!("expected Refused, got {other:?}"),
    }
}

fn frame(id: u32, body: FrameBody) -> Frame {
    Frame {
        request_id: id,
        body,
    }
}

#[test]
fn repeated_unauthenticated_submissions_close_session_before_unbounded_audit() {
    let dir = temp_dir("audit-budget");
    let fx = ChainFixture::new(1, None);
    let srv = server(&fx, open_store(&dir));
    let (env, _) = envelope(&fx.agent, "audit-budget", &[], &["x"], 5);
    let mut req = submit_request(&fx.agent, fx.chain.clone(), &env, [9; 32], 5).unwrap();
    req.chain.links[0].signature[0] ^= 1; // Well-encoded, but not signed by the authority.
    let submitted = frame(2, FrameBody::Submit(Box::new(req)));
    let encoded = encode_frame(&submitted).unwrap();
    let (submitted, consumed) = decode_frame(&encoded, &WireLimits::default()).unwrap();
    assert_eq!(consumed, encoded.len());
    let mut session = srv.session();
    assert!(
        !session
            .handle(frame(
                0,
                FrameBody::Hello(Hello {
                    max_frame_body: 65_536,
                    max_pending_chunk_bytes: 0,
                })
            ))
            .close
    );
    let mut closed = false;
    for _ in 0..65 {
        session.handle(frame(
            1,
            FrameBody::Have(Have {
                repo_id: repo(),
                digests: vec![],
            }),
        ));
        let reply = session.handle(submitted.clone());
        assert_eq!(
            refused_code(reply.frames.first().cloned()),
            RefusalCode::AuthGrantSignatureInvalid
        );
        if reply.close {
            closed = true;
            break;
        }
    }
    assert!(
        closed,
        "a connection must stop spending audit capacity on untrusted submissions"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn full_shared_audit_refuses_before_submit_payload_decode_and_closes() {
    use synapse_auth::{AuditOutcome, BoundaryKind, MAX_AUDIT_ENTRIES};
    use synapse_wire::{ServerConfig, WireServer};
    let dir = temp_dir("audit-full");
    let fx = ChainFixture::new(1, None);
    let store = open_store(&dir);
    let mut auth = fx.enforcer();
    for _ in 0..MAX_AUDIT_ENTRIES {
        auth.audit_log_mut()
            .record(
                1,
                BoundaryKind::Api,
                repo(),
                "untrusted".into(),
                Capability::Propose,
                "wire_submit",
                AuditOutcome::Refused {
                    code: RefusalCode::AuthChainBroken,
                    reason: "untrusted".into(),
                },
            )
            .unwrap();
    }
    let srv = WireServer::new(
        ServerConfig {
            repo_id: repo(),
            read_limits: WireLimits::default(),
            max_pending_chunk_bytes: 64,
        },
        store,
        auth,
        std::sync::Arc::new(|| 5),
    )
    .unwrap();
    let (env, _) = envelope(&fx.agent, "full-audit", &[], &["x"], 5);
    let mut req = submit_request(&fx.agent, fx.chain.clone(), &env, [9; 32], 5).unwrap();
    req.payload.clear(); // Negative control: decoder would return WireFrameMalformed without preflight.
    let mut session = srv.session();
    session.handle(frame(
        0,
        FrameBody::Hello(Hello {
            max_frame_body: 65_536,
            max_pending_chunk_bytes: 0,
        }),
    ));
    let reply = session.handle(frame(1, FrameBody::Submit(Box::new(req))));
    assert_eq!(
        refused_code(reply.frames.into_iter().next()),
        RefusalCode::BackpressureOverCapacity
    );
    assert!(reply.close);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn server_refuses_protocol_violations_with_typed_refusals() {
    let dir = temp_dir("refusals");
    let fx = ChainFixture::new(1, Some(vec!["lib".into()]));
    let store = open_store(&dir);
    let srv = server(&fx, store.clone());
    let (mut client, t) = connect(&srv);
    let data = blob(0x5A, 100);
    let (env, blobs) = envelope(&fx.agent, "r", &[("lib/r.rs", data.clone())], &[], 5);
    let digest = blobs[0].0;
    let have = |repo_id: RepoId| {
        frame(
            10,
            FrameBody::Have(Have {
                repo_id,
                digests: vec![digest],
            }),
        )
    };

    // A chunk nobody asked for.
    let c = frame(
        11,
        FrameBody::Chunk(Chunk {
            digest,
            bytes: data.clone(),
        }),
    );
    assert_eq!(
        refused_code(client.exchange(std::slice::from_ref(&c)).unwrap()),
        RefusalCode::WireProtocolViolation
    );
    // A Have for another repository.
    let other = RepoId::new("aien-spark/other").unwrap();
    assert_eq!(
        refused_code(client.exchange(&[have(other)]).unwrap()),
        RefusalCode::AuthCrossRepoDenied
    );
    // Submit before the wanted chunk.
    let want = client.exchange(&[have(repo())]).unwrap().unwrap();
    assert!(matches!(want.body, FrameBody::Want(ref w) if w.digests == vec![digest]));
    let req = submit_request(&fx.agent, fx.chain.clone(), &env, [7; 32], 5).unwrap();
    let submit = frame(12, FrameBody::Submit(Box::new(req.clone())));
    assert_eq!(
        refused_code(client.exchange(std::slice::from_ref(&submit)).unwrap()),
        RefusalCode::WireProtocolViolation
    );
    // A chunk whose bytes do not hash to its digest.
    client.exchange(&[have(repo())]).unwrap();
    let mut wrong = data.clone();
    wrong[0] ^= 1;
    let bad = frame(
        13,
        FrameBody::Chunk(Chunk {
            digest,
            bytes: wrong,
        }),
    );
    assert_eq!(
        refused_code(client.exchange(&[bad]).unwrap()),
        RefusalCode::BlobDigestMismatch
    );
    // The same chunk twice.
    client.exchange(&[have(repo())]).unwrap();
    assert_eq!(
        refused_code(client.exchange(&[c.clone(), c.clone()]).unwrap()),
        RefusalCode::WireProtocolViolation
    );
    // Frames a server never accepts from a client, and a second Hello.
    for body in [
        FrameBody::Want(Want { digests: vec![] }),
        FrameBody::Hello(Hello {
            max_frame_body: 1024,
            max_pending_chunk_bytes: 0,
        }),
    ] {
        assert_eq!(
            refused_code(client.exchange(&[frame(14, body)]).unwrap()),
            RefusalCode::WireProtocolViolation
        );
    }
    // A request scope that does not list exactly the envelope's paths.
    let mut narrow = req.clone();
    narrow.scope.paths = vec!["lib".into()];
    narrow.request_nonce = [17; 32];
    let narrow = resign(&fx, narrow);
    client.exchange(&[have(repo())]).unwrap();
    assert_eq!(
        refused_code(
            client
                .exchange(&[c.clone(), frame(15, FrameBody::Submit(Box::new(narrow)))])
                .unwrap()
        ),
        RefusalCode::AuthPathOutOfScope
    );
    // A path outside the chain's scope.
    let (env_out, blobs_out) = envelope(&fx.agent, "out", &[("src/x.rs", data.clone())], &[], 6);
    let req_out = submit_request(&fx.agent, fx.chain.clone(), &env_out, [8; 32], 6).unwrap();
    client.exchange(&[have(repo())]).unwrap();
    let c_out = frame(
        16,
        FrameBody::Chunk(Chunk {
            digest: blobs_out[0].0,
            bytes: data.clone(),
        }),
    );
    assert_eq!(blobs_out[0].0, digest);
    assert_eq!(
        refused_code(
            client
                .exchange(&[c_out, frame(17, FrameBody::Submit(Box::new(req_out)))])
                .unwrap()
        ),
        RefusalCode::AuthPathOutOfScope
    );
    // A request signed by a key that is not the chain's leaf audience.
    let stranger = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    let forged = submit_request(&stranger, fx.chain.clone(), &env, [9; 32], 5).unwrap();
    client.exchange(&[have(repo())]).unwrap();
    let code = refused_code(
        client
            .exchange(&[c.clone(), frame(18, FrameBody::Submit(Box::new(forged)))])
            .unwrap(),
    );
    assert!(format!("{code:?}").starts_with("Auth"), "{code:?}");
    // A payload that is not one canonical binary envelope.
    let mut junk = req.clone();
    junk.payload = b"not an envelope".to_vec();
    let junk = resign(&fx, junk);
    client.exchange(&[have(repo())]).unwrap();
    assert_eq!(
        refused_code(
            client
                .exchange(&[c.clone(), frame(19, FrameBody::Submit(Box::new(junk)))])
                .unwrap()
        ),
        RefusalCode::WireFrameMalformed
    );
    // After every refusal the session still accepts a well-formed change.
    let ok = client.submit(&req, &blobs).unwrap();
    assert!(!ok.accepted.duplicate);
    assert_eq!(store.read().committed_seq(), ok.accepted.wal_seq);
    drop(client);
    t.join().unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Re-sign a request after changing a signed field.
fn resign(fx: &ChainFixture, r: ChainedRequest) -> ChainedRequest {
    ChainedRequest::sign_new(
        &fx.agent,
        r.chain,
        r.target_repo_id,
        Capability::Propose,
        RequestScope {
            paths: r.scope.paths,
            reference: r.scope.reference,
            join_change: r.scope.join_change,
        },
        r.request_nonce,
        r.timestamp_ms,
        r.payload,
    )
}

#[test]
fn server_closes_connection_on_frame_before_hello_or_malformed_frame() {
    use std::io::{Read, Write};
    let dir = temp_dir("close");
    let fx = ChainFixture::new(1, None);
    let srv = server(&fx, open_store(&dir));
    let limits = WireLimits::default();

    // A Have before Hello: refused, then the server closes.
    let (mut a, b) = UnixStream::pair().unwrap();
    // A missing reply fails the test instead of hanging it.
    a.set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    let s = srv.clone();
    let t = std::thread::spawn(move || s.serve(b));
    let have = encode_frame(&frame(
        1,
        FrameBody::Have(Have {
            repo_id: repo(),
            digests: vec![],
        }),
    ))
    .unwrap();
    a.write_all(&have).unwrap();
    assert_eq!(
        refused_code(read_frame(&mut a, &limits).unwrap()),
        RefusalCode::WireProtocolViolation
    );
    assert!(read_frame(&mut a, &limits).unwrap().is_none());
    t.join().unwrap().unwrap();

    // Bytes that are not a frame after Hello: refused as malformed, then closed.
    let (mut a, b) = UnixStream::pair().unwrap();
    // A missing reply fails the test instead of hanging it.
    a.set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    let s = srv.clone();
    let t = std::thread::spawn(move || s.serve(b));
    a.write_all(&hello_bytes()).unwrap();
    assert!(matches!(
        read_frame(&mut a, &limits).unwrap().map(|f| f.body),
        Some(FrameBody::Hello(_))
    ));
    a.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!(
        refused_code(read_frame(&mut a, &limits).unwrap()),
        RefusalCode::WireFrameMalformed
    );
    let mut rest = Vec::new();
    a.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    t.join().unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
