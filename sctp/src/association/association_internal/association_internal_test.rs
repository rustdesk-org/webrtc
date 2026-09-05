use std::io;
use std::net::SocketAddr;

use super::*;

type Result<T> = std::result::Result<T, util::Error>;

impl From<Error> for util::Error {
    fn from(e: Error) -> Self {
        util::Error::from_std(e)
    }
}

struct DumbConn;

#[async_trait]
impl Conn for DumbConn {
    async fn connect(&self, _addr: SocketAddr) -> Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "Not applicable").into())
    }

    async fn recv(&self, _b: &mut [u8]) -> Result<usize> {
        Ok(0)
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Err(io::Error::new(io::ErrorKind::Other, "Not applicable").into())
    }

    async fn send(&self, _b: &[u8]) -> Result<usize> {
        Ok(0)
    }

    async fn send_to(&self, _buf: &[u8], _target: SocketAddr) -> Result<usize> {
        Err(io::Error::new(io::ErrorKind::Other, "Not applicable").into())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Addr Not Available").into())
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

fn create_association_internal(config: Config) -> AssociationInternal {
    let (close_loop_ch_tx, _close_loop_ch_rx) = broadcast::channel(1);
    let (accept_ch_tx, _accept_ch_rx) = mpsc::channel(1);
    let (handshake_completed_ch_tx, _handshake_completed_ch_rx) = mpsc::channel(1);
    let (awake_write_loop_ch_tx, _awake_write_loop_ch_rx) = mpsc::channel(1);
    AssociationInternal::new(
        config,
        close_loop_ch_tx,
        accept_ch_tx,
        handshake_completed_ch_tx,
        Arc::new(awake_write_loop_ch_tx),
    )
}

#[test]
fn test_create_forward_tsn_forward_one_abandoned() -> Result<()> {
    let mut a = create_association_internal(Config {
        net_conn: Arc::new(DumbConn {}),
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: "client".to_owned(),
    });

    a.cumulative_tsn_ack_point = 9;
    a.advanced_peer_tsn_ack_point = 10;
    a.inflight_queue.push_no_check(ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn: 10,
        stream_identifier: 1,
        stream_sequence_number: 2,
        user_data: Bytes::from_static(b"ABC"),
        nsent: 1,
        abandoned: Arc::new(AtomicBool::new(true)),
        ..Default::default()
    });

    let fwdtsn = a.create_forward_tsn();

    assert_eq!(fwdtsn.new_cumulative_tsn, 10, "should be able to serialize");
    assert_eq!(fwdtsn.streams.len(), 1, "there should be one stream");
    assert_eq!(fwdtsn.streams[0].identifier, 1, "si should be 1");
    assert_eq!(fwdtsn.streams[0].sequence, 2, "ssn should be 2");

    Ok(())
}

#[test]
fn test_create_forward_tsn_forward_two_abandoned_with_the_same_si() -> Result<()> {
    let mut a = create_association_internal(Config {
        net_conn: Arc::new(DumbConn {}),
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: "client".to_owned(),
    });

    a.cumulative_tsn_ack_point = 9;
    a.advanced_peer_tsn_ack_point = 12;
    a.inflight_queue.push_no_check(ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn: 10,
        stream_identifier: 1,
        stream_sequence_number: 2,
        user_data: Bytes::from_static(b"ABC"),
        nsent: 1,
        abandoned: Arc::new(AtomicBool::new(true)),
        ..Default::default()
    });
    a.inflight_queue.push_no_check(ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn: 11,
        stream_identifier: 1,
        stream_sequence_number: 3,
        user_data: Bytes::from_static(b"DEF"),
        nsent: 1,
        abandoned: Arc::new(AtomicBool::new(true)),
        ..Default::default()
    });
    a.inflight_queue.push_no_check(ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn: 12,
        stream_identifier: 2,
        stream_sequence_number: 1,
        user_data: Bytes::from_static(b"123"),
        nsent: 1,
        abandoned: Arc::new(AtomicBool::new(true)),
        ..Default::default()
    });

    let fwdtsn = a.create_forward_tsn();

    assert_eq!(fwdtsn.new_cumulative_tsn, 12, "should be able to serialize");
    assert_eq!(fwdtsn.streams.len(), 2, "there should be two stream");

    let mut si1ok = false;
    let mut si2ok = false;
    for s in &fwdtsn.streams {
        match s.identifier {
            1 => {
                assert_eq!(3, s.sequence, "ssn should be 3");
                si1ok = true;
            }
            2 => {
                assert_eq!(1, s.sequence, "ssn should be 1");
                si2ok = true;
            }
            _ => panic!("unexpected stream identifier"),
        }
    }
    assert!(si1ok, "si=1 should be present");
    assert!(si2ok, "si=2 should be present");

    Ok(())
}

#[tokio::test]
async fn test_handle_forward_tsn_forward_3unreceived_chunks() -> Result<()> {
    let mut a = create_association_internal(Config {
        net_conn: Arc::new(DumbConn {}),
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: "client".to_owned(),
    });
    a.use_forward_tsn = true;

    let prev_tsn = a.peer_last_tsn;

    let fwdtsn = ChunkForwardTsn {
        new_cumulative_tsn: a.peer_last_tsn + 3,
        streams: vec![ChunkForwardTsnStream {
            identifier: 0,
            sequence: 0,
        }],
    };

    let p = a.handle_forward_tsn(&fwdtsn).await?;

    let delayed_ack_triggered = a.delayed_ack_triggered;
    let immediate_ack_triggered = a.immediate_ack_triggered;
    assert_eq!(
        a.peer_last_tsn,
        prev_tsn + 3,
        "peerLastTSN should advance by 3 "
    );
    assert!(delayed_ack_triggered, "delayed sack should be triggered");
    assert!(
        !immediate_ack_triggered,
        "immediate sack should NOT be triggered"
    );
    assert!(p.is_empty(), "should return empty");

    Ok(())
}

#[tokio::test]
async fn test_handle_forward_tsn_forward_1for1_missing() -> Result<()> {
    let mut a = create_association_internal(Config {
        net_conn: Arc::new(DumbConn {}),
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: "client".to_owned(),
    });
    a.use_forward_tsn = true;

    let prev_tsn = a.peer_last_tsn;

    // this chunk is blocked by the missing chunk at tsn=1
    a.payload_queue.push(
        ChunkPayloadData {
            beginning_fragment: true,
            ending_fragment: true,
            tsn: a.peer_last_tsn + 2,
            stream_identifier: 0,
            stream_sequence_number: 1,
            user_data: Bytes::from_static(b"ABC"),
            ..Default::default()
        },
        a.peer_last_tsn,
    );

    let fwdtsn = ChunkForwardTsn {
        new_cumulative_tsn: a.peer_last_tsn + 1,
        streams: vec![ChunkForwardTsnStream {
            identifier: 0,
            sequence: 1,
        }],
    };

    let p = a.handle_forward_tsn(&fwdtsn).await?;

    let delayed_ack_triggered = a.delayed_ack_triggered;
    let immediate_ack_triggered = a.immediate_ack_triggered;
    assert_eq!(
        a.peer_last_tsn,
        prev_tsn + 2,
        "peerLastTSN should advance by 2"
    );
    assert!(delayed_ack_triggered, "delayed sack should be triggered");
    assert!(
        !immediate_ack_triggered,
        "immediate sack should NOT be triggered"
    );
    assert!(p.is_empty(), "should return empty");

    Ok(())
}

#[tokio::test]
async fn test_handle_forward_tsn_forward_1for2_missing() -> Result<()> {
    let mut a = create_association_internal(Config {
        net_conn: Arc::new(DumbConn {}),
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: "client".to_owned(),
    });
    a.use_forward_tsn = true;

    let prev_tsn = a.peer_last_tsn;

    // this chunk is blocked by the missing chunk at tsn=1
    a.payload_queue.push(
        ChunkPayloadData {
            beginning_fragment: true,
            ending_fragment: true,
            tsn: a.peer_last_tsn + 3,
            stream_identifier: 0,
            stream_sequence_number: 1,
            user_data: Bytes::from_static(b"ABC"),
            ..Default::default()
        },
        a.peer_last_tsn,
    );

    let fwdtsn = ChunkForwardTsn {
        new_cumulative_tsn: a.peer_last_tsn + 1,
        streams: vec![ChunkForwardTsnStream {
            identifier: 0,
            sequence: 1,
        }],
    };

    let p = a.handle_forward_tsn(&fwdtsn).await?;

    let immediate_ack_triggered = a.immediate_ack_triggered;
    assert_eq!(
        a.peer_last_tsn,
        prev_tsn + 1,
        "peerLastTSN should advance by 1"
    );
    assert!(
        immediate_ack_triggered,
        "immediate sack should be triggered"
    );
    assert!(p.is_empty(), "should return empty");

    Ok(())
}

#[tokio::test]
async fn test_handle_forward_tsn_dup_forward_tsn_chunk_should_generate_sack() -> Result<()> {
    let mut a = create_association_internal(Config {
        net_conn: Arc::new(DumbConn {}),
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: "client".to_owned(),
    });
    a.use_forward_tsn = true;

    let prev_tsn = a.peer_last_tsn;

    let fwdtsn = ChunkForwardTsn {
        new_cumulative_tsn: a.peer_last_tsn,
        streams: vec![ChunkForwardTsnStream {
            identifier: 0,
            sequence: 1,
        }],
    };

    let p = a.handle_forward_tsn(&fwdtsn).await?;

    assert_eq!(a.peer_last_tsn, prev_tsn, "peerLastTSN should not advance");
    assert_eq!(a.ack_state, AckState::Immediate, "sack should be requested");
    assert!(p.is_empty(), "should return empty");

    Ok(())
}

#[tokio::test]
async fn test_assoc_create_new_stream() -> Result<()> {
    let (close_loop_ch_tx, _close_loop_ch_rx) = broadcast::channel(1);
    let (accept_ch_tx, _accept_ch_rx) = mpsc::channel(ACCEPT_CH_SIZE);
    let (handshake_completed_ch_tx, _handshake_completed_ch_rx) = mpsc::channel(1);
    let (awake_write_loop_ch_tx, _awake_write_loop_ch_rx) = mpsc::channel(1);
    let mut a = AssociationInternal::new(
        Config {
            net_conn: Arc::new(DumbConn {}),
            max_receive_buffer_size: 0,
            max_message_size: 0,
            name: "client".to_owned(),
        },
        close_loop_ch_tx,
        accept_ch_tx,
        handshake_completed_ch_tx,
        Arc::new(awake_write_loop_ch_tx),
    );

    for i in 0..ACCEPT_CH_SIZE {
        let s = a.create_stream(i as u16, true);
        if let Some(s) = s {
            let result = a.streams.get(&s.stream_identifier);
            assert!(result.is_some(), "should be in a.streams map");
        } else {
            panic!("{i} should success");
        }
    }

    let new_si = ACCEPT_CH_SIZE as u16;
    let s = a.create_stream(new_si, true);
    assert!(s.is_none(), "should be none");
    let result = a.streams.get(&new_si);
    assert!(result.is_none(), "should NOT be in a.streams map");

    let to_be_ignored = ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn: a.peer_last_tsn + 1,
        stream_identifier: new_si,
        user_data: Bytes::from_static(b"ABC"),
        ..Default::default()
    };

    let p = a.handle_data(&to_be_ignored).await?;
    assert!(p.is_empty(), "should return empty");

    Ok(())
}

async fn handle_init_test(name: &str, initial_state: AssociationState, expect_err: bool) {
    let mut a = create_association_internal(Config {
        net_conn: Arc::new(DumbConn {}),
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: "client".to_owned(),
    });
    a.set_state(initial_state);
    let pkt = Packet {
        source_port: 5001,
        destination_port: 5002,
        ..Default::default()
    };
    let mut init = ChunkInit {
        initial_tsn: 1234,
        num_outbound_streams: 1001,
        num_inbound_streams: 1002,
        initiate_tag: 5678,
        advertised_receiver_window_credit: 512 * 1024,
        ..Default::default()
    };
    init.set_supported_extensions();

    let result = a.handle_init(&pkt, &init).await;
    if expect_err {
        assert!(result.is_err(), "{name} should fail");
        return;
    } else {
        assert!(result.is_ok(), "{name} should be ok");
    }
    assert_eq!(
        a.peer_last_tsn,
        if init.initial_tsn == 0 {
            u32::MAX
        } else {
            init.initial_tsn - 1
        },
        "{name} should match"
    );
    assert_eq!(a.my_max_num_outbound_streams, 1001, "{name} should match");
    assert_eq!(a.my_max_num_inbound_streams, 1002, "{name} should match");
    assert_eq!(a.peer_verification_tag, 5678, "{name} should match");
    assert_eq!(a.destination_port, pkt.source_port, "{name} should match");
    assert_eq!(a.source_port, pkt.destination_port, "{name} should match");
    assert!(a.use_forward_tsn, "{name} should be set to true");
}

#[tokio::test]
async fn test_assoc_handle_init() -> Result<()> {
    handle_init_test("normal", AssociationState::Closed, false).await;

    handle_init_test(
        "unexpected state established",
        AssociationState::Established,
        true,
    )
    .await;

    handle_init_test(
        "unexpected state shutdownAckSent",
        AssociationState::ShutdownAckSent,
        true,
    )
    .await;

    handle_init_test(
        "unexpected state shutdownPending",
        AssociationState::ShutdownPending,
        true,
    )
    .await;

    handle_init_test(
        "unexpected state shutdownReceived",
        AssociationState::ShutdownReceived,
        true,
    )
    .await;

    handle_init_test(
        "unexpected state shutdownSent",
        AssociationState::ShutdownSent,
        true,
    )
    .await;

    Ok(())
}

#[tokio::test]
async fn test_assoc_max_message_size_default() -> Result<()> {
    let mut a = create_association_internal(Config {
        net_conn: Arc::new(DumbConn {}),
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: "client".to_owned(),
    });
    assert_eq!(
        a.max_message_size.load(Ordering::SeqCst),
        65536,
        "should match"
    );

    let stream = a.create_stream(1, false);
    assert!(stream.is_some(), "should succeed");

    if let Some(s) = stream {
        let p = Bytes::from(vec![0u8; 65537]);
        let ppi = PayloadProtocolIdentifier::from(s.default_payload_type.load(Ordering::SeqCst));

        if let Err(err) = s.write_sctp(&p.slice(..65536), ppi).await {
            assert_ne!(
                err,
                Error::ErrOutboundPacketTooLarge,
                "should be not Error::ErrOutboundPacketTooLarge"
            );
        } else {
            panic!("should be error");
        }

        if let Err(err) = s.write_sctp(&p.slice(..65537), ppi).await {
            assert_eq!(
                err,
                Error::ErrOutboundPacketTooLarge,
                "should be Error::ErrOutboundPacketTooLarge"
            );
        } else {
            panic!("should be error");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_assoc_max_message_size_explicit() -> Result<()> {
    let mut a = create_association_internal(Config {
        net_conn: Arc::new(DumbConn {}),
        max_receive_buffer_size: 0,
        max_message_size: 30000,
        name: "client".to_owned(),
    });

    assert_eq!(
        a.max_message_size.load(Ordering::SeqCst),
        30000,
        "should match"
    );

    let stream = a.create_stream(1, false);
    assert!(stream.is_some(), "should succeed");

    if let Some(s) = stream {
        let p = Bytes::from(vec![0u8; 30001]);
        let ppi = PayloadProtocolIdentifier::from(s.default_payload_type.load(Ordering::SeqCst));

        if let Err(err) = s.write_sctp(&p.slice(..30000), ppi).await {
            assert_ne!(
                err,
                Error::ErrOutboundPacketTooLarge,
                "should be not Error::ErrOutboundPacketTooLarge"
            );
        } else {
            panic!("should be error");
        }

        if let Err(err) = s.write_sctp(&p.slice(..30001), ppi).await {
            assert_eq!(
                err,
                Error::ErrOutboundPacketTooLarge,
                "should be Error::ErrOutboundPacketTooLarge"
            );
        } else {
            panic!("should be error");
        }
    }

    Ok(())
}

fn create_client_association_internal() -> AssociationInternal {
    create_association_internal(Config {
        net_conn: Arc::new(DumbConn {}),
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: "client".to_owned(),
    })
}

/// Queues `n` single-chunk messages of `size` bytes and returns how many bytes one pass of
/// the pending-queue pop sends.
async fn queue_and_pop(a: &mut AssociationInternal, n: usize, size: usize) -> usize {
    for i in 0..n {
        a.pending_queue
            .push(ChunkPayloadData {
                beginning_fragment: true,
                ending_fragment: true,
                stream_identifier: 1,
                stream_sequence_number: i as u16,
                user_data: Bytes::from(vec![0u8; size]),
                ..Default::default()
            })
            .await;
    }
    let (chunks, _) = a.pop_pending_data_chunks_to_send().await;
    chunks.iter().map(|c| c.user_data.len()).sum()
}

#[tokio::test]
async fn test_assoc_no_congestion_control_sends_past_cwnd_up_to_rwnd() -> Result<()> {
    let mut a = create_client_association_internal();
    a.no_congestion_control = true;
    a.rwnd = 20_000;
    assert!(a.cwnd < a.rwnd);

    let sent = queue_and_pop(&mut a, 40, 1000).await;

    assert!(sent > a.cwnd as usize, "cwnd should not gate sending");
    assert_eq!(sent, 20_000, "rwnd should still gate sending");

    Ok(())
}

// The switch is the association's own copy, not the process-wide static: `a` keeps sending
// without cwnd after the static is set off. (Only ever set off here, its default, so the
// tests creating associations in parallel are not affected.)
#[tokio::test]
async fn test_assoc_no_congestion_control_fixed_at_creation() -> Result<()> {
    let mut a = create_client_association_internal();
    a.no_congestion_control = true;
    set_no_congestion_control(false);
    let mut b = create_client_association_internal();
    a.rwnd = 20_000;
    b.rwnd = 20_000;

    let sent_a = queue_and_pop(&mut a, 40, 1000).await;
    let sent_b = queue_and_pop(&mut b, 40, 1000).await;

    assert_eq!(sent_a, 20_000, "created with the switch on: rwnd alone");
    assert!(
        sent_b <= b.cwnd as usize,
        "created with it off: cwnd applies"
    );

    Ok(())
}

/// T3-rtx with the peer's window fully used: RFC 4960 sec 6.2.1 gives the marked chunks
/// their rwnd credit back, so every one of them is resent, not just a zero-window probe.
async fn assert_t3_resends_all_marked(nocc: bool) {
    let mut a = create_client_association_internal();
    a.no_congestion_control = nocc;
    a.cumulative_tsn_ack_point = 9;
    a.rwnd = 0;
    for tsn in 10..=12 {
        a.inflight_queue.push_no_check(ChunkPayloadData {
            beginning_fragment: true,
            ending_fragment: true,
            tsn,
            stream_identifier: 1,
            stream_sequence_number: (tsn - 10) as u16,
            user_data: Bytes::from(vec![0u8; 100]),
            nsent: 1,
            retransmit: true,
            ..Default::default()
        });
    }

    let packets = a.get_data_packets_to_retransmit();

    let resent: usize = packets.iter().map(|p| p.chunks.len()).sum();
    assert_eq!(
        resent, 3,
        "nocc={nocc}: every marked chunk should be resent"
    );
}

#[tokio::test]
async fn test_assoc_t3_resends_all_marked_with_rwnd_exhausted() -> Result<()> {
    assert_t3_resends_all_marked(false).await;
    assert_t3_resends_all_marked(true).await;
    Ok(())
}

#[tokio::test]
async fn test_assoc_no_congestion_control_caps_inflight_below_large_rwnd() -> Result<()> {
    let mut a = create_client_association_internal();
    a.no_congestion_control = true;
    a.rwnd = 4 * NO_CC_MAX_INFLIGHT as u32;

    let sent = queue_and_pop(&mut a, 2048, 1024).await;

    assert_eq!(
        sent, NO_CC_MAX_INFLIGHT,
        "a large a_rwnd must not enlarge the burst"
    );

    Ok(())
}

/// Puts TSN 10..=16 in flight with 100-byte chunks sent in TSN order, `sent_seq` == TSN.
/// The send time that goes with send-order stamp `seq`: a millisecond apart, and a second in the
/// past so a real transmission stamped by the code under test still comes after all of them.
fn at(seq: u64) -> Instant {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(|| Instant::now() - Duration::from_secs(1)) + Duration::from_millis(seq)
}

fn inflight_10_to_16(a: &mut AssociationInternal) {
    a.cumulative_tsn_ack_point = 9;
    a.my_next_tsn = 17;
    a.send_seq = 17;
    for tsn in 10..=16 {
        a.inflight_queue.push_no_check(ChunkPayloadData {
            tsn,
            user_data: Bytes::from(vec![0u8; 100]),
            nsent: 1,
            sent_seq: u64::from(tsn),
            sent_at: at(u64::from(tsn)),
            ..Default::default()
        });
    }
}

/// Models a resend of `tsn` as the `seq`-th transmission of the association.
fn resent(a: &mut AssociationInternal, tsn: u32, seq: u64) {
    if let Some(c) = a.inflight_queue.get_mut(tsn) {
        c.nsent = 2;
        c.sent_seq = seq;
        c.sent_at = at(seq);
    }
}

fn miss_indicator(a: &AssociationInternal, tsn: u32) -> Option<u32> {
    a.inflight_queue.get(tsn).map(|c| c.miss_indicator)
}

/// Runs a SACK through the acking and loss-detection steps of handle_sack; `gaps` are offsets
/// from `cum`, as on the wire.
async fn sack(
    a: &mut AssociationInternal,
    cum: u32,
    gaps: &[(u16, u16)],
) -> crate::error::Result<()> {
    sack_with_dups(a, cum, gaps, &[]).await
}

async fn sack_with_dups(
    a: &mut AssociationInternal,
    cum: u32,
    gaps: &[(u16, u16)],
    dups: &[u32],
) -> crate::error::Result<()> {
    use crate::chunk::chunk_selective_ack::GapAckBlock;
    let d = ChunkSelectiveAck {
        cumulative_tsn_ack: cum,
        advertised_receiver_window_credit: a.rwnd,
        gap_ack_blocks: gaps
            .iter()
            .map(|&(start, end)| GapAckBlock { start, end })
            .collect(),
        duplicate_tsn: dups.to_vec(),
    };
    let (_, htna) = a.process_selective_ack(&d).await?;
    let advanced = sna32lt(a.cumulative_tsn_ack_point, cum);
    a.cumulative_tsn_ack_point = cum;
    a.process_fast_retransmission(cum, htna, advanced)
}

// Only chunks sent after a chunk's latest transmission count as evidence against it: TSN 10
// was resent after 11 and 12 went out, so their acks say nothing about the resend.
#[tokio::test]
async fn test_assoc_no_congestion_control_detects_a_lost_retransmission() -> Result<()> {
    let mut a = create_client_association_internal();
    a.no_congestion_control = true;
    inflight_10_to_16(&mut a);
    // 10 went out again between the first sends of 12 and 13.
    for tsn in 13..=16 {
        if let Some(c) = a.inflight_queue.get_mut(tsn) {
            c.sent_seq += 1;
            c.sent_at = at(c.sent_seq);
        }
    }
    resent(&mut a, 10, 13);
    a.send_seq = 18;

    sack(&mut a, 9, &[(2, 3), (5, 6)]).await?;
    assert_eq!(
        miss_indicator(&a, 10),
        Some(2),
        "acks below the resend must not count"
    );
    assert!(!a.will_retransmit_fast, "two acks above are not enough");

    sack(&mut a, 9, &[(2, 3), (5, 7)]).await?;
    assert_eq!(
        miss_indicator(&a, 10),
        Some(3),
        "third ack above the resend"
    );
    assert!(a.will_retransmit_fast, "the lost resend must go out again");

    Ok(())
}

// Chunks resent in one pass are evidence for each other: 10..=13 go out again together, and
// the acks of 11..=13 alone show that 10's resend is lost, with no new data after them.
#[tokio::test]
async fn test_assoc_no_congestion_control_resent_chunks_are_evidence_for_each_other() -> Result<()>
{
    let mut a = create_client_association_internal();
    a.no_congestion_control = true;
    inflight_10_to_16(&mut a);
    for tsn in 10..=13 {
        if let Some(c) = a.inflight_queue.get_mut(tsn) {
            c.miss_indicator = 3;
        }
    }
    for tsn in 14..=16 {
        a.inflight_queue.mark_as_acked(tsn);
    }
    a.will_retransmit_fast = true;
    let packets = a.gather_outbound_fast_retransmission_packets(vec![]);
    let resent: usize = packets.iter().map(|p| p.chunks.len()).sum();
    assert_eq!(resent, 4, "10..=13 resent together");

    sack(&mut a, 9, &[(2, 7)]).await?;
    assert_eq!(
        miss_indicator(&a, 10),
        Some(3),
        "resent with 10, acked after it"
    );
    assert!(a.will_retransmit_fast, "10's resend is lost");

    Ok(())
}

// Evidence is what was sent after the chunk's latest transmission, in any TSN direction: the
// later resends of 10..=12 arriving show that 15's resend is lost, even though their acks come
// as a cumulative point advance that takes them out of the in-flight queue.
#[tokio::test]
async fn test_assoc_no_congestion_control_later_resends_of_lower_tsns_are_evidence() -> Result<()> {
    let mut a = create_client_association_internal();
    a.no_congestion_control = true;
    inflight_10_to_16(&mut a);
    for tsn in [13, 14, 16] {
        a.inflight_queue.mark_as_acked(tsn);
    }
    resent(&mut a, 15, 17);
    for tsn in 10..=12 {
        resent(&mut a, tsn, 8 + u64::from(tsn));
    }
    a.send_seq = 21;

    sack(&mut a, 14, &[(2, 2)]).await?;
    assert_eq!(a.inflight_queue.len(), 2, "10..=14 left the queue");
    assert_eq!(miss_indicator(&a, 15), Some(3), "three later sends acked");
    assert!(a.will_retransmit_fast, "15's resend is lost");

    Ok(())
}

/// Marks TSN 10..=14 lost and returns how many chunks one fast-retransmission pass sends.
async fn fast_retransmitted(nocc: bool) -> usize {
    let mut a = create_client_association_internal();
    a.no_congestion_control = nocc;
    a.cumulative_tsn_ack_point = 9;
    for tsn in 10..=14 {
        a.inflight_queue.push_no_check(ChunkPayloadData {
            tsn,
            user_data: Bytes::from(vec![0u8; 1000]),
            nsent: 1,
            miss_indicator: 3,
            ..Default::default()
        });
    }
    a.will_retransmit_fast = true;

    let packets = a.gather_outbound_fast_retransmission_packets(vec![]);
    packets.iter().map(|p| p.chunks.len()).sum()
}

#[tokio::test]
async fn test_assoc_no_congestion_control_fast_retransmits_all_lost_chunks() -> Result<()> {
    assert_eq!(
        fast_retransmitted(false).await,
        1,
        "one MTU per SACK with cwnd"
    );
    assert_eq!(
        fast_retransmitted(true).await,
        5,
        "everything found lost without cwnd"
    );
    Ok(())
}

#[tokio::test]
async fn test_assoc_no_congestion_control_caps_inflight_chunks() -> Result<()> {
    let mut a = create_client_association_internal();
    a.no_congestion_control = true;
    a.rwnd = NO_CC_MAX_INFLIGHT as u32;

    let sent = queue_and_pop(&mut a, 2 * NO_CC_MAX_INFLIGHT_CHUNKS, 10).await;

    assert_eq!(
        sent,
        10 * NO_CC_MAX_INFLIGHT_CHUNKS,
        "small chunks are bounded by count, as KCP's segments are"
    );

    Ok(())
}

// With a reordering window, evidence must have been sent that much after the chunk as well as
// after it in send order: at a 3ms window, of 11..=13 (sent 1, 2 and 3ms after 10) only 13 is
// evidence against 10, and 14..=16 then complete the three.
#[tokio::test]
async fn test_assoc_no_congestion_control_reordering_window_withholds_evidence() -> Result<()> {
    let mut a = create_client_association_internal();
    a.no_congestion_control = true;
    inflight_10_to_16(&mut a);
    // The chunks' RTT samples are near zero here; hold srtt where the window needs it.
    a.rto_mgr.srtt = 12;
    a.rto_mgr.no_update = true;
    a.reo_wnd_mult = 1;

    sack(&mut a, 9, &[(2, 4)]).await?;
    assert_eq!(
        miss_indicator(&a, 10),
        Some(1),
        "11 and 12 were sent within the window of 10"
    );
    assert!(!a.will_retransmit_fast);

    sack(&mut a, 9, &[(2, 7)]).await?;
    assert_eq!(miss_indicator(&a, 10), Some(3), "14..=16 are past the window");
    assert!(a.will_retransmit_fast, "10 is lost");

    Ok(())
}

// Once the path is seen to reorder the window is a quarter of srtt; each SACK that reports
// duplicate TSNs adds a quarter, at most once per srtt; 16 srtt without duplicates take it back
// to one quarter, and 16 srtt without reordering either close it.
#[tokio::test]
async fn test_assoc_no_congestion_control_widens_the_window_on_duplicates() -> Result<()> {
    let mut a = create_client_association_internal();
    a.no_congestion_control = true;
    a.rto_mgr.srtt = 40;
    a.rto_mgr.no_update = true;
    inflight_10_to_16(&mut a);

    sack(&mut a, 9, &[(4, 4)]).await?;
    assert_eq!(a.reo_wnd, Duration::ZERO, "in order so far");

    sack(&mut a, 9, &[(2, 2), (4, 4)]).await?;
    assert_eq!(
        a.reo_wnd,
        Duration::from_millis(10),
        "11 acked behind 13: a quarter of srtt"
    );

    sack_with_dups(&mut a, 9, &[(2, 2), (4, 5)], &[11]).await?;
    assert_eq!(
        a.reo_wnd,
        Duration::from_millis(20),
        "a duplicate reported: one quarter more"
    );

    sack_with_dups(&mut a, 9, &[(2, 2), (4, 6)], &[12]).await?;
    assert_eq!(
        a.reo_wnd,
        Duration::from_millis(20),
        "not again within an srtt"
    );

    a.reo_wnd_dup_at = Some(Instant::now() - Duration::from_secs(1));
    sack(&mut a, 9, &[(2, 2), (4, 6)]).await?;
    assert_eq!(
        a.reo_wnd,
        Duration::from_millis(10),
        "16 srtt without duplicates: back to a quarter"
    );

    a.reo_wnd_seen_at = Some(Instant::now() - Duration::from_secs(1));
    sack(&mut a, 9, &[(2, 2), (4, 7)]).await?;
    assert_eq!(a.reo_wnd, Duration::ZERO, "16 srtt in order close it");

    Ok(())
}

// Both bundlers must count a chunk as it goes on the wire, header and 4-byte padding included.
// Counting the payload alone let a bundle of small chunks marshal past the MTU: 500 + 663
// payload bytes pass a payload-only check against 1191 exactly and marshal to 1208, and a run
// of 1-byte chunks, each padded to 4, overshoots by a quarter.
#[test]
fn test_bundled_data_chunks_stay_within_mtu() -> Result<()> {
    let mut a = create_association_internal(Config {
        net_conn: Arc::new(DumbConn {}),
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: "client".to_owned(),
    });
    let chunk = |tsn: u32, len: usize| ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn,
        stream_identifier: 1,
        stream_sequence_number: tsn as u16,
        user_data: Bytes::from(vec![0u8; len]),
        nsent: 1,
        ..Default::default()
    };
    let sizes: Vec<usize> = [500, 663]
        .into_iter()
        .chain(std::iter::repeat(1).take(100))
        .collect();

    let chunks: Vec<_> = sizes
        .iter()
        .enumerate()
        .map(|(i, &len)| chunk(i as u32 + 1, len))
        .collect();
    let packets = a.bundle_data_chunks_into_packets(chunks);
    assert!(packets.len() > 1, "the chunks should span several packets");
    for p in packets {
        let raw = p.marshal()?;
        assert!(
            raw.len() as u32 <= a.mtu,
            "bundled packet of {} bytes exceeds the MTU of {}",
            raw.len(),
            a.mtu
        );
    }

    // The fast-retransmit bundler, with every chunk found lost.
    a.no_congestion_control = true;
    a.cumulative_tsn_ack_point = 0;
    for (i, &len) in sizes.iter().enumerate() {
        let mut c = chunk(i as u32 + 1, len);
        c.miss_indicator = 3;
        a.inflight_queue.push_no_check(c);
    }
    a.will_retransmit_fast = true;
    let packets = a.gather_outbound_fast_retransmission_packets(vec![]);
    assert!(packets.len() > 1, "the resends should span several packets");
    for p in packets {
        let raw = p.marshal()?;
        assert!(
            raw.len() as u32 <= a.mtu,
            "fast-retransmit packet of {} bytes exceeds the MTU of {}",
            raw.len(),
            a.mtu
        );
    }

    Ok(())
}
