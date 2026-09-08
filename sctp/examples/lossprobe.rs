//! lossprobe: an in-process link simulator for the no-congestion-window sending mode.
//!
//! Two associations exchange a frame workload over a pair of one-way pipes that model a path:
//! serialization at a bit rate, a base delay, jitter, loss, a finite buffer, stalls and capacity
//! dips. The same binary drives KCP (`--features kcp`) so the two transports can be compared on
//! the same path; comparing revisions of this crate means building this example in each
//! checkout (copy it into `sctp/examples/` where it is missing - it uses nothing but the public
//! `Association`, `Stream` and `set_no_congestion_control` API).
//!
//! Everything is set through the environment; each run prints one `RESULT` line.
//!
//! ```text
//! PROTO=sctp|kcp   NC=1 sends without a congestion window (default), NC=0 with one
//! OWD=35           one-way delay, ms                   RATE=30       link rate, Mbps
//! RATE_REV=RATE    reverse-direction rate              OVERHEAD=65|28  per-packet IP/UDP(/DTLS) bytes
//! LOSS=0           % of packets lost, both ways        BURST_MS=0    mean length of a loss burst
//! JITTER=0         ms of queueing-style jitter         JITTER_IID=1  independent per packet instead
//! REORDER=0        per mille sent REORDER_MS early     QUEUE_MS=0    buffer depth at RATE
//! QUEUE_BYTES=0    buffer in bytes, overrides QUEUE_MS
//! SPIKE_EVERY=0 SPIKE_MS=0      the link sends nothing for SPIKE_MS every SPIKE_EVERY ms
//! DIP_EVERY=0 DIP_MS=0 DIP_RATE=1  the link runs at DIP_RATE Mbps for DIP_MS every DIP_EVERY ms
//! FRAME=12000 FPS=30 FRAMES=300     the workload: FRAMES frames of FRAME bytes at FPS
//! GAP_EVERY=0 GAP_MS=0              pause GAP_MS after every GAP_EVERY frames: bursts with tails
//! TAILDROP=0                        drop the last TAILDROP packets of every burst. The pipe
//!                                    drops the next packets it is handed, retransmissions of
//!                                    an earlier burst included, so a tail-loss run wants one
//!                                    burst (GAP_EVERY=FRAMES) and several seeds rather than
//!                                    bursts whose recovery can overlap the next drop.
//! SEED=1 DEADLINE=60
//! ```
//!
//! Loss, jitter and the channel state are one time-domain trace per direction, drawn from the
//! seed at a millisecond a tick, and the path's clock starts with the workload rather than
//! with the handshake, so every transport run with the same seed sees the same path; only
//! independent per-packet loss (`BURST_MS=0`) is drawn per packet. Wire figures count the
//! workload only, not the handshake. `RUST_LOG=webrtc_sctp=trace` logs the associations. Independent per-packet
//! jitter (`JITTER_IID=1`) reorders far more than any real path and is kept only because that
//! is what first showed fast retransmission misfiring on reordering; the default jitter is a
//! random walk shared by consecutive packets, delivered in order, as a queue jitters.
//!
//! Caveats: both ends run in this process on real time, so the numbers carry scheduling noise
//! and chaotic scenarios (a link at the edge of its capacity, stalls on a slow link) need
//! several seeds; percentiles are of delivered frames only, while `miss*` count the undelivered
//! ones as missed; nothing models the peer's CPU or an application adapting its bit rate.

use std::cmp::Ordering as CmpOrdering;
use std::collections::BinaryHeap;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use rand::{Rng, SeedableRng};
use tokio::sync::{mpsc, Mutex};
use tokio::time::Instant;
use util::Conn;

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

#[derive(Default)]
struct LinkStats {
    pkts: AtomicU64,
    /// Bytes handed to the link. Counted before the buffer decides, so this is what the sender
    /// offered, not what went out - the two differ by exactly `drop_bytes` and only a run with
    /// no tail drops can read them as the same number.
    offered: AtomicU64,
    /// Bytes the bottleneck actually put on the wire: offered, less what the buffer turned away.
    bytes: AtomicU64,
    dropped: AtomicU64,
    drop_bytes: AtomicU64,
}

/// The path as a function of time, a millisecond a tick: what a packet meets depends on when
/// it is sent, not on how many were sent before it, so transports that packetize differently
/// still see the same path.
struct PathTrace {
    jitter_us: Vec<u32>,
    bad: Vec<bool>,
}

impl PathTrace {
    fn new(seed: u64, ticks: usize, jitter: Duration, loss_pct: u64, burst: Duration) -> Self {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let j = jitter.as_micros() as i64;
        let step = (j / 20).max(1);
        let mut jit = if j > 0 { rng.gen_range(0..=j) } else { 0 };
        let p = loss_pct as f64 / 100.0;
        let bad_ms = burst.as_millis() as f64;
        // Gilbert: the bad state loses every packet and lasts `burst` on average; the fraction
        // of time spent in it is the loss rate.
        let p_bg = if bad_ms > 0.0 { 1.0 / bad_ms } else { 1.0 };
        let p_gb = if p < 1.0 { p * p_bg / (1.0 - p) } else { 1.0 };
        let mut bad = false;
        let mut jitter_us = Vec::with_capacity(ticks);
        let mut bads = Vec::with_capacity(ticks);
        for _ in 0..ticks {
            if j > 0 {
                jit = (jit + rng.gen_range(-step..=step)).clamp(0, j);
            }
            jitter_us.push(jit as u32);
            if bad_ms > 0.0 {
                if bad {
                    if rng.gen::<f64>() < p_bg {
                        bad = false;
                    }
                } else if rng.gen::<f64>() < p_gb {
                    bad = true;
                }
            }
            bads.push(bad);
        }
        PathTrace {
            jitter_us,
            bad: bads,
        }
    }

    fn at(&self, t: Duration) -> (u32, bool) {
        let i = (t.as_millis() as usize).min(self.jitter_us.len() - 1);
        (self.jitter_us[i], self.bad[i])
    }
}

/// A packet waiting to arrive, ordered by arrival time, earliest first.
struct Scheduled {
    at: Instant,
    seq: u64,
    b: Bytes,
}

impl PartialEq for Scheduled {
    fn eq(&self, o: &Self) -> bool {
        self.at == o.at && self.seq == o.seq
    }
}
impl Eq for Scheduled {}
impl PartialOrd for Scheduled {
    fn partial_cmp(&self, o: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(o))
    }
}
impl Ord for Scheduled {
    fn cmp(&self, o: &Self) -> CmpOrdering {
        (o.at, o.seq).cmp(&(self.at, self.seq))
    }
}

#[derive(Clone)]
struct PipeTx(mpsc::UnboundedSender<(Instant, Bytes)>);

impl PipeTx {
    fn send(&self, b: Bytes) -> bool {
        self.0.send((Instant::now(), b)).is_ok()
    }
}

struct Impair {
    delay: Duration,
    rate_mbps: f64,
    /// Bytes every packet costs on the wire beyond its payload: IP + UDP, and DTLS for SCTP.
    overhead: usize,
    /// % of packets lost; with `burst` zero drawn per packet, else the trace's bad state.
    loss: u64,
    burst: Duration,
    jitter: Duration,
    jitter_iid: bool,
    /// Per mille of packets that arrive `reorder_by` early, as netem's reorder sends them.
    reorder: u64,
    reorder_by: Duration,
    /// Buffer at the bottleneck. A packet arriving with this many bytes already waiting is
    /// dropped at the tail. Zero is unbounded.
    ///
    /// Sized in bytes rather than in waiting time on purpose: a time bound also fires on a
    /// packet entering an EMPTY buffer during a stall, since its wait is the stall, and that
    /// turns a stall into a black hole instead of a buffer that fills and then overflows.
    queue_bytes: u64,
    /// Every `spike_every`, the link sends nothing for `spike_len`; packets queue behind it.
    spike_every: Duration,
    spike_len: Duration,
    /// Every `dip_every`, the link runs at `dip_rate_mbps` for `dip_len`.
    dip_every: Duration,
    dip_len: Duration,
    dip_rate_mbps: f64,
    /// Packets still to drop on the workload's order, for a controlled tail loss, once
    /// `drop_skip` more have passed.
    drop_next: Arc<AtomicU64>,
    drop_skip: Arc<AtomicU64>,
    trace: Arc<PathTrace>,
    epoch: Arc<std::sync::Mutex<Instant>>,
}

fn pipe(
    im: Impair,
    seed: u64,
    loss_on: Arc<AtomicBool>,
    stats: Arc<LinkStats>,
) -> (PipeTx, mpsc::UnboundedReceiver<Bytes>) {
    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<(Instant, Bytes)>();
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Bytes>();
    tokio::spawn(async move {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut last_depart = Instant::now();
        // What the buffer is holding: everything accepted whose departure is still ahead.
        let mut buffered: std::collections::VecDeque<(Instant, u64)> = Default::default();
        let mut buffered_bytes = 0u64;
        let mut last_at = last_depart;
        let mut heap: BinaryHeap<Scheduled> = BinaryHeap::new();
        let mut seq = 0u64;
        let mut open = true;
        loop {
            if !open && heap.is_empty() {
                break;
            }
            let next_at = heap.peek().map(|s| s.at);
            tokio::select! {
                biased;
                item = in_rx.recv(), if open => match item {
                    Some((sent, b)) => {
                        let impaired = loss_on.load(Ordering::Relaxed);
                        let wire = (b.len() + im.overhead) as u64;
                        if impaired {
                            stats.pkts.fetch_add(1, Ordering::Relaxed);
                            stats.offered.fetch_add(wire, Ordering::Relaxed);
                        }
                        // The path's clock starts with the workload, the same for every
                        // transport and both directions.
                        let epoch = *im.epoch.lock().unwrap();
                        let since = sent.saturating_duration_since(epoch);
                        let (jitter_us, bad) = im.trace.at(since);
                        // Serialization: packets go out back to back at the link rate, so a
                        // burst spreads out and queues behind itself. A stall is the link
                        // sending nothing: what was queued goes out at the link rate after it.
                        let mut start_tx = sent.max(last_depart);
                        if impaired && !im.spike_every.is_zero() {
                            let phase = Duration::from_micros(
                                (start_tx.saturating_duration_since(epoch).as_micros()
                                    % im.spike_every.as_micros()) as u64,
                            );
                            if phase < im.spike_len {
                                start_tx += im.spike_len - phase;
                            }
                        }
                        let dipped = impaired
                            && !im.dip_every.is_zero()
                            && Duration::from_micros(
                                (start_tx.saturating_duration_since(epoch).as_micros()
                                    % im.dip_every.as_micros()) as u64,
                            ) < im.dip_len;
                        let rate = if dipped { im.dip_rate_mbps } else { im.rate_mbps };
                        let depart = start_tx
                            + Duration::from_secs_f64(
                                (b.len() + im.overhead) as f64 * 8.0 / (rate * 1e6),
                            );
                        // Drain first: anything whose departure has passed has left the buffer.
                        while let Some(&(d, n)) = buffered.front() {
                            if d <= sent {
                                buffered.pop_front();
                                buffered_bytes -= n;
                            } else {
                                break;
                            }
                        }
                        if impaired && im.queue_bytes > 0 && buffered_bytes + wire > im.queue_bytes
                        {
                            stats.dropped.fetch_add(1, Ordering::Relaxed);
                            stats.drop_bytes.fetch_add(wire, Ordering::Relaxed);
                            continue;
                        }
                        if impaired {
                            stats.bytes.fetch_add(wire, Ordering::Relaxed);
                        }
                        buffered.push_back((depart, wire));
                        buffered_bytes += wire;
                        last_depart = depart;
                        let lost = if im.burst.is_zero() {
                            rng.gen_range(0..100u64) < im.loss
                        } else {
                            bad
                        };
                        let forced = if im.drop_skip.load(Ordering::Relaxed) > 0 {
                            im.drop_skip.fetch_sub(1, Ordering::Relaxed);
                            false
                        } else {
                            im.drop_next.load(Ordering::Relaxed) > 0
                                && im.drop_next.fetch_sub(1, Ordering::Relaxed) > 0
                        };
                        if impaired && (lost || forced) {
                            stats.dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let mut at = depart + im.delay;
                        if impaired && !im.jitter.is_zero() {
                            if im.jitter_iid {
                                at += Duration::from_micros(
                                    rng.gen_range(0..=im.jitter.as_micros() as u64),
                                );
                            } else {
                                at += Duration::from_micros(u64::from(jitter_us));
                            }
                        }
                        if impaired && im.reorder > 0 && rng.gen_range(0..1000u64) < im.reorder {
                            at = at.checked_sub(im.reorder_by).unwrap_or(depart).max(depart);
                        }
                        // Only independent jitter and netem reordering may deliver out of order.
                        if !(im.jitter_iid && !im.jitter.is_zero()) && im.reorder == 0 {
                            at = at.max(last_at);
                            last_at = at;
                        }
                        heap.push(Scheduled { at, seq, b });
                        seq += 1;
                    }
                    None => open = false,
                },
                _ = async {
                    match next_at {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    if let Some(s) = heap.pop() {
                        if out_tx.send(s.b).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    (PipeTx(in_tx), out_rx)
}

struct Link {
    rate: f64,
    rate_rev: f64,
    overhead: usize,
    seed: u64,
    delay: Duration,
    loss: u64,
    burst: Duration,
    jitter: Duration,
    jitter_iid: bool,
    reorder: u64,
    reorder_by: Duration,
    queue_bytes: u64,
    spike_every: Duration,
    spike_len: Duration,
    dip_every: Duration,
    dip_len: Duration,
    dip_rate: f64,
    trace_ticks: usize,
    drop_next: Arc<AtomicU64>,
    drop_skip: Arc<AtomicU64>,
    /// When the workload started: the path's clock.
    epoch: Arc<std::sync::Mutex<Instant>>,
    loss_on: Arc<AtomicBool>,
    ab: Arc<LinkStats>,
    ba: Arc<LinkStats>,
}

impl Link {
    fn impair(&self, rev: bool) -> Impair {
        let seed = self.seed + u64::from(rev);
        Impair {
            delay: self.delay,
            rate_mbps: if rev { self.rate_rev } else { self.rate },
            overhead: self.overhead,
            loss: self.loss,
            burst: self.burst,
            jitter: self.jitter,
            jitter_iid: self.jitter_iid,
            reorder: self.reorder,
            reorder_by: self.reorder_by,
            queue_bytes: self.queue_bytes,
            spike_every: self.spike_every,
            spike_len: self.spike_len,
            dip_every: if rev { Duration::ZERO } else { self.dip_every },
            dip_len: self.dip_len,
            dip_rate_mbps: self.dip_rate,
            drop_next: if rev {
                Arc::default()
            } else {
                self.drop_next.clone()
            },
            drop_skip: if rev {
                Arc::default()
            } else {
                self.drop_skip.clone()
            },
            epoch: self.epoch.clone(),
            trace: Arc::new(PathTrace::new(
                seed,
                self.trace_ticks,
                self.jitter,
                self.loss,
                self.burst,
            )),
        }
    }

    fn pipes(
        &self,
    ) -> (
        PipeTx,
        mpsc::UnboundedReceiver<Bytes>,
        PipeTx,
        mpsc::UnboundedReceiver<Bytes>,
    ) {
        let (ab_tx, ab_rx) = pipe(
            self.impair(false),
            self.seed,
            self.loss_on.clone(),
            self.ab.clone(),
        );
        let (ba_tx, ba_rx) = pipe(
            self.impair(true),
            self.seed + 1,
            self.loss_on.clone(),
            self.ba.clone(),
        );
        (ab_tx, ab_rx, ba_tx, ba_rx)
    }
}

struct DelayedConn {
    tx: PipeTx,
    rx: Mutex<mpsc::UnboundedReceiver<Bytes>>,
}

#[async_trait::async_trait]
impl Conn for DelayedConn {
    async fn connect(&self, _addr: SocketAddr) -> util::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "n/a").into())
    }
    async fn recv(&self, b: &mut [u8]) -> util::Result<usize> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(d) => {
                let n = d.len().min(b.len());
                b[..n].copy_from_slice(&d[..n]);
                Ok(n)
            }
            None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed").into()),
        }
    }
    async fn recv_from(&self, buf: &mut [u8]) -> util::Result<(usize, SocketAddr)> {
        let n = self.recv(buf).await?;
        Ok((n, SocketAddr::from_str("0.0.0.0:0")?))
    }
    async fn send(&self, b: &[u8]) -> util::Result<usize> {
        self.tx.send(Bytes::copy_from_slice(b));
        Ok(b.len())
    }
    async fn send_to(&self, _b: &[u8], _t: SocketAddr) -> util::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Other, "n/a").into())
    }
    fn local_addr(&self) -> util::Result<SocketAddr> {
        Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "n/a").into())
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }
    async fn close(&self) -> util::Result<()> {
        Ok(())
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[derive(Clone)]
struct Workload {
    /// Packets a frame takes on this transport, for `tail_drop`.
    frame_packets: u64,
    frame: usize,
    frames: usize,
    interval: Duration,
    deadline: Duration,
    gap_every: usize,
    gap: Duration,
    tail_drop: u64,
}

impl Workload {
    /// When to send frame `i` next, and the tail drop to arm before it: the last `tail_drop`
    /// packets of the burst, however many frames they span.
    fn step(&self, i: usize, next: &mut Instant, drop_next: &AtomicU64, drop_skip: &AtomicU64) {
        *next += self.interval;
        if self.gap_every > 0 && (i + 1) % self.gap_every == 0 {
            *next += self.gap;
        }
        if self.tail_drop == 0 || self.gap_every == 0 {
            return;
        }
        let frames = self.tail_drop.div_ceil(self.frame_packets) as usize;
        if i % self.gap_every == self.gap_every - frames {
            drop_skip.store(
                frames as u64 * self.frame_packets - self.tail_drop,
                Ordering::Relaxed,
            );
            drop_next.store(self.tail_drop, Ordering::Relaxed);
        }
    }
}

/// Packets a frame takes: SCTP fragments the message at RustDesk's 60000 bytes and chunks at
/// this crate's 1160-byte payload; KCP segments the 4-byte-prefixed frame at its 1176-byte MSS.
fn frame_packets(frame: usize, proto: &str) -> u64 {
    let frame = frame.max(8) as u64;
    if proto == "kcp" {
        (frame + 4).div_ceil(1176)
    } else {
        (0..frame)
            .step_by(60000)
            .map(|off| (frame - off).min(60000).div_ceil(1160))
            .sum()
    }
}

struct Report {
    total: Duration,
    lat: Vec<Duration>,
}

fn frame_bytes(start: Instant, at: Instant, frame: usize) -> Bytes {
    let mut b = BytesMut::with_capacity(frame.max(8));
    b.put_u64((at - start).as_micros() as u64);
    b.resize(frame.max(8), 0xAB);
    b.freeze()
}

fn note(start: Instant, payload: &[u8], lat: &mut Vec<Duration>) {
    let ts = u64::from_be_bytes(payload[..8].try_into().unwrap());
    let now = start.elapsed().as_micros() as u64;
    lat.push(Duration::from_micros(now.saturating_sub(ts)));
}

async fn run_sctp(w: &Workload, link: &Link, nc: bool) -> Report {
    use webrtc_sctp::association::{set_no_congestion_control, Association, Config};
    use webrtc_sctp::chunk::chunk_payload_data::PayloadProtocolIdentifier;

    set_no_congestion_control(nc);
    let (ab_tx, ab_rx, ba_tx, ba_rx) = link.pipes();
    let ca = Arc::new(DelayedConn {
        tx: ab_tx,
        rx: Mutex::new(ba_rx),
    });
    let cb = Arc::new(DelayedConn {
        tx: ba_tx,
        rx: Mutex::new(ab_rx),
    });

    let server = tokio::spawn(async move {
        Association::server(Config {
            net_conn: cb,
            max_receive_buffer_size: 0,
            max_message_size: 0,
            name: "server".into(),
        })
        .await
        .unwrap()
    });
    let client = Association::client(Config {
        net_conn: ca,
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: "client".into(),
    })
    .await
    .unwrap();
    let server = server.await.unwrap();

    let s0 = client
        .open_stream(6, PayloadProtocolIdentifier::Binary)
        .await
        .unwrap();
    s0.write_sctp(
        &Bytes::from_static(b"hello"),
        PayloadProtocolIdentifier::Binary,
    )
    .await
    .unwrap();
    let s1 = server.accept_stream().await.unwrap();
    let mut buf = vec![0u8; 65536];
    s1.read_sctp(&mut buf).await.unwrap();

    let start = Instant::now();
    *link.epoch.lock().unwrap() = start;
    link.loss_on.store(true, Ordering::Relaxed);
    let frames = w.frames;
    let lat: Arc<std::sync::Mutex<Vec<Duration>>> = Arc::default();
    let lat2 = lat.clone();
    let frame_len = w.frame.max(8);
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut got = 0;
        let mut acc = 0;
        let mut head = [0u8; 8];
        while got < frames {
            let (n, _) = s1.read_sctp(&mut buf).await.unwrap();
            if acc == 0 {
                head.copy_from_slice(&buf[..8]);
            }
            acc += n;
            if acc >= frame_len {
                note(start, &head, &mut lat2.lock().unwrap());
                got += 1;
                acc = 0;
            }
        }
        start.elapsed()
    });
    let (frame, drop_next, drop_skip) = (w.frame, link.drop_next.clone(), link.drop_skip.clone());
    let w = w.clone();
    let deadline = w.deadline;
    tokio::spawn(async move {
        let mut next = start;
        for i in 0..frames {
            tokio::time::sleep_until(next).await;
            let f = frame_bytes(start, next, frame);
            w.step(i, &mut next, &drop_next, &drop_skip);
            // As RustDesk fragments a message for the data channel's 64 KiB limit.
            for piece in f.chunks(60000) {
                s0.write_sctp(
                    &Bytes::copy_from_slice(piece),
                    PayloadProtocolIdentifier::Binary,
                )
                .await
                .unwrap();
            }
        }
    });
    let total = match tokio::time::timeout(deadline, reader).await {
        Ok(Ok(t)) => t,
        _ => deadline,
    };
    link.loss_on.store(false, Ordering::Relaxed);
    let lat = lat.lock().unwrap().clone();
    Report { total, lat }
}

#[cfg(feature = "kcp")]
async fn run_kcp(w: &Workload, link: &Link, nc: bool) -> Report {
    use kcp_sys::{endpoint::KcpEndpoint, packet_def::KcpPacket, stream::KcpStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mk = || {
        let mut ep = KcpEndpoint::new();
        if !nc {
            ep.set_kcp_config_factory(Box::new(|conv| {
                let mut c = kcp_sys::ffi_safe::KcpConfig::new_turbo(conv);
                c.nc = Some(0);
                c
            }));
        }
        ep
    };
    let mut ea = mk();
    let mut eb = mk();
    ea.run().await;
    eb.run().await;

    let (ab_tx, mut ab_rx, ba_tx, mut ba_rx) = link.pipes();
    let mut out_a = ea.output_receiver().unwrap();
    let mut out_b = eb.output_receiver().unwrap();
    let in_a = ea.input_sender();
    let in_b = eb.input_sender();
    tokio::spawn(async move {
        while let Some(p) = out_a.recv().await {
            if !ab_tx.send(p.inner().freeze()) {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(p) = out_b.recv().await {
            if !ba_tx.send(p.inner().freeze()) {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(b) = ab_rx.recv().await {
            if in_b
                .send(KcpPacket::from(BytesMut::from(&b[..])))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(b) = ba_rx.recv().await {
            if in_a
                .send(KcpPacket::from(BytesMut::from(&b[..])))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let (conn_a, conn_b) = tokio::join!(
        ea.connect(Duration::from_secs(5), 0, 0, Bytes::new()),
        async {
            tokio::time::timeout(Duration::from_secs(5), eb.accept())
                .await
                .unwrap()
        }
    );
    let mut sa = KcpStream::new(&ea, conn_a.unwrap()).unwrap();
    let mut sb = KcpStream::new(&eb, conn_b.unwrap()).unwrap();

    let start = Instant::now();
    *link.epoch.lock().unwrap() = start;
    link.loss_on.store(true, Ordering::Relaxed);
    let frames = w.frames;
    let lat: Arc<std::sync::Mutex<Vec<Duration>>> = Arc::default();
    let lat2 = lat.clone();
    let frame_len = w.frame.max(8);
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; frame_len.max(65536)];
        let mut got = 0;
        while got < frames {
            let mut hdr = [0u8; 4];
            sb.read_exact(&mut hdr).await.unwrap();
            let n = u32::from_be_bytes(hdr) as usize;
            sb.read_exact(&mut buf[..n]).await.unwrap();
            note(start, &buf[..n], &mut lat2.lock().unwrap());
            got += 1;
        }
        start.elapsed()
    });
    let (frame, drop_next, drop_skip) = (w.frame, link.drop_next.clone(), link.drop_skip.clone());
    let w = w.clone();
    let deadline = w.deadline;
    tokio::spawn(async move {
        let mut next = start;
        for i in 0..frames {
            tokio::time::sleep_until(next).await;
            let f = frame_bytes(start, next, frame);
            w.step(i, &mut next, &drop_next, &drop_skip);
            let mut framed = BytesMut::with_capacity(4 + f.len());
            framed.put_u32(f.len() as u32);
            framed.put_slice(&f);
            sa.write_all(&framed).await.unwrap();
        }
    });
    let total = match tokio::time::timeout(deadline, reader).await {
        Ok(Ok(t)) => t,
        _ => deadline,
    };
    link.loss_on.store(false, Ordering::Relaxed);
    let lat = lat.lock().unwrap().clone();
    Report { total, lat }
}

#[cfg(not(feature = "kcp"))]
async fn run_kcp(_w: &Workload, _link: &Link, _nc: bool) -> Report {
    panic!("PROTO=kcp needs --features kcp");
}

fn pct(sorted: &[Duration], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i].as_secs_f64() * 1000.0
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let _ = env_logger::Builder::from_default_env()
        .format_timestamp_micros()
        .try_init();
    let proto = std::env::var("PROTO").unwrap_or_else(|_| "sctp".into());
    let nc = env_u64("NC", 1) == 1;
    let rate = env_u64("RATE", 30);
    let frame = env_u64("FRAME", 12000) as usize;
    let w = Workload {
        frame_packets: frame_packets(frame, &proto),
        frame,
        frames: env_u64("FRAMES", 300) as usize,
        interval: Duration::from_micros(1_000_000 / env_u64("FPS", 30)),
        deadline: Duration::from_secs(env_u64("DEADLINE", 60)),
        gap_every: env_u64("GAP_EVERY", 0) as usize,
        gap: Duration::from_millis(env_u64("GAP_MS", 0)),
        tail_drop: env_u64("TAILDROP", 0),
    };
    let link = Link {
        rate: rate as f64,
        rate_rev: env_u64("RATE_REV", rate) as f64,
        // What a packet costs outside the transport's own header, on IPv4: 20 IP + 8 UDP,
        // and for SCTP the 37-byte DTLS record `INITIAL_MTU` is sized around (13 header, 8
        // explicit nonce, 16 GCM tag). On IPv6 both are 20 bytes more.
        overhead: env_u64("OVERHEAD", if proto == "kcp" { 28 } else { 65 }) as usize,
        seed: env_u64("SEED", 1),
        delay: Duration::from_millis(env_u64("OWD", 35)),
        loss: env_u64("LOSS", 0),
        burst: Duration::from_millis(env_u64("BURST_MS", 0)),
        jitter: Duration::from_millis(env_u64("JITTER", 0)),
        jitter_iid: env_u64("JITTER_IID", 0) == 1,
        reorder: env_u64("REORDER", 0),
        reorder_by: Duration::from_millis(env_u64("REORDER_MS", 10)),
        queue_bytes: {
            let explicit = env_u64("QUEUE_BYTES", 0);
            if explicit > 0 {
                explicit
            } else {
                // What fits in that many milliseconds at the nominal rate, which is how a
                // buffer of a given depth is usually quoted.
                env_u64("QUEUE_MS", 0) * rate * 1_000_000 / 8 / 1000
            }
        },
        spike_every: Duration::from_millis(env_u64("SPIKE_EVERY", 0)),
        spike_len: Duration::from_millis(env_u64("SPIKE_MS", 0)),
        dip_every: Duration::from_millis(env_u64("DIP_EVERY", 0)),
        dip_len: Duration::from_millis(env_u64("DIP_MS", 0)),
        dip_rate: env_u64("DIP_RATE", 1) as f64,
        trace_ticks: (w.deadline.as_millis() as usize) + 10_000,
        drop_next: Arc::default(),
        drop_skip: Arc::default(),
        epoch: Arc::new(std::sync::Mutex::new(Instant::now())),
        loss_on: Arc::new(AtomicBool::new(false)),
        ab: Arc::new(LinkStats::default()),
        ba: Arc::new(LinkStats::default()),
    };
    assert!(
        w.tail_drop <= w.gap_every as u64 * w.frame_packets,
        "TAILDROP exceeds a burst's packets"
    );
    let r = match proto.as_str() {
        "sctp" => run_sctp(&w, &link, nc).await,
        "kcp" => run_kcp(&w, &link, nc).await,
        _ => panic!("PROTO=sctp|kcp"),
    };
    let mut sorted = r.lat.clone();
    sorted.sort();
    let mean = if sorted.is_empty() {
        f64::NAN
    } else {
        sorted.iter().map(|d| d.as_secs_f64()).sum::<f64>() / sorted.len() as f64 * 1000.0
    };
    let undelivered = w.frames - sorted.len();
    let miss = |ms: u128| sorted.iter().filter(|d| d.as_millis() > ms).count() + undelivered;
    let app = (w.frame * w.frames) as f64;
    println!(
        "RESULT proto={} nc={} rate={} rev={} ovh={} owd={} loss={} burst_ms={} jitter={}{} reorder={} queue_bytes={} spike={}/{} dip={}/{}@{} frame={} fps={} gap={}/{} taildrop={} seed={} delivered={}/{} total={:.2}s mean={:.0} p50={:.0} p90={:.0} p99={:.0} max={:.0} miss100={} miss200={} miss500={} offered_fwd={:.2}x wire_fwd={:.2}x pkts_fwd={} drop_fwd={} drop_bytes_fwd={} bytes_rev={} pkts_rev={}",
        proto,
        nc as u8,
        link.rate,
        link.rate_rev,
        link.overhead,
        link.delay.as_millis(),
        link.loss,
        link.burst.as_millis(),
        link.jitter.as_millis(),
        if link.jitter_iid { "iid" } else { "" },
        link.reorder,
        link.queue_bytes,
        link.spike_len.as_millis(),
        link.spike_every.as_millis(),
        link.dip_len.as_millis(),
        link.dip_every.as_millis(),
        link.dip_rate,
        w.frame,
        1_000_000 / w.interval.as_micros(),
        w.gap_every,
        w.gap.as_millis(),
        w.tail_drop,
        link.seed,
        sorted.len(),
        w.frames,
        r.total.as_secs_f64(),
        mean,
        pct(&sorted, 0.5),
        pct(&sorted, 0.9),
        pct(&sorted, 0.99),
        pct(&sorted, 1.0),
        miss(100),
        miss(200),
        miss(500),
        link.ab.offered.load(Ordering::Relaxed) as f64 / app,
        link.ab.bytes.load(Ordering::Relaxed) as f64 / app,
        link.ab.pkts.load(Ordering::Relaxed),
        link.ab.dropped.load(Ordering::Relaxed),
        link.ab.drop_bytes.load(Ordering::Relaxed),
        link.ba.bytes.load(Ordering::Relaxed),
        link.ba.pkts.load(Ordering::Relaxed),
    );
    std::process::exit(0);
}
