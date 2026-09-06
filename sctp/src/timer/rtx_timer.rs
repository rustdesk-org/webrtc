use std::sync::{Arc, Weak};

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;

use crate::association::RtxTimerId;

// RFC 4960's RTO.Initial/RTO.Min are 3000/1000, inherited from TCP for arbitrary public paths.
// They cost a full second per loss here, and fast retransmit cannot cover for it: a
// request/response exchange keeps one chunk in flight, so no later SACK ever raises
// `miss_indicator` to the 3 that arms it, leaving the T3 floor as the recovery time.
//
// The values below are dcsctp's, the SCTP implementation Google wrote to replace usrsctp for
// Chrome's WebRTC data channels - the same realtime workload - from
// https://webrtc.googlesource.com/src/+/refs/heads/main/net/dcsctp/public/dcsctp_options.h
//
//     rto_initial = 500      rto_min = 400      rto_max = 60'000
//
// `rto_min` carries dcsctp's comment "This must be larger than an expected peer delayed ack
// timeout". The longest a peer may take to acknowledge a DATA chunk is RTT + ATO, and 200ms is
// the delayed-ack default both in usrsctp and in this crate (`ACK_INTERVAL`). A floor at or below
// the peer's ATO makes T3 fire before the acknowledgement can physically arrive, so every idle
// single-chunk exchange retransmits - and an SCTP T3 also collapses cwnd to one MTU and halves
// ssthresh, which costs far more than the duplicate packet.
//
// Lowering our own `ACK_INTERVAL` would not help: the budget an RTO must cover is the *peer's*
// delayed-ack timer, which we do not control at all when the peer is a browser.
//
// One deliberate divergence: dcsctp gives its control timers their own initial value, while this
// crate drives T1-init, T1-cookie, T2-shutdown and T3 from the one RtoManager, so RTO_INITIAL
// moves all of them. It has to: `set_new_rtt` is only reached from SACK handling, so the
// INIT/COOKIE exchange never produces an RTT sample and RTO_INITIAL *is* the T3 value for the
// first DATA chunk - the login exchange and the first keyframe, which is the whole point here.
// The control timers therefore retransmit sooner than dcsctp's would. That is accepted: the
// deadline a user actually experiences comes from the application's own connect timeout, which
// fires long before the association exhausts its retransmission budget.
pub(crate) const RTO_INITIAL: u64 = 500; // msec
pub(crate) const RTO_MIN: u64 = 400; // msec
pub(crate) const RTO_MAX: u64 = 60000; // msec
pub(crate) const RTO_ALPHA: u64 = 1;
pub(crate) const RTO_BETA: u64 = 2;
pub(crate) const RTO_BASE: u64 = 8;
// dcsctp's `min_rtt_variance`, which it identifies as the "G" (clock granularity) term of
// https://datatracker.ietf.org/doc/html/rfc6298#section-4: a floor under the measured variance
// so a quiet link cannot let RTO converge onto SRTT and start timing out before an
// acknowledgement can physically arrive.
//
// dcsctp configures 220 but does NOT use it raw. RetransmissionTimeout divides it by
// `kHeuristicVarianceAdjustment = 8.0` first, with the comment that the /8 was originally
// unintentional (the code used scaled integers) and was kept because downstream users had
// measured good values with it. The effective floor is therefore 220/8 = 27.5ms of variance,
// contributing 4 * 27.5 = 110ms to RTO - not 220ms, and emphatically not 880ms. Flooring the
// raw variance at 220 would add ~770ms to every RTO and undo the point of the change.
pub(crate) const RTT_VAR_MIN: f64 = 220.0 / 8.0; // msec, dcsctp's 220 after its /8 adjustment
// Without a congestion window every DATA chunk carries the I bit (RFC 7053), so a peer that
// honours it answers within an RTT and the 200ms delayed-ack budget above no longer applies. A
// chunk lost at the tail of a burst has nothing sent after it to ack, so its recovery time *is*
// the RTO, and a T3 there resends one packet and withholds the rest until a SACK says whether
// the timeout was early (RFC 4960 sec 6.3.3 E3, RFC 5682), so an early one costs a packet. RTO
// then floors at the KCP turbo profile's 30ms, and the variance term at a quarter of the 25ms
// QUIC allows the peer to hold an ack (RFC 9002 sec 6.2.1, max_ack_delay), for srtt + 25ms at
// the least: KCP's srtt + 10ms leaves a link running at the edge of its capacity timing out on
// its own queueing delay, and every early probe there is a drop.
pub(crate) const RTO_MIN_NO_CC: u64 = 30; // msec
pub(crate) const RTT_VAR_MIN_NO_CC: f64 = 6.25; // msec
pub(crate) const MAX_INIT_RETRANS: usize = 8;
pub(crate) const PATH_MAX_RETRANS: usize = 5;
pub(crate) const NO_MAX_RETRANS: usize = 0;

/// rtoManager manages Rtx timeout values.
/// This is an implementation of RFC 4960 sec 6.3.1.
#[derive(Default, Debug)]
pub(crate) struct RtoManager {
    pub(crate) srtt: u64,
    pub(crate) rttvar: f64,
    pub(crate) rto: u64,
    pub(crate) no_update: bool,
    rto_min: u64,
    rttvar_min: f64,
}

impl RtoManager {
    /// newRTOManager creates a new rtoManager.
    pub(crate) fn new() -> Self {
        RtoManager {
            rto: RTO_INITIAL,
            rto_min: RTO_MIN,
            rttvar_min: RTT_VAR_MIN,
            ..Default::default()
        }
    }

    /// The manager for an association sending without a congestion window: RTO_MIN_NO_CC and
    /// RTT_VAR_MIN_NO_CC in place of dcsctp's floors.
    pub(crate) fn new_no_congestion_control() -> Self {
        RtoManager {
            rto: RTO_INITIAL,
            rto_min: RTO_MIN_NO_CC,
            rttvar_min: RTT_VAR_MIN_NO_CC,
            ..Default::default()
        }
    }

    /// set_new_rtt takes a newly measured RTT then adjust the RTO in msec.
    pub(crate) fn set_new_rtt(&mut self, rtt: u64) -> u64 {
        if self.no_update {
            return self.srtt;
        }

        if self.srtt == 0 {
            // First measurement
            self.srtt = rtt;
            self.rttvar = rtt as f64 / 2.0;
        } else {
            // Subsequent rtt measurement
            self.rttvar = ((RTO_BASE - RTO_BETA) as f64 * self.rttvar
                + RTO_BETA as f64 * (self.srtt as i64 - rtt as i64).abs() as f64)
                / RTO_BASE as f64;
            self.srtt = ((RTO_BASE - RTO_ALPHA) * self.srtt + RTO_ALPHA * rtt) / RTO_BASE;
        }

        if self.rttvar < self.rttvar_min {
            self.rttvar = self.rttvar_min;
        }
        self.rto = (self.srtt + (4.0 * self.rttvar) as u64).clamp(self.rto_min, RTO_MAX);

        self.srtt
    }

    /// get_rto simply returns the current RTO in msec.
    pub(crate) fn get_rto(&self) -> u64 {
        self.rto
    }

    /// reset resets the RTO variables to the initial values.
    pub(crate) fn reset(&mut self) {
        if self.no_update {
            return;
        }

        self.srtt = 0;
        self.rttvar = 0.0;
        self.rto = RTO_INITIAL;
    }

    /// set RTO value for testing
    pub(crate) fn set_rto(&mut self, rto: u64, no_update: bool) {
        self.rto = rto;
        self.no_update = no_update;
    }
}

pub(crate) fn calculate_next_timeout(rto: u64, n_rtos: usize) -> u64 {
    // RFC 4096 sec 6.3.3.  Handle T3-rtx Expiration
    //   E2)  For the destination address for which the timer expires, set RTO
    //        <- RTO * 2 ("back off the timer").  The maximum value discussed
    //        in rule C7 above (RTO.max) may be used to provide an upper bound
    //        to this doubling operation.
    if n_rtos < 31 {
        std::cmp::min(rto << n_rtos, RTO_MAX)
    } else {
        RTO_MAX
    }
}

/// rtxTimerObserver is the interface to a timer observer.
/// NOTE: Observers MUST NOT call start() or stop() method on rtxTimer
/// from within these callbacks.
#[async_trait]
pub(crate) trait RtxTimerObserver {
    async fn on_retransmission_timeout(&mut self, timer_id: RtxTimerId, n: usize);
    async fn on_retransmission_failure(&mut self, timer_id: RtxTimerId);
}

/// rtxTimer provides the retnransmission timer conforms with RFC 4960 Sec 6.3.1
#[derive(Default, Debug)]
pub(crate) struct RtxTimer<T: 'static + RtxTimerObserver + Send> {
    pub(crate) timeout_observer: Weak<Mutex<T>>,
    pub(crate) id: RtxTimerId,
    pub(crate) max_retrans: usize,
    pub(crate) close_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,
}

impl<T: 'static + RtxTimerObserver + Send> RtxTimer<T> {
    /// newRTXTimer creates a new retransmission timer.
    /// if max_retrans is set to 0, it will keep retransmitting until stop() is called.
    /// (it will never make on_retransmission_failure() callback.
    pub(crate) fn new(
        timeout_observer: Weak<Mutex<T>>,
        id: RtxTimerId,
        max_retrans: usize,
    ) -> Self {
        RtxTimer {
            timeout_observer,
            id,
            max_retrans,
            close_tx: Arc::new(Mutex::new(None)),
        }
    }

    /// start starts the timer.
    pub(crate) async fn start(&self, rto: u64) -> bool {
        // Note: rto value is intentionally not capped by RTO.Min to allow
        // fast timeout for the tests. Non-test code should pass in the
        // rto generated by rtoManager get_rto() method which caps the
        // value at RTO.Min or at RTO.Max.

        // this timer is already closed
        let mut close_rx = {
            let mut close = self.close_tx.lock().await;
            if close.is_some() {
                return false;
            }

            let (close_tx, close_rx) = mpsc::channel(1);
            *close = Some(close_tx);
            close_rx
        };

        let id = self.id;
        let max_retrans = self.max_retrans;
        let close_tx = Arc::clone(&self.close_tx);
        let timeout_observer = self.timeout_observer.clone();

        tokio::spawn(async move {
            let mut n_rtos = 0;

            loop {
                let interval = calculate_next_timeout(rto, n_rtos);
                let timer = tokio::time::sleep(Duration::from_millis(interval));
                tokio::pin!(timer);

                tokio::select! {
                    _ = timer.as_mut() => {
                        n_rtos+=1;

                        let failure = {
                            if let Some(observer) = timeout_observer.upgrade(){
                                let mut observer = observer.lock().await;
                                if max_retrans == 0 || n_rtos <= max_retrans {
                                    observer.on_retransmission_timeout(id, n_rtos).await;
                                    false
                                } else {
                                    observer.on_retransmission_failure(id).await;
                                    true
                                }
                            }else{
                                true
                            }
                        };
                        if failure {
                            let mut close = close_tx.lock().await;
                            *close = None;
                            break;
                        }
                    }
                    _ = close_rx.recv() => break,
                }
            }
        });

        true
    }

    /// stop stops the timer.
    pub(crate) async fn stop(&self) {
        let mut close_tx = self.close_tx.lock().await;
        close_tx.take();
    }

    /// isRunning tests if the timer is running.
    /// Debug purpose only
    pub(crate) async fn is_running(&self) -> bool {
        let close_tx = self.close_tx.lock().await;
        close_tx.is_some()
    }
}
